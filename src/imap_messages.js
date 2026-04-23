// ============================================================================
//  imap_messages.js
// ----------------------------------------------------------------------------
//  Server-side handlers for message operations: FETCH, STORE, COPY (+ their
//  UID variants). Also houses all the shared helpers these three commands
//  rely on:
//
//    • parseFetchItems        — tokenize a FETCH data-items request
//    • fetchMessages          — orchestrate a FETCH round-trip
//    • fetchEachMessage       — per-message body/envelope gathering loop
//    • createBodyResponder    — responder-pattern API for messageBody event
//    • collectStream          — drain a Readable into a single Buffer
//    • emitFetchResponse      — build the untagged FETCH reply
//    • emitFetchResponseStreaming — streaming variant for large BODY[]
//    • extractBodySectionBytes — pull out a BODY[section] slice from the raw
//    • storeBatch             — STORE implementation, flag update loop
//
//  Dependencies are injected via the `s` session interface passed to
//  `registerMessageHandlers(s)`. The function attaches three handlers to s:
//
//     s.handleFetch(tag, args, byUid)
//     s.handleStore(tag, args, byUid)
//     s.handleCopy (tag, args, byUid)
//
//  which the session dispatcher (in imap_session.js) then calls. The `s`
//  object provides:
//
//     s.context          — session state (current folder, condstore flags, ...)
//     s.ev               — EventEmitter (for messageMeta/messageBody/setFlags events)
//     s.sendTagged       — send OK/NO/BAD tagged reply
//     s.sendUntagged     — send untagged response
//     s.send             — send raw bytes / Buffer[]
//     s.requireSelected  — guard: verify session is in SELECTED state
//
//  Keeping all these functions in one file preserves the tight cohesion
//  between them (STORE emits FETCH responses; FETCH/COPY share UID mapping
//  and sequence-set handling) without polluting the top-level imap_session.js.
// ============================================================================

import { TOK, serializeValue } from './imap_wire.js';
import { parseMessageTree } from './message.js';
import {
  // Pure helpers
  serializeFlag,
  serializeFlagList,
  normalizeFlag,
  checkFlagsHygiene,
  parseSequenceSet,
  compressUids,
  formatRanges,
  buildCopyUidCode,
  formatInternalDate,
  parseBodySection,
  buildBodyResponseName,
  buildEnvelope,
  buildBodyStructure,
  buildEnvelopeFromJson,
  buildBodyStructureFromJson,
  extractBodyStructure,
  extractEnvelope
} from './imap_helpers.js';


export function registerMessageHandlers(s) {
  const context        = s.context;
  const ev             = s.ev;
  const sendTagged     = s.sendTagged;
  const sendUntagged   = s.sendUntagged;
  const send           = s.send;
  const requireSelected = s.requireSelected;
  const getStringValue = s.getStringValue;

  // Parse parenthesized fetch/store modifiers like "(CHANGEDSINCE 12345)" or
  // "(UNCHANGEDSINCE 42)" or "(CHANGEDSINCE 42 VANISHED)". Returns an object
  // keyed by uppercase modifier name.
  //
  // Modifiers with a numeric argument consume the next token. Boolean flags
  // (like VANISHED) stand alone.
  function parseCommandModifiers(listTok) {
    if (!listTok || listTok.type !== TOK.LIST) return null;
    // Modifiers that take a numeric/atom argument
    let VALUED = { CHANGEDSINCE: 1, UNCHANGEDSINCE: 1 };
    let out = {};
    let items = listTok.value;
    for (let i = 0; i < items.length; i++) {
      let tok = items[i];
      if (!tok || tok.type !== TOK.ATOM) continue;
      let name = String(tok.value).toUpperCase();
      if (VALUED[name]) {
        let val = items[i + 1];
        if (val && val.type === TOK.NUMBER) {
          out[name] = val.value;
          i++;
        } else if (val && val.type === TOK.ATOM) {
          let n = parseInt(val.value, 10);
          out[name] = isNaN(n) ? val.value : n;
          i++;
        } else {
          out[name] = null;  // missing value — caller should validate
        }
      } else {
        out[name] = true;  // boolean flag
      }
    }
    return out;
  }

  // --- FETCH / UID FETCH ---
  function handleFetch(tag, args, byUid) {
    if (!requireSelected(tag)) return;
    if (args.length < 2) {
      sendTagged(tag, 'BAD', 'FETCH requires sequence set and items');
      return;
    }

    // Parse sequence set
    let setStr = getStringValue(args[0]);
    let parsed = parseSequenceSet(setStr, { isUid: byUid, total: context.currentFolderTotal });
    if (parsed.error) {
      sendTagged(tag, 'BAD', 'Invalid sequence set: ' + parsed.error);
      return;
    }

    // Parse items (may be a single atom, or a list, or a macro)
    let items = parseFetchItems(args[1]);
    if (!items || items.length === 0) {
      sendTagged(tag, 'BAD', 'Invalid FETCH items');
      return;
    }

    // Optional modifier list (RFC 7162): FETCH 1:* FLAGS (CHANGEDSINCE 12345)
    // Also supports VANISHED modifier (RFC 7162 §3.2.7) which requests vanished UIDs.
    let changedSince = null;
    let wantVanished = false;
    if (args.length >= 3 && args[2].type === TOK.LIST) {
      let mods = parseCommandModifiers(args[2]);
      if (mods && mods.CHANGEDSINCE != null) {
        changedSince = mods.CHANGEDSINCE;
        context.condstoreEnabled = true;
        // CHANGEDSINCE implies MODSEQ in response
        let hasModseq = false;
        for (let i = 0; i < items.length; i++) if (items[i].name === 'MODSEQ') hasModseq = true;
        if (!hasModseq) items.push({ name: 'MODSEQ' });
      }
      if (mods && mods.VANISHED) {
        // VANISHED modifier is only valid when QRESYNC was enabled AND CHANGEDSINCE is present
        if (context.qresyncEnabled && changedSince != null) {
          wantVanished = true;
        } else {
          sendTagged(tag, 'BAD', 'VANISHED modifier requires QRESYNC enabled and CHANGEDSINCE');
          return;
        }
      }
    }

    // If VANISHED was requested, emit VANISHED (EARLIER) before the FETCH responses
    if (wantVanished && ev.listenerCount('resolveVanished') > 0) {
      ev.emit('resolveVanished', context.currentFolder, {
        changedSince: changedSince,
        type: byUid ? 'uid' : 'seq',
        ranges: parsed.ranges
      }, function(verr, vanished) {
        if (!verr && vanished) {
          let str = null;
          if (vanished.ranges && vanished.ranges.length > 0) {
            str = formatRanges(vanished.ranges);
          } else if (Array.isArray(vanished) && vanished.length > 0) {
            str = compressUids(vanished);
          } else if (vanished.uids && vanished.uids.length > 0) {
            str = compressUids(vanished.uids);
          }
          if (str) sendUntagged('VANISHED (EARLIER) ' + str);
        }
        doResolveAndFetch();
      });
      return;
    }
    doResolveAndFetch();

    function doResolveAndFetch() {
      // Build query for resolveMessages
      let query = { type: byUid ? 'uid' : 'seq', ranges: parsed.ranges };
      if (changedSince != null) query.changedSince = changedSince;

      ev.emit('resolveMessages', context.currentFolder, query, function(err, messages) {
        if (err) {
          sendTagged(tag, 'NO', err.message || 'Cannot resolve messages');
          return;
        }
        messages = messages || [];
        if (messages.length === 0) {
          sendTagged(tag, 'OK', (byUid ? 'UID ' : '') + 'FETCH completed');
          return;
        }
        fetchMessages(tag, messages, items, byUid);
      });
    }
  }

  // Expand FETCH items. Returns an array of item objects:
  //   { name: 'UID' | 'FLAGS' | 'INTERNALDATE' | 'RFC822.SIZE' |
  //            'RFC822' | 'RFC822.HEADER' | 'RFC822.TEXT' |
  //            'ENVELOPE' | 'BODYSTRUCTURE' |
  //            'BODY',
  //     // for name === 'BODY':
  //     peek, section, partial, responseName }
  // Macros FAST/ALL/FULL expand here (ENVELOPE/BODYSTRUCTURE return NIL until Phase 3c).
  function parseFetchItems(arg) {
    let items = [];
    let add = function(tok) {
      if (!tok) return;
      let n = String(tok.value || '').toUpperCase();
      if (!n) return;

      // BODY / BODY.PEEK with optional section + partial
      // The wire attaches `.section` and `.partial` when [...] / <offset.length> were present.
      if (n === 'BODY' || n === 'BODY.PEEK') {
        // BODY without a section is the "BODYSTRUCTURE" alias (same as name 'BODY' with section=null)
        // vs. BODY[] which is whole-message body. The tokenizer distinguishes:
        //   "BODY" (no brackets)    → tok.section is undefined
        //   "BODY[]"                → tok.section is ''
        let hasSection = (tok.section !== undefined && tok.section !== null);
        if (!hasSection && n === 'BODY') {
          // Plain BODY = BODYSTRUCTURE alias
          items.push({ name: 'BODY_STRUCT' });  // internal marker — see emit below
          return;
        }
        items.push({
          name: 'BODY',
          peek: n === 'BODY.PEEK',
          section: tok.section || '',
          partial: tok.partial || null,
          responseName: buildBodyResponseName(tok.section || '', tok.partial)
        });
        return;
      }

      // Macros
      if (n === 'FAST') {
        items.push({ name: 'FLAGS' }, { name: 'INTERNALDATE' }, { name: 'RFC822.SIZE' });
        return;
      }
      if (n === 'ALL') {
        items.push({ name: 'FLAGS' }, { name: 'INTERNALDATE' }, { name: 'RFC822.SIZE' }, { name: 'ENVELOPE' });
        return;
      }
      if (n === 'FULL') {
        items.push({ name: 'FLAGS' }, { name: 'INTERNALDATE' }, { name: 'RFC822.SIZE' }, { name: 'ENVELOPE' }, { name: 'BODY_STRUCT' });
        return;
      }

      // Plain atom items
      items.push({ name: n });
    };

    if (arg.type === TOK.LIST) {
      for (let i = 0; i < arg.value.length; i++) add(arg.value[i]);
    } else {
      add(arg);
    }
    return items;
  }

  // Fetch a set of messages and emit responses.
  function fetchMessages(tag, messages, items, byUid) {
    // Detect which optional batched-cache events are registered. If so,
    // ENVELOPE / BODYSTRUCTURE can be served from the developer's cache
    // without reading each message body — huge win for folder-open flows.
    let hasEnvelopeListener = ev.listenerCount('messageEnvelope') > 0;
    let hasBsListener       = ev.listenerCount('messageBodyStructure') > 0;

    let needsEnv           = false;  // ENVELOPE requested
    let needsBs            = false;  // BODYSTRUCTURE (or BODY alias) requested
    let needsBody          = false;  // need raw bytes for some item
    let needsTree          = false;  // need MIME tree from the body

    for (let i = 0; i < items.length; i++) {
      let n = items[i].name;
      if (n === 'RFC822' || n === 'BODY') {
        needsBody = true;
        if (n === 'BODY' && items[i].section && items[i].section !== '') needsTree = true;
      }
      if (n === 'RFC822.HEADER' || n === 'RFC822.TEXT') {
        needsBody = true;
        needsTree = true;
      }
      if (n === 'ENVELOPE') {
        needsEnv = true;
        if (!hasEnvelopeListener) { needsBody = true; needsTree = true; }
      }
      if (n === 'BODYSTRUCTURE' || n === 'BODY_STRUCT') {
        needsBs = true;
        if (!hasBsListener) { needsBody = true; needsTree = true; }
      }
    }

    let needsMeta = false;
    for (let i = 0; i < items.length; i++) {
      let n = items[i].name;
      if (n === 'FLAGS' || n === 'INTERNALDATE' || n === 'RFC822.SIZE' || n === 'MODSEQ') {
        needsMeta = true; break;
      }
    }

    let alwaysUid = byUid || items.some(function(it) { return it.name === 'UID'; });
    let uids = messages.map(function(m) { return m.uid; });

    // Gather all batched data in parallel before per-message emission
    let metas     = null;
    let envelopes = null;   // uid → envelope JSON (or null on cache miss)
    let bodyStrs  = null;   // uid → bodyStructure JSON

    let pending = 0;
    if (needsMeta)                     pending++;
    if (needsEnv && hasEnvelopeListener) pending++;
    if (needsBs  && hasBsListener)       pending++;

    function allGathered() {
      fetchEachMessage(tag, messages, items, metas, envelopes, bodyStrs,
                       needsBody, needsTree, alwaysUid, byUid);
    }

    if (pending === 0) { allGathered(); return; }

    function one(err) {
      if (err) {
        sendTagged(tag, 'NO', err.message || 'Cannot fetch');
        pending = -1;   // poison subsequent callbacks
        return;
      }
      if (pending < 0) return;
      pending--;
      if (pending === 0) allGathered();
    }

    if (needsMeta) {
      ev.emit('messageMeta', context.currentFolder, uids, function(err, results) {
        if (!err) {
          metas = indexByUid(results || []);
          // Dev-mode: check any returned flag arrays for backslash issues.
          if (Array.isArray(results)) {
            for (let i = 0; i < results.length; i++) {
              if (results[i] && results[i].flags) checkFlagsHygiene(results[i].flags, 'messageMeta');
            }
          }
        }
        one(err);
      });
    }
    if (needsEnv && hasEnvelopeListener) {
      ev.emit('messageEnvelope', context.currentFolder, uids, function(err, results) {
        if (!err) envelopes = indexByUidField(results || [], 'envelope');
        one(err);
      });
    }
    if (needsBs && hasBsListener) {
      ev.emit('messageBodyStructure', context.currentFolder, uids, function(err, results) {
        if (!err) bodyStrs = indexByUidField(results || [], 'bodyStructure');
        one(err);
      });
    }
  }

  // Index by uid, extracting one field. Returns { uid: value } for entries
  // where the field is present (allows per-uid cache-miss handling).
  function indexByUidField(arr, field) {
    let map = {};
    for (let i = 0; i < arr.length; i++) {
      let r = arr[i];
      if (r && r.uid != null && r[field] != null) map[r.uid] = r[field];
    }
    return map;
  }

  // Build a { uid: info } index from an array for O(1) lookup.
  function indexByUid(arr) {
    let map = {};
    for (let i = 0; i < arr.length; i++) {
      if (arr[i] && arr[i].uid != null) map[arr[i].uid] = arr[i];
    }
    return map;
  }

  // Process each message and emit FETCH responses in sequence order.
  //
  // Implementation note: trampolines every 100 sync iterations via setImmediate
  // so large FETCHes (e.g. `FETCH 1:50000 FLAGS`) don't blow the call stack.
  // Async messageBody callbacks naturally yield the stack between messages.
  const SYNC_BATCH = 100;
  function fetchEachMessage(tag, messages, items, metas, envelopes, bodyStrs,
                            needsBody, needsTree, alwaysUid, byUid) {
    let idx = 0;

    // Can we stream the body straight to the wire? Only when:
    //   • no tree navigation needed
    //   • exactly one body-producing item
    let canStream = false;
    if (!needsTree) {
      let bodyItemCount = 0;
      for (let i = 0; i < items.length; i++) {
        let n = items[i].name;
        if (n === 'BODY' || n === 'RFC822') bodyItemCount++;
      }
      canStream = bodyItemCount === 1;
    }

    function processBatch() {
      let count = 0;
      while (idx < messages.length && count < SYNC_BATCH) {
        let msg = messages[idx];
        let meta = metas ? metas[msg.uid] : null;
        let cachedEnv = envelopes ? envelopes[msg.uid] : null;
        let cachedBs  = bodyStrs  ? bodyStrs[msg.uid]  : null;

        if (!needsBody) {
          idx++;
          count++;
          emitFetchResponse(msg.seq, msg.uid, meta, null, null, items, alwaysUid, cachedEnv, cachedBs);
          continue;
        }

        // Body path — async, break the sync loop and resume from the callback
        idx++;
        let capturedMsg = msg;
        let capturedMeta = meta;
        let capturedEnv = cachedEnv;
        let capturedBs  = cachedBs;
        let responder = createBodyResponder(canStream,
          function(buf) {
            let tree = needsTree ? parseMessageTree(buf) : null;
            emitFetchResponse(capturedMsg.seq, capturedMsg.uid, capturedMeta,
                              buf, tree, items, alwaysUid, capturedEnv, capturedBs);
            setImmediate(processBatch);
          },
          function(length, stream) {
            emitFetchResponseStreaming(
              capturedMsg.seq, capturedMsg.uid, capturedMeta,
              length, stream, items, alwaysUid,
              function() { setImmediate(processBatch); }
            );
          },
          function(err) {
            setImmediate(processBatch);
          }
        );

        ev.emit('messageBody', context.currentFolder, capturedMsg.uid, responder);
        return;
      }

      if (idx >= messages.length) {
        sendTagged(tag, 'OK', (byUid ? 'UID ' : '') + 'FETCH completed');
        return;
      }
      setImmediate(processBatch);
    }

    processBatch();
  }

  // Create a responder object that the developer receives from the `messageBody` event.
  //
  //   session.on('messageBody', function(folder, uid, responder) {
  //     responder.send(buffer)                       // simple — one buffer
  //     responder.send({ length, stream: readable }) // streaming — for large bodies
  //     responder.error('message not found')         // abort
  //   });
  //
  // The library decides internally whether to stream or buffer. If streaming
  // would be unsafe for the current FETCH (e.g. the client asked for BODY[HEADER]
  // which needs MIME parsing), the provided stream is drained into a buffer
  // automatically — transparent to the developer.
  function createBodyResponder(canStream, onBuffer, onStream, onError) {
    let called = false;
    return {
      send: function(data) {
        if (called) return;
        called = true;

        if (Buffer.isBuffer(data)) {
          onBuffer(data);
          return;
        }
        if (data instanceof Uint8Array) {
          onBuffer(Buffer.from(data));
          return;
        }
        if (typeof data === 'string') {
          onBuffer(Buffer.from(data, 'utf-8'));
          return;
        }
        if (data && typeof data.length === 'number' && data.stream &&
            typeof data.stream.on === 'function') {
          if (canStream) {
            // Direct stream path — zero-copy passthrough
            onStream(data.length, data.stream);
          } else {
            // MIME navigation needed — drain stream into buffer, then proceed
            collectStream(data.stream, data.length, function(err, buf) {
              if (err) onError(err);
              else onBuffer(buf);
            });
          }
          return;
        }

        // Empty / unknown — treat as empty body
        onBuffer(Buffer.alloc(0));
      },
      error: function(msg) {
        if (called) return;
        called = true;
        onError(new Error(msg || 'body unavailable'));
      }
    };
  }

  // Drain a Node Readable stream into a single Buffer of the expected length.
  function collectStream(stream, expectedLength, cb) {
    let chunks = [];
    let done = false;
    stream.on('data', function(chunk) {
      if (!Buffer.isBuffer(chunk)) chunk = Buffer.from(chunk);
      chunks.push(chunk);
    });
    stream.on('end', function() {
      if (done) return;
      done = true;
      cb(null, Buffer.concat(chunks));
    });
    stream.on('error', function(err) {
      if (done) return;
      done = true;
      cb(err);
    });
  }

  // Build and send a FETCH response that streams a large body straight to the
  // wire, avoiding ever holding the full body in the library's memory.
  //
  // Wire format:  "* N FETCH (<text items> BODY[] {LENGTH}\r\n" + <stream bytes> + ")\r\n"
  //
  // Body item is always emitted LAST when streaming — simplifies the flow.
  function emitFetchResponseStreaming(seq, uid, meta, bodyLength, bodyStream, items, alwaysUid, onDone) {
    // Ensure UID is present first when required (same rule as non-streaming path)
    let order = items;
    if (alwaysUid) {
      let hasUid = false;
      for (let i = 0; i < items.length; i++) if (items[i].name === 'UID') { hasUid = true; break; }
      if (!hasUid) order = [{ name: 'UID' }].concat(items);
    }

    // Split into non-body items (text) and the single body item
    let bodyItem = null;
    let textItems = [];
    for (let i = 0; i < order.length; i++) {
      let it = order[i];
      if (it.name === 'BODY' || it.name === 'RFC822') bodyItem = it;
      else textItems.push(it);
    }

    let head = '* ' + seq + ' FETCH (';
    let first = true;
    for (let i = 0; i < textItems.length; i++) {
      let item = textItems[i];
      let text;
      switch (item.name) {
        case 'UID':          text = String(uid); break;
        case 'FLAGS':        text = serializeFlagList(meta && meta.flags || []); break;
        case 'INTERNALDATE': text = '"' + formatInternalDate(meta && meta.internalDate || new Date()) + '"'; break;
        case 'RFC822.SIZE':  text = String(meta && meta.size != null ? meta.size : bodyLength); break;
        case 'MODSEQ':       text = '(' + (meta && meta.modseq != null ? meta.modseq : 0) + ')'; break;
        default: continue;   // tree-dependent items can't appear in streaming path
      }
      head += (first ? '' : ' ') + item.name + ' ' + text;
      first = false;
    }

    // Append body literal marker
    let bodyName = bodyItem.name === 'RFC822' ? 'RFC822' : (bodyItem.responseName || 'BODY[]');
    head += (first ? '' : ' ') + bodyName + ' {' + bodyLength + '}\r\n';
    send(Buffer.from(head, 'utf-8'));

    // Pipe the stream chunks directly to the wire
    let bytesSent = 0;
    let finished = false;
    function finish() {
      if (finished) return;
      finished = true;
      // Pad if stream under-delivered (wire format requires exactly bodyLength bytes)
      if (bytesSent < bodyLength) {
        send(Buffer.alloc(bodyLength - bytesSent));
      }
      send(Buffer.from(')\r\n', 'utf-8'));
      onDone();
    }

    bodyStream.on('data', function(chunk) {
      if (finished) return;
      if (!Buffer.isBuffer(chunk)) chunk = Buffer.from(chunk);
      if (bytesSent + chunk.length > bodyLength) {
        // Truncate — stream over-delivered, trim to advertised size
        chunk = chunk.subarray(0, bodyLength - bytesSent);
      }
      bytesSent += chunk.length;
      send(chunk);
    });
    bodyStream.on('end', finish);
    bodyStream.on('error', function(err) {
      // Complete the literal with zero-padding so the wire stays valid
      finish();
    });
  }

  // Convert body (Buffer/Uint8Array/string) to Buffer.
  function bodyToBuffer(body) {
    if (Buffer.isBuffer(body)) return body;
    if (body instanceof Uint8Array) return Buffer.from(body);
    if (typeof body === 'string') return Buffer.from(body, 'utf-8');
    return Buffer.alloc(0);
  }

  // Build and send a "* N FETCH (...)" response.
  //
  // Text-first building: items that produce plain text (UID, FLAGS, MODSEQ,
  // ENVELOPE, etc.) are concatenated into a single string. Only when an item
  // produces a binary chunk (BODY[] literal with message bytes) do we switch
  // to multi-buffer mode. For a FETCH of 10k messages with FLAGS+UID, this is
  // one Buffer.from per message instead of ~15.
  function emitFetchResponse(seq, uid, meta, raw, tree, items, alwaysUid, cachedEnv, cachedBs) {
    let head = '* ' + seq + ' FETCH (';
    let binaryParts = null;   // stays null for text-only responses
    let first = true;

    function addText(name, text) {
      head += (first ? '' : ' ') + name + ' ' + text;
      first = false;
    }
    // Append a binary literal: "name {N}\r\n<bytes>" with zero-copy content.
    // Flushes accumulated text into one Buffer, then pushes the raw content
    // buffer as-is — no concat, no per-byte copy.
    function addBinary(name, contentBytes) {
      if (binaryParts === null) binaryParts = [];
      binaryParts.push(Buffer.from(
        head + (first ? '' : ' ') + name + ' {' + contentBytes.length + '}\r\n',
        'utf-8'
      ));
      binaryParts.push(contentBytes);
      head = '';
      first = false;
    }
    function addItem(name, formatted) {
      if (Buffer.isBuffer(formatted)) addBinary(name, formatted);
      else addText(name, String(formatted));
    }

    // Ensure UID comes first when required
    let order = items;
    if (alwaysUid) {
      let hasUid = false;
      for (let i = 0; i < items.length; i++) if (items[i].name === 'UID') { hasUid = true; break; }
      if (!hasUid) order = [{ name: 'UID' }].concat(items);
    }

    for (let i = 0; i < order.length; i++) {
      let item = order[i];
      switch (item.name) {
        case 'UID':
          addText('UID', String(uid));
          break;
        case 'FLAGS':
          addText('FLAGS', serializeFlagList(meta && meta.flags || []));
          break;
        case 'INTERNALDATE':
          addText('INTERNALDATE', '"' + formatInternalDate(meta && meta.internalDate || new Date()) + '"');
          break;
        case 'RFC822.SIZE':
          addText('RFC822.SIZE', String(meta && meta.size != null ? meta.size : (raw ? raw.length : 0)));
          break;

        // Legacy RFC822.* items — equivalent to BODY[] / BODY[HEADER] / BODY[TEXT]
        case 'RFC822':
          addItem('RFC822', extractBodySectionBytes(tree, raw, { section: '', partial: null }));
          break;
        case 'RFC822.HEADER':
          addItem('RFC822.HEADER', extractBodySectionBytes(tree, raw, { section: 'HEADER', partial: null }));
          break;
        case 'RFC822.TEXT':
          addItem('RFC822.TEXT', extractBodySectionBytes(tree, raw, { section: 'TEXT', partial: null }));
          break;

        // BODY[...] with section + optional partial
        case 'BODY':
          addItem(item.responseName, extractBodySectionBytes(tree, raw, item));
          break;

        // Phase 3c: ENVELOPE / BODYSTRUCTURE — prefer cached JSON if supplied
        case 'ENVELOPE':
          if (cachedEnv) {
            addText('ENVELOPE', serializeBuiltToken(buildEnvelopeFromJson(cachedEnv)));
          } else if (tree) {
            addText('ENVELOPE', serializeBuiltToken(buildEnvelope(tree)));
          } else {
            addText('ENVELOPE', 'NIL');
          }
          break;
        case 'BODYSTRUCTURE':
          if (cachedBs) {
            addText('BODYSTRUCTURE', serializeBuiltToken(buildBodyStructureFromJson(cachedBs, true)));
          } else if (tree) {
            addText('BODYSTRUCTURE', serializeBuiltToken(buildBodyStructure(tree, true)));
          } else {
            addText('BODYSTRUCTURE', 'NIL');
          }
          break;
        case 'BODY_STRUCT':  // internal marker for plain "BODY" (= non-extended BODYSTRUCTURE)
          if (cachedBs) {
            addText('BODY', serializeBuiltToken(buildBodyStructureFromJson(cachedBs, false)));
          } else if (tree) {
            addText('BODY', serializeBuiltToken(buildBodyStructure(tree, false)));
          } else {
            addText('BODY', 'NIL');
          }
          break;

        // RFC 7162 CONDSTORE: MODSEQ is wrapped in parens per §3.1.4
        case 'MODSEQ':
          addText('MODSEQ', '(' + (meta && meta.modseq != null ? meta.modseq : 0) + ')');
          break;

        default:
          addText(item.name, 'NIL');
      }
    }

    // Finalize
    if (binaryParts === null) {
      // Pure text response — one allocation
      send(Buffer.from(head + ')\r\n', 'utf-8'));
    } else {
      binaryParts.push(Buffer.from(head + ')\r\n', 'utf-8'));
      // Pass the array directly to send() — avoids one big Buffer.concat.
      // Large body responses (50MB+) save 50MB of intermediate allocation here.
      send(binaryParts);
    }
  }

  // Extract bytes for a BODY[...] section, return as IMAP literal Buffer.
  // `item` has { section, partial }.
  // Extract raw bytes for a BODY[...] section, as a zero-copy subarray of `raw`.
  // Returns a plain Buffer — the caller (emitFetchResponse) wraps it in the
  // "{N}\r\n<bytes>" literal format, avoiding an intermediate Buffer.concat.
  function extractBodySectionBytes(tree, raw, item) {
    if (!raw) return Buffer.alloc(0);

    let sec = parseBodySection(item.section || '');
    if (!sec) return Buffer.alloc(0);

    // Fast path: whole-message body (BODY[] / RFC822) — no tree needed.
    // The root bytes are the entire raw buffer. Apply partial if present.
    if (!tree && sec.type === null && (!sec.part || sec.part.length === 0)) {
      let bytes = raw;
      if (item.partial) {
        let off = item.partial.offset;
        let len = item.partial.length;
        if (off >= bytes.length) return Buffer.alloc(0);
        let endPos = len != null ? Math.min(off + len, bytes.length) : bytes.length;
        bytes = bytes.subarray(off, endPos);
      }
      return bytes;
    }

    if (!tree) return Buffer.alloc(0);

    // Navigate the tree by part path (1-indexed)
    let node = tree;
    if (sec.part && sec.part.length > 0) {
      for (let i = 0; i < sec.part.length; i++) {
        let idx = sec.part[i] - 1;
        if (!node.parts || idx < 0 || idx >= node.parts.length) {
          return Buffer.alloc(0);
        }
        node = node.parts[idx];
      }
    }

    // Extract bytes based on section type (all zero-copy subarrays)
    let bytes;
    if (sec.type === null) {
      bytes = raw.subarray(node.start, node.end);
    } else if (sec.type === 'HEADER') {
      bytes = raw.subarray(node.headerStart, node.headerEnd);
    } else if (sec.type === 'TEXT') {
      bytes = raw.subarray(node.bodyStart, node.bodyEnd);
    } else if (sec.type === 'MIME') {
      bytes = raw.subarray(node.headerStart, node.headerEnd);
    } else if (sec.type === 'HEADER.FIELDS' || sec.type === 'HEADER.FIELDS.NOT') {
      let wanted = sec.fields || [];
      let isNot  = sec.type === 'HEADER.FIELDS.NOT';
      let pieces = [];
      for (let i = 0; i < node.headers.length; i++) {
        let h = node.headers[i];
        let isMatch = wanted.indexOf(h.name.toUpperCase()) >= 0;
        if (isMatch !== isNot) {
          pieces.push(raw.subarray(h.rawStart, h.rawEnd));
        }
      }
      // RFC 3501 §6.4.5: result includes the blank CRLF that terminates headers
      pieces.push(Buffer.from('\r\n', 'utf-8'));
      bytes = Buffer.concat(pieces);   // unavoidable here (headers aren't contiguous)
    } else {
      bytes = Buffer.alloc(0);
    }

    // Apply partial <offset.length> — still a zero-copy subarray
    if (item.partial) {
      let off = item.partial.offset;
      let len = item.partial.length;
      if (off >= bytes.length) {
        bytes = Buffer.alloc(0);
      } else {
        let endPos = len != null ? Math.min(off + len, bytes.length) : bytes.length;
        bytes = bytes.subarray(off, endPos);
      }
    }
    return bytes;
  }

  // Serialize a built token tree (from buildEnvelope/buildBodyStructure) to its
  // IMAP wire form as a Buffer. Delegates to imap_wire's serializeValue for the
  // actual string production, then converts to Buffer for binary-safe sending.
  function serializeBuiltToken(tok) {
    return Buffer.from(serializeValue(tok), 'utf-8');
  }

  // --- STORE / UID STORE ---
  function handleStore(tag, args, byUid) {
    if (!requireSelected(tag)) return;
    if (args.length < 3) {
      sendTagged(tag, 'BAD', 'STORE requires sequence set, operation, and flags');
      return;
    }

    // args: [ seqSet, (optional modifier-list), operation, flagList ]
    let setStr = getStringValue(args[0]);

    // RFC 7162: STORE 1:5 (UNCHANGEDSINCE 12345) +FLAGS (\Seen)
    // If args[1] is a LIST token, it's a parenthesized modifier list.
    let unchangedSince = null;
    let opIdx = 1;
    if (args[1].type === TOK.LIST) {
      let mods = parseCommandModifiers(args[1]);
      if (mods && mods.UNCHANGEDSINCE != null) {
        unchangedSince = mods.UNCHANGEDSINCE;
        context.condstoreEnabled = true;
      }
      opIdx = 2;
    }

    if (args.length < opIdx + 2) {
      sendTagged(tag, 'BAD', 'STORE requires operation and flags');
      return;
    }

    let opStr = String(args[opIdx].value || '').toUpperCase();

    // Parse operation
    let mode    = 'set';
    let silent  = false;
    if (opStr.indexOf('+') === 0)                  { mode = 'add';    opStr = opStr.slice(1); }
    else if (opStr.indexOf('-') === 0)             { mode = 'remove'; opStr = opStr.slice(1); }
    if (opStr === 'FLAGS.SILENT')                  { silent = true; opStr = 'FLAGS'; }
    if (opStr !== 'FLAGS') {
      sendTagged(tag, 'BAD', 'Unsupported STORE operation: ' + opStr);
      return;
    }

    // Parse flag list (may be a list or a single atom)
    let flagArg = args[opIdx + 1];
    let flags = [];
    if (flagArg.type === TOK.LIST) {
      for (let i = 0; i < flagArg.value.length; i++) {
        flags.push(normalizeFlag(flagArg.value[i].value));
      }
    } else {
      flags.push(normalizeFlag(flagArg.value));
    }

    // Parse seq set
    let parsed = parseSequenceSet(setStr, { isUid: byUid, total: context.currentFolderTotal });
    if (parsed.error) {
      sendTagged(tag, 'BAD', 'Invalid sequence set: ' + parsed.error);
      return;
    }

    ev.emit('resolveMessages', context.currentFolder,
      { type: byUid ? 'uid' : 'seq', ranges: parsed.ranges },
      function(err, messages) {
        if (err) {
          sendTagged(tag, 'NO', err.message || 'Cannot resolve messages');
          return;
        }
        storeBatch(tag, messages || [], flags, mode, silent, byUid, unchangedSince);
      });
  }

  // Issues a single batched `setFlags` event for all messages, then emits FETCH
  // responses for those that were actually modified.
  //
  // Event contract:
  //   session.on('setFlags', function(folder, query, cb) {
  //     // query = { uids, flags, mode, unchangedSince?, condstoreEnabled }
  //     // cb(null, [
  //     //   { uid, flags, modseq },        // modified
  //     //   { uid, skipped: true },         // UNCHANGEDSINCE rejected this one
  //     //   ...
  //     // ]);
  //   });
  function storeBatch(tag, messages, flags, mode, silent, byUid, unchangedSince) {
    let uids = messages.map(function(m) { return m.uid; });
    let query = {
      uids: uids,
      flags: flags,
      mode: mode,
      condstoreEnabled: context.condstoreEnabled
    };
    if (unchangedSince != null) query.unchangedSince = unchangedSince;

    ev.emit('setFlags', context.currentFolder, query, function(err, results) {
      if (err) {
        sendTagged(tag, 'NO', err.message || 'STORE failed');
        return;
      }

      // Index results by uid for lookup during FETCH emission
      results = results || [];
      let byUidMap = {};
      for (let i = 0; i < results.length; i++) {
        let r = results[i];
        if (r && typeof r.uid === 'number') byUidMap[r.uid] = r;
        // Dev-mode warning: flags should be clean names, not backslashed.
        // Fires at most once per process.
        if (r && r.flags) checkFlagsHygiene(r.flags, 'setFlags');
      }

      // Walk messages in sequence order and emit FETCH responses as needed
      let skippedUids = [];
      for (let i = 0; i < messages.length; i++) {
        let msg = messages[i];
        let r = byUidMap[msg.uid];
        if (!r) continue;   // developer dropped this uid — skip silently

        if (r.skipped) {
          skippedUids.push(msg.uid);
          continue;
        }

        // After STORE, server MUST send untagged FETCH with new flags (unless .SILENT)
        // RFC 7162 §3.2: MODSEQ is also included in the FETCH response when CONDSTORE
        // is enabled, even for silent stores (clients need the new MODSEQ).
        let shouldEmit = !silent || byUid || context.condstoreEnabled;
        if (!shouldEmit) continue;

        let items = [];
        if (byUid) items.push({ name: 'UID' });
        items.push({ name: 'FLAGS' });
        if (context.condstoreEnabled) items.push({ name: 'MODSEQ' });
        let meta = { flags: r.flags != null ? r.flags : flags };
        if (r.modseq != null) meta.modseq = r.modseq;
        emitFetchResponse(msg.seq, msg.uid, meta, null, null, items, byUid);
      }

      let code = null;
      if (skippedUids.length > 0) {
        code = 'MODIFIED ' + compressUids(skippedUids);
      }
      sendTagged(tag, 'OK', (byUid ? 'UID ' : '') + 'STORE completed', code);
    });
  }

  // --- COPY / UID COPY ---
  function handleCopy(tag, args, byUid) {
    if (!requireSelected(tag)) return;
    if (args.length < 2) {
      sendTagged(tag, 'BAD', 'COPY requires sequence set and destination');
      return;
    }
    let setStr = getStringValue(args[0]);
    let dst = getStringValue(args[1]);

    let parsed = parseSequenceSet(setStr, { isUid: byUid, total: context.currentFolderTotal });
    if (parsed.error) {
      sendTagged(tag, 'BAD', 'Invalid sequence set: ' + parsed.error);
      return;
    }

    ev.emit('resolveMessages', context.currentFolder,
      { type: byUid ? 'uid' : 'seq', ranges: parsed.ranges },
      function(err, messages) {
        if (err) {
          sendTagged(tag, 'NO', err.message || 'Cannot resolve messages');
          return;
        }
        messages = messages || [];
        if (messages.length === 0) {
          sendTagged(tag, 'OK', (byUid ? 'UID ' : '') + 'COPY completed');
          return;
        }
        let uids = messages.map(function(m) { return m.uid; });
        ev.emit('copyMessages', context.currentFolder, uids, dst, function(err, mapping) {
          if (err) {
            sendTagged(tag, 'NO', err.message || 'Cannot copy messages');
            return;
          }
          // RFC 4315 COPYUID: developer returns either
          //   • [{srcUid, dstUid}, ...]                        (legacy, no COPYUID emitted)
          //   • {dstUidValidity, mapping:[{srcUid, dstUid}]}   (emits COPYUID)
          let code = buildCopyUidCode(mapping);
          sendTagged(tag, 'OK', (byUid ? 'UID ' : '') + 'COPY completed', code);
        });
      });
  }

  s.handleFetch = handleFetch;
  s.handleStore = handleStore;
  s.handleCopy  = handleCopy;

  // Exposed for QRESYNC sync in imap_folders.js (handleSelect w/ QRESYNC
  // parameter sends FETCH responses for changed messages as part of resync).
  s.emitFetchResponse = emitFetchResponse;
}
