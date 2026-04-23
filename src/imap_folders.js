// ============================================================================
//  imap_folders.js
// ----------------------------------------------------------------------------
//  Server-side handlers for folder (mailbox) operations. This file groups all
//  commands that operate on the folder level of the mailbox — from listing
//  and selecting folders, through creating/deleting/renaming them, down to
//  the per-folder message operations APPEND and EXPUNGE, and finally MOVE
//  (which is really COPY+EXPUNGE packaged as one command per RFC 6851).
//
//  Commands covered:
//    LIST / LSUB       (RFC 3501 §6.3.8-9)
//    SELECT / EXAMINE  (RFC 3501 §6.3.1-2, with QRESYNC resync per RFC 7162)
//    STATUS            (RFC 3501 §6.3.10)
//    CREATE / DELETE / RENAME          (RFC 3501 §6.3.3-5)
//    SUBSCRIBE / UNSUBSCRIBE           (RFC 3501 §6.3.6-7)
//    CLOSE / UNSELECT                  (RFC 3501 §6.4.2 / RFC 3691)
//    APPEND            (RFC 3501 §6.3.11)
//    EXPUNGE / UID EXPUNGE (RFC 3501 §6.4.3 + RFC 4315)
//    MOVE / UID MOVE   (RFC 6851)
//    NAMESPACE         (RFC 2342)
//
//  Note: IDLE (RFC 2177) stays in imap_session.js because it is session-state
//  management (enter/leave idle mode), not a folder operation.
//
//  Dependencies injected via the `s` session interface. `registerFolderHandlers(s)`
//  attaches the following handlers:
//
//     s.handleList       s.handleSelect    s.handleStatus
//     s.handleCreate     s.handleDelete    s.handleRename
//     s.handleSubscribe  s.handleUnsubscribe
//     s.handleClose      s.handleUnselect
//     s.handleAppend     s.handleExpunge   s.handleMove
//     s.handleNamespace
//
//  `s` provides:
//
//     s.context           — session state
//     s.ev                — EventEmitter
//     s.STATE             — state machine constants (STATE.AUTHENTICATED, etc.)
//     s.sendTagged        — send tagged OK/NO/BAD reply
//     s.sendUntagged      — send untagged response
//     s.send              — send raw bytes / Buffer[]
//     s.getStringValue    — extract string from a token (atom/quoted/literal)
//     s.emitFetchResponse — build an untagged FETCH reply (used for QRESYNC sync)
//
//  IMPORTANT: `registerFolderHandlers` must be called AFTER
//  `registerMessageHandlers` since it depends on `s.emitFetchResponse`.
// ============================================================================

import { TOK } from './imap_wire.js';
import {
  FLAGS,
  DEFAULT_FLAGS,
  normalizeSpecialUse,
  normalizeFlag,
  serializeFlagList,
  makeWildcardMatcher,
  hasChildren,
  parseSequenceSet,
  compressUids,
  formatRanges,
  buildCopyUidCode,
  parseInternalDate
} from './imap_helpers.js';


export function registerFolderHandlers(s) {
  const context           = s.context;
  const ev                = s.ev;
  const STATE             = s.STATE;
  const sendTagged        = s.sendTagged;
  const sendUntagged      = s.sendUntagged;
  const send              = s.send;
  const getStringValue    = s.getStringValue;
  const emitFetchResponse = s.emitFetchResponse;
  const requireSelected   = s.requireSelected;

  // ============================================================
  //  SERVER MODE — Phase 2 handlers: folders + SELECT
  // ============================================================

  // Guard helper — most Phase 2 commands require authentication
  function requireAuth(tag) {
    if (!context.authenticated) {
      sendTagged(tag, 'BAD', 'Command requires authentication');
      return false;
    }
    return true;
  }

  // Clear any SELECTED state (used on CLOSE/UNSELECT and on implicit close via SELECT/EXAMINE).
  function exitSelected() {
    context.state = STATE.AUTHENTICATED;
    context.currentFolder = null;
    context.currentFolderReadOnly = false;
    context.currentFolderUidValidity = null;
    context.currentFolderTotal = 0;
    // Phase 3 will also clear sequence↔UID mapping here.
  }

  // --- LIST / LSUB (handler is shared; `subscribedOnly` chooses the event) ---
  //
  // Supports both RFC 3501 basic syntax:
  //     LIST reference mailbox
  //
  // and RFC 5258 extended syntax:
  //     LIST [ (selection-options) ] reference ( mailbox | (mailbox mailbox ...) )
  //          [ RETURN (return-options) ]
  //
  // Selection options:  SUBSCRIBED, REMOTE, RECURSIVEMATCH
  // Return options:     CHILDREN, SUBSCRIBED, SPECIAL-USE, STATUS (<items>)
  //
  // Thunderbird issues the extended form by default, e.g.:
  //     LIST () "" "*" RETURN (CHILDREN SPECIAL-USE SUBSCRIBED)
  //
  // The RETURN STATUS option is especially valuable — it lets the client
  // fetch message counts for every folder in a single round-trip instead of
  // a LIST followed by one STATUS per folder.
  function handleList(tag, args, subscribedOnly) {
    if (!requireAuth(tag)) return;
    if (args.length < 2) {
      sendTagged(tag, 'BAD', 'LIST requires reference and mailbox pattern');
      return;
    }

    // ---- Parse (possibly-extended) LIST syntax ----
    let cursor = 0;
    let selectionOpts = {};   // { subscribed, remote, recursiveMatch }

    // Selection options: args[0] is a LIST → parse, advance cursor
    if (args[cursor] && args[cursor].type === TOK.LIST) {
      let selTok = args[cursor++];
      for (let i = 0; i < selTok.value.length; i++) {
        let opt = String(selTok.value[i].value || '').toUpperCase();
        if (opt === 'SUBSCRIBED')     selectionOpts.subscribed     = true;
        else if (opt === 'REMOTE')    selectionOpts.remote         = true;
        else if (opt === 'RECURSIVEMATCH') selectionOpts.recursiveMatch = true;
      }
    }

    if (cursor >= args.length) {
      sendTagged(tag, 'BAD', 'LIST requires reference');
      return;
    }
    let reference = getStringValue(args[cursor++]);

    if (cursor >= args.length) {
      sendTagged(tag, 'BAD', 'LIST requires mailbox pattern');
      return;
    }
    // Patterns: either a single mailbox string, or a parenthesized list
    let patterns = [];
    let patTok = args[cursor++];
    if (patTok.type === TOK.LIST) {
      for (let i = 0; i < patTok.value.length; i++) {
        patterns.push(getStringValue(patTok.value[i]));
      }
    } else {
      patterns.push(getStringValue(patTok));
    }

    // RETURN clause (optional): atom 'RETURN' followed by a LIST
    let returnOpts = { children: false, subscribed: false, specialUse: false, status: null };
    if (cursor < args.length &&
        args[cursor].type === TOK.ATOM &&
        String(args[cursor].value).toUpperCase() === 'RETURN') {
      cursor++;
      if (cursor >= args.length || args[cursor].type !== TOK.LIST) {
        sendTagged(tag, 'BAD', 'RETURN requires a parenthesized option list');
        return;
      }
      let retTok = args[cursor++];
      for (let i = 0; i < retTok.value.length; i++) {
        let opt = String(retTok.value[i].value || '').toUpperCase();
        if (opt === 'CHILDREN')         returnOpts.children   = true;
        else if (opt === 'SUBSCRIBED')  returnOpts.subscribed = true;
        else if (opt === 'SPECIAL-USE') returnOpts.specialUse = true;
        else if (opt === 'STATUS' && i + 1 < retTok.value.length &&
                 retTok.value[i + 1].type === TOK.LIST) {
          // RETURN (STATUS (MESSAGES UNSEEN ...)) — items come as the next list
          let items = [];
          let itemList = retTok.value[i + 1].value;
          for (let j = 0; j < itemList.length; j++) {
            items.push(String(itemList[j].value || '').toUpperCase());
          }
          returnOpts.status = items;
          i++;   // skip the items list
        }
      }
    }

    // LSUB → treat as LIST with SUBSCRIBED selection (plus legacy flag)
    if (subscribedOnly) selectionOpts.subscribed = true;

    // Special case per RFC 3501 §6.3.8: LIST "" "" returns just the hierarchy
    // delimiter. "Ping" for clients to discover the delimiter.
    if (reference === '' && patterns.length === 1 && patterns[0] === '') {
      sendUntagged('LIST (\\Noselect) "' + context.delimiter + '" ""');
      sendTagged(tag, 'OK', 'LIST completed');
      return;
    }

    ev.emit('folders', function(err, folders) {
      if (err) {
        sendTagged(tag, 'NO', err.message || 'Cannot list folders');
        return;
      }
      folders = folders || [];

      // Apply SUBSCRIBED selection filter
      if (selectionOpts.subscribed) {
        folders = folders.filter(function(f) {
          return f.subscribed !== false;   // default is subscribed
        });
      }

      // Build matchers for each pattern and collect all names for HasChildren
      let matchers = patterns.map(function(p) {
        return makeWildcardMatcher(reference, p, context.delimiter);
      });
      let allNames = folders.map(function(f) { return f.name; });

      // Collect folders that matched at least one pattern (dedup by name)
      let seen = {};
      let matched = [];
      for (let i = 0; i < folders.length; i++) {
        let f = folders[i];
        if (!f || !f.name || seen[f.name]) continue;
        for (let m = 0; m < matchers.length; m++) {
          if (matchers[m](f.name)) {
            seen[f.name] = true;
            matched.push(f);
            break;
          }
        }
      }

      // Emit one LIST/LSUB response per matched folder
      let respName = (subscribedOnly ? 'LSUB' : 'LIST');
      for (let i = 0; i < matched.length; i++) {
        let f = matched[i];
        let attrs = [];
        // \HasChildren / \HasNoChildren (RFC 3348) — always sent; Thunderbird
        // needs this to render the tree even without explicit RETURN (CHILDREN)
        attrs.push(hasChildren(f.name, allNames, context.delimiter) ? '\\HasChildren' : '\\HasNoChildren');
        // Special-use (RFC 6154) — always sent when present, not gated on
        // RETURN (SPECIAL-USE) in practice (Thunderbird expects it regardless).
        let su = normalizeSpecialUse(f.specialUse);
        if (su) attrs.push(su);
        // \Subscribed (RFC 5258) — only when RETURN (SUBSCRIBED) was requested,
        // or when the legacy LSUB command is in use.
        if ((returnOpts.subscribed || subscribedOnly) && f.subscribed !== false) {
          attrs.push('\\Subscribed');
        }
        // \Noselect if developer marked folder as container-only
        if (f.selectable === false) attrs.push('\\Noselect');

        sendUntagged(respName + ' (' + attrs.join(' ') + ') "' + context.delimiter + '" ' + quoteMailbox(f.name));
      }

      // RETURN (STATUS (...)) — emit STATUS untagged per folder, then OK.
      // This is a huge UX win for folder panels: the mail client gets
      // unread counts for every folder in one round-trip.
      if (returnOpts.status && matched.length > 0) {
        let pendingStatus = matched.length;
        function oneStatus() {
          if (--pendingStatus === 0) {
            sendTagged(tag, 'OK', respName + ' completed');
          }
        }
        for (let i = 0; i < matched.length; i++) {
          emitStatusForFolder(matched[i].name, returnOpts.status, oneStatus);
        }
        return;
      }

      sendTagged(tag, 'OK', respName + ' completed');
    });
  }

  // Emit a single "* STATUS <mailbox> (<items>)" untagged response for the
  // given folder and items, then call done(). Used by LIST RETURN (STATUS ...)
  // and by the regular STATUS command. Items are the uppercase atoms like
  // MESSAGES / UIDNEXT / UIDVALIDITY / UNSEEN / RECENT / HIGHESTMODSEQ.
  function emitStatusForFolder(name, items, done) {
    ev.emit('status', name, items, function(err, stats) {
      if (err || !stats) {
        // On error we skip the STATUS line rather than abort the whole LIST
        if (done) done();
        return;
      }
      let parts = [];
      for (let i = 0; i < items.length; i++) {
        let k = items[i];
        let v;
        switch (k) {
          case 'MESSAGES':      v = stats.messages;      break;
          case 'UIDNEXT':       v = stats.uidnext;       break;
          case 'UIDVALIDITY':   v = stats.uidvalidity;   break;
          case 'UNSEEN':        v = stats.unseen;        break;
          case 'RECENT':        v = stats.recent;        break;
          case 'HIGHESTMODSEQ': v = stats.highestmodseq; break;
          case 'DELETED':       v = stats.deleted;       break;
          case 'SIZE':          v = stats.size;          break;
          default:              v = undefined;
        }
        if (v != null) parts.push(k + ' ' + v);
      }
      sendUntagged('STATUS ' + quoteMailbox(name) + ' (' + parts.join(' ') + ')');
      if (done) done();
    });
  }

  // --- SELECT / EXAMINE (shared; `readOnly` chooses) ---
  function handleSelect(tag, args, readOnly) {
    if (!requireAuth(tag)) return;
    if (args.length < 1) {
      sendTagged(tag, 'BAD', (readOnly ? 'EXAMINE' : 'SELECT') + ' requires mailbox name');
      return;
    }

    let name = getStringValue(args[0]);

    // RFC 7162 §3.1.8 / §3.2.5: optional parameter list
    //   SELECT mbox (CONDSTORE)
    //   SELECT mbox (QRESYNC (<uidvalidity> <lastModseq> [<knownUids>]))
    let qresyncParams = null;
    if (args.length >= 2 && args[1].type === TOK.LIST) {
      let params = args[1].value;
      for (let i = 0; i < params.length; i++) {
        let p = params[i];
        if (p.type !== TOK.ATOM) continue;
        let pname = String(p.value || '').toUpperCase();
        if (pname === 'CONDSTORE') {
          context.condstoreEnabled = true;
        }
        else if (pname === 'QRESYNC' && i + 1 < params.length && params[i + 1].type === TOK.LIST) {
          qresyncParams = parseQresyncParam(params[i + 1]);
          if (qresyncParams) {
            // QRESYNC implies CONDSTORE (RFC 7162 §3.2.3)
            context.condstoreEnabled = true;
            context.qresyncEnabled = true;
          }
          i++;  // skip the nested list
        }
      }
    }

    // RFC 3501 §6.3.1: any already-selected mailbox is implicitly deselected
    // regardless of whether the new SELECT succeeds. After an unsuccessful
    // SELECT, no mailbox is selected.
    exitSelected();

    ev.emit('openFolder', name, function(err, info) {
      if (err) {
        sendTagged(tag, 'NO', err.message || 'Cannot open folder');
        return;
      }
      if (!info) {
        sendTagged(tag, 'NO', 'Folder not found');
        return;
      }

      // Apply defaults
      let flags          = info.flags          || DEFAULT_FLAGS;
      let permanentFlags = info.permanentFlags || DEFAULT_FLAGS.concat(['*']);
      let total          = info.total != null ? info.total : 0;
      let recent         = info.recent != null ? info.recent : 0;
      let uidValidity    = info.uidValidity != null ? info.uidValidity : 1;
      let uidNext        = info.uidNext     != null ? info.uidNext     : 1;
      let highestModseq  = info.highestModseq != null ? info.highestModseq : 0;

      // Send required untagged responses (RFC 3501 §6.3.1)
      sendUntagged('FLAGS ' + serializeFlagList(flags));
      sendUntagged(total + ' EXISTS');
      sendUntagged(recent + ' RECENT');
      if (info.unseen != null) {
        sendUntagged('OK [UNSEEN ' + info.unseen + '] Message ' + info.unseen + ' is first unseen');
      }
      sendUntagged('OK [UIDVALIDITY ' + uidValidity + '] UIDs valid');
      sendUntagged('OK [UIDNEXT ' + uidNext + '] Predicted next UID');
      sendUntagged('OK [PERMANENTFLAGS ' + serializeFlagList(permanentFlags) + '] Limited');
      if (info.highestModseq != null) {
        sendUntagged('OK [HIGHESTMODSEQ ' + highestModseq + '] Highest');
      } else {
        sendUntagged('OK [NOMODSEQ] No permanent mod-sequences for this mailbox');
      }

      // Update state on success
      context.state                     = STATE.SELECTED;
      context.currentFolder             = name;
      context.currentFolderReadOnly     = !!readOnly;
      context.currentFolderUidValidity  = uidValidity;
      context.currentFolderTotal        = total;
      context.currentFolderHighestModseq = highestModseq;

      let code = readOnly ? 'READ-ONLY' : 'READ-WRITE';
      let cmdName = readOnly ? 'EXAMINE' : 'SELECT';

      // RFC 7162 §3.2.5: if QRESYNC parameters were provided, emit the sync data
      // before the tagged OK. Abort gracefully if the developer doesn't handle it.
      if (qresyncParams && ev.listenerCount('qresync') > 0) {
        // Check uidValidity — if mismatched, the client's state is invalid
        // (per RFC 7162 §3.2.5.1) and we skip the resync entirely.
        if (qresyncParams.uidValidity !== uidValidity) {
          sendTagged(tag, 'OK', cmdName + ' completed', code);
          return;
        }
        ev.emit('qresync', name, qresyncParams, function(qerr, sync) {
          if (!qerr && sync) emitQresyncData(sync);
          sendTagged(tag, 'OK', cmdName + ' completed', code);
        });
        return;
      }

      sendTagged(tag, 'OK', cmdName + ' completed', code);
    });
  }

  // Parse the QRESYNC nested list: (uidvalidity modseq [knownUids] [(knownSeqs knownUids)])
  // Returns {uidValidity, lastKnownModseq, knownUids (flat ranges)} or null on error.
  function parseQresyncParam(listTok) {
    if (!listTok || listTok.type !== TOK.LIST) return null;
    let p = listTok.value;
    if (p.length < 2) return null;

    let uv = numericTokenValue(p[0]);
    let ms = numericTokenValue(p[1]);
    if (uv == null || ms == null) return null;

    let knownUids = null;
    let idx = 2;
    // Optional: known-uids sequence set (atom)
    if (idx < p.length && p[idx].type === TOK.ATOM) {
      let parsed = parseSequenceSet(String(p[idx].value || ''), {});
      if (!parsed.error) knownUids = parsed.ranges;
      idx++;
    }
    // Optional: (known-sequence-set known-uid-set) — reconciliation data.
    // We don't implement full reconciliation; skip the nested list if present.

    return { uidValidity: uv, lastKnownModseq: ms, knownUids: knownUids };
  }

  function numericTokenValue(tok) {
    if (!tok) return null;
    if (tok.type === TOK.NUMBER) return tok.value;
    if (tok.type === TOK.ATOM) {
      let n = parseInt(tok.value, 10);
      return isNaN(n) ? null : n;
    }
    return null;
  }

  // Emit the VANISHED + FETCH responses that constitute a QRESYNC sync.
  // `sync` from the developer:
  //   { vanishedRanges: [from1, to1, ...]    (flat half-open) — preferred
  //     vanishedUids:   [uid, uid, ...]      (list) — alternative
  //     changedMessages: [{uid, seq, flags, modseq}, ...] }
  function emitQresyncData(sync) {
    // VANISHED (EARLIER) — collapsed ranges
    let vanishedStr = null;
    if (sync.vanishedRanges && sync.vanishedRanges.length > 0) {
      vanishedStr = formatRanges(sync.vanishedRanges);
    } else if (sync.vanishedUids && sync.vanishedUids.length > 0) {
      vanishedStr = compressUids(sync.vanishedUids);
    }
    if (vanishedStr) {
      sendUntagged('VANISHED (EARLIER) ' + vanishedStr);
    }

    // FETCH responses for each changed message
    let changed = sync.changedMessages || [];
    for (let i = 0; i < changed.length; i++) {
      let m = changed[i];
      let meta = { flags: m.flags || [], modseq: m.modseq };
      let items = [{ name: 'UID' }, { name: 'FLAGS' }, { name: 'MODSEQ' }];
      emitFetchResponse(m.seq, m.uid, meta, null, null, items, true);
    }
  }

  // --- CREATE ---
  function handleCreate(tag, args) {
    if (!requireAuth(tag)) return;
    if (args.length < 1) {
      sendTagged(tag, 'BAD', 'CREATE requires mailbox name');
      return;
    }
    let name = getStringValue(args[0]);

    // RFC 3501 §6.3.3: trailing hierarchy delimiter is a hint that the client
    // intends to create names under this one. Most servers strip and create normally.
    while (name.length > 1 && name.charAt(name.length - 1) === context.delimiter) {
      name = name.slice(0, -1);
    }

    if (name.toUpperCase() === 'INBOX') {
      sendTagged(tag, 'NO', 'INBOX already exists');
      return;
    }

    // RFC 6154 §5: client may include USE (\Sent) option to set special-use on creation.
    // Look for a list argument whose first atom is "USE".
    let useFlags = extractUseFlags(args);

    let payload = { name: name };
    if (useFlags.length > 0) payload.specialUse = useFlags[0];  // primary use

    ev.emit('createFolder', name, payload, function(err) {
      if (err) {
        sendTagged(tag, 'NO', err.message || 'Cannot create folder');
        return;
      }
      sendTagged(tag, 'OK', 'CREATE completed');
    });
  }

  // Look through CREATE args for a "USE (\Sent ...)" option — returns normalized array.
  function extractUseFlags(args) {
    let out = [];
    for (let i = 1; i < args.length; i++) {
      let a = args[i];
      if (a && a.type === TOK.LIST && a.value && a.value.length >= 2) {
        let first = a.value[0];
        if (first && String(first.value || '').toUpperCase() === 'USE' &&
            a.value[1] && a.value[1].type === TOK.LIST) {
          let flagList = a.value[1].value || [];
          for (let j = 0; j < flagList.length; j++) {
            let v = String(flagList[j].value || '');
            let n = normalizeSpecialUse(v);
            if (n) out.push(n);
          }
        }
      }
    }
    return out;
  }

  // --- DELETE ---
  function handleDelete(tag, args) {
    if (!requireAuth(tag)) return;
    if (args.length < 1) {
      sendTagged(tag, 'BAD', 'DELETE requires mailbox name');
      return;
    }
    let name = getStringValue(args[0]);

    if (name.toUpperCase() === 'INBOX') {
      sendTagged(tag, 'NO', 'Cannot delete INBOX');
      return;
    }

    // If the folder being deleted is currently selected, the selection state is lost
    // (client will notice via the tagged response; many clients handle this explicitly).
    if (context.state === STATE.SELECTED && context.currentFolder === name) {
      exitSelected();
    }

    ev.emit('deleteFolder', name, function(err) {
      if (err) {
        sendTagged(tag, 'NO', err.message || 'Cannot delete folder');
        return;
      }
      sendTagged(tag, 'OK', 'DELETE completed');
    });
  }

  // --- RENAME ---
  function handleRename(tag, args) {
    if (!requireAuth(tag)) return;
    if (args.length < 2) {
      sendTagged(tag, 'BAD', 'RENAME requires old and new names');
      return;
    }
    let oldName = getStringValue(args[0]);
    let newName = getStringValue(args[1]);

    // If the renamed folder is currently selected, drop the selection.
    if (context.state === STATE.SELECTED && context.currentFolder === oldName) {
      exitSelected();
    }

    ev.emit('renameFolder', oldName, newName, function(err) {
      if (err) {
        sendTagged(tag, 'NO', err.message || 'Cannot rename folder');
        return;
      }
      sendTagged(tag, 'OK', 'RENAME completed');
    });
  }

  // --- SUBSCRIBE / UNSUBSCRIBE ---
  function handleSubscribe(tag, args) {
    if (!requireAuth(tag)) return;
    if (args.length < 1) {
      sendTagged(tag, 'BAD', 'SUBSCRIBE requires mailbox name');
      return;
    }
    let name = getStringValue(args[0]);
    ev.emit('subscribe', name, function(err) {
      if (err) {
        sendTagged(tag, 'NO', err.message || 'Cannot subscribe');
        return;
      }
      sendTagged(tag, 'OK', 'SUBSCRIBE completed');
    });
  }

  function handleUnsubscribe(tag, args) {
    if (!requireAuth(tag)) return;
    if (args.length < 1) {
      sendTagged(tag, 'BAD', 'UNSUBSCRIBE requires mailbox name');
      return;
    }
    let name = getStringValue(args[0]);
    ev.emit('unsubscribe', name, function(err) {
      if (err) {
        sendTagged(tag, 'NO', err.message || 'Cannot unsubscribe');
        return;
      }
      sendTagged(tag, 'OK', 'UNSUBSCRIBE completed');
    });
  }

  // --- STATUS ---
  function handleStatus(tag, args) {
    if (!requireAuth(tag)) return;
    if (args.length < 2) {
      sendTagged(tag, 'BAD', 'STATUS requires mailbox name and items');
      return;
    }
    let name = getStringValue(args[0]);
    if (args[1].type !== TOK.LIST) {
      sendTagged(tag, 'BAD', 'STATUS items must be a parenthesized list');
      return;
    }

    // Normalize requested items to an array of lowercase strings
    let requestedItems = [];
    for (let i = 0; i < args[1].value.length; i++) {
      let v = String(args[1].value[i].value || '').toUpperCase();
      if (v) requestedItems.push(v);
    }

    ev.emit('status', name, requestedItems, function(err, info) {
      if (err) {
        sendTagged(tag, 'NO', err.message || 'Cannot get status');
        return;
      }
      if (!info) {
        sendTagged(tag, 'NO', 'Folder not found');
        return;
      }

      // Build response items from what the developer provided, in the requested order
      let parts = [];
      for (let i = 0; i < requestedItems.length; i++) {
        let item = requestedItems[i];
        let val = null;
        if      (item === 'MESSAGES'    && info.messages    != null) val = info.messages;
        else if (item === 'RECENT'      && info.recent      != null) val = info.recent;
        else if (item === 'UIDNEXT'     && info.uidNext     != null) val = info.uidNext;
        else if (item === 'UIDVALIDITY' && info.uidValidity != null) val = info.uidValidity;
        else if (item === 'UNSEEN'      && info.unseen      != null) val = info.unseen;
        if (val != null) parts.push(item + ' ' + val);
      }

      sendUntagged('STATUS ' + quoteMailbox(name) + ' (' + parts.join(' ') + ')');
      sendTagged(tag, 'OK', 'STATUS completed');
    });
  }

  // --- CLOSE (discards deletions, exits SELECTED) ---
  function handleClose(tag) {
    if (!requireAuth(tag)) return;
    if (context.state !== STATE.SELECTED) {
      sendTagged(tag, 'BAD', 'No folder selected');
      return;
    }
    // Phase 4 will emit 'expunge' here for non-read-only; Phase 2 just closes.
    exitSelected();
    sendTagged(tag, 'OK', 'CLOSE completed');
  }

  // --- UNSELECT (RFC 3691) — like CLOSE but never expunges ---
  function handleUnselect(tag) {
    if (!requireAuth(tag)) return;
    if (context.state !== STATE.SELECTED) {
      sendTagged(tag, 'BAD', 'No folder selected');
      return;
    }
    exitSelected();
    sendTagged(tag, 'OK', 'UNSELECT completed');
  }

  // Quote a mailbox name for wire — uses quoted string if possible, else literal.
  // Reuses the tested quoteString logic from imap_wire's serializer.
  function quoteMailbox(name) {
    // Mailbox names in LIST/LSUB/STATUS responses are traditionally quoted strings,
    // even when they'd be atom-safe. We always quote for consistency.
    let hasSpecial = false;
    for (let i = 0; i < name.length; i++) {
      let c = name.charCodeAt(i);
      if (c === 13 || c === 10 || c === 0 || c > 127) { hasSpecial = true; break; }
    }
    if (hasSpecial) {
      // Needs literal
      let buf = Buffer.from(name, 'utf-8');
      return '{' + buf.length + '}\r\n' + name;
    }
    return '"' + name.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  }


  // --- APPEND (RFC 3501 §6.3.11) ---
  //   APPEND <mailbox> [ (<flags>) ] [ "<internal-date>" ] <literal>
  // flags and date are both optional. Literal is the raw RFC 5322 message bytes.
  function handleAppend(tag, args) {
    if (context.state !== STATE.AUTHENTICATED && context.state !== STATE.SELECTED) {
      sendTagged(tag, 'BAD', 'APPEND requires authentication');
      return;
    }
    if (args.length < 2) {
      sendTagged(tag, 'BAD', 'APPEND requires mailbox and message');
      return;
    }

    let folder = getStringValue(args[0]);
    let flags = null;
    let internalDate = null;
    let literal = null;

    // Walk the middle + last args, detecting each by token type.
    for (let i = 1; i < args.length; i++) {
      let a = args[i];
      if (a.type === TOK.LIST) {
        // Flag list: ([\Seen] [\Flagged] ...)
        flags = [];
        for (let j = 0; j < a.value.length; j++) {
          let f = a.value[j];
          flags.push(normalizeFlag(f.value));
        }
      } else if (a.type === TOK.LITERAL) {
        literal = a.value;
      } else if (a.type === TOK.QUOTED || a.type === TOK.ATOM) {
        let s = getStringValue(a);
        let d = parseInternalDate(s);
        if (d) internalDate = d;
      }
    }

    if (!literal) {
      sendTagged(tag, 'BAD', 'APPEND requires message literal');
      return;
    }

    let raw = Buffer.isBuffer(literal) ? literal : Buffer.from(literal);
    let options = {};
    if (flags)        options.flags = flags;
    if (internalDate) options.internalDate = internalDate;

    ev.emit('append', folder, raw, options, function(err, result) {
      if (err) {
        sendTagged(tag, 'NO', err.message || 'APPEND failed');
        return;
      }
      // RFC 4315 APPENDUID: if developer returned both uid and uidValidity, advertise it
      let code = null;
      if (result && result.uid != null && result.uidValidity != null) {
        code = 'APPENDUID ' + result.uidValidity + ' ' + result.uid;
      }
      sendTagged(tag, 'OK', 'APPEND completed', code);
    });
  }

  // --- EXPUNGE (RFC 3501 §6.4.3) + UID EXPUNGE (RFC 4315) ---
  // When args is null, this is a plain EXPUNGE (remove everything with \Deleted).
  // When args is an array, first arg is a UID set — only matching UIDs are expunged.
  function handleExpunge(tag, args) {
    if (!requireSelected(tag)) return;
    if (context.currentFolderReadOnly) {
      sendTagged(tag, 'NO', 'Cannot expunge in EXAMINE mode');
      return;
    }

    let options = null;
    let isUidExpunge = false;
    if (args && args.length >= 1) {
      isUidExpunge = true;
      let setStr = getStringValue(args[0]);
      let parsed = parseSequenceSet(setStr, { isUid: true, total: context.currentFolderTotal });
      if (parsed.error) {
        sendTagged(tag, 'BAD', 'Invalid UID set: ' + parsed.error);
        return;
      }
      options = { uidRanges: parsed.ranges };
    }

    ev.emit('expunge', context.currentFolder, options, function(err, deleted) {
      if (err) {
        sendTagged(tag, 'NO', err.message || 'EXPUNGE failed');
        return;
      }
      sendExpungeResponses(deleted || []);
      sendTagged(tag, 'OK', (isUidExpunge ? 'UID ' : '') + 'EXPUNGE completed');
    });
  }

  // Helper: emit "* N EXPUNGE" for each deleted message, in DECREASING seq order
  // so the client's seq numbers don't shift mid-batch. Also decrements the total.
  function sendExpungeResponses(deleted) {
    if (!deleted || deleted.length === 0) return;
    let sorted = deleted.slice().sort(function(a, b) { return b.seq - a.seq; });
    for (let i = 0; i < sorted.length; i++) {
      if (typeof sorted[i].seq === 'number') {
        sendUntagged(sorted[i].seq + ' EXPUNGE');
      }
    }
    context.currentFolderTotal = Math.max(0, context.currentFolderTotal - sorted.length);
  }

  // --- MOVE (RFC 6851) + UID MOVE ---
  //   MOVE <seq-set> <dst-mailbox>
  // Atomically copies messages to destination and expunges them from source.
  function handleMove(tag, args, byUid) {
    if (!requireSelected(tag)) return;
    if (context.currentFolderReadOnly) {
      sendTagged(tag, 'NO', 'Cannot move from read-only folder');
      return;
    }
    if (args.length < 2) {
      sendTagged(tag, 'BAD', 'MOVE requires sequence set and destination');
      return;
    }
    if (ev.listenerCount('move') === 0) {
      sendTagged(tag, 'NO', 'MOVE not supported');
      return;
    }

    let setStr = getStringValue(args[0]);
    let dst    = getStringValue(args[1]);
    let parsed = parseSequenceSet(setStr, { isUid: byUid, total: context.currentFolderTotal });
    if (parsed.error) {
      sendTagged(tag, 'BAD', 'Invalid sequence set: ' + parsed.error);
      return;
    }

    // Resolve set → list of {uid, seq} pairs
    ev.emit('resolveMessages', context.currentFolder,
      { type: byUid ? 'uid' : 'seq', ranges: parsed.ranges },
      function(err, messages) {
        if (err) { sendTagged(tag, 'NO', err.message); return; }
        messages = messages || [];
        if (messages.length === 0) {
          sendTagged(tag, 'OK', (byUid ? 'UID ' : '') + 'MOVE completed');
          return;
        }
        let uids = messages.map(function(m) { return m.uid; });

        ev.emit('move', context.currentFolder, uids, dst, function(err, mapping) {
          if (err) {
            sendTagged(tag, 'NO', err.message || 'MOVE failed');
            return;
          }
          // RFC 6851: send untagged "OK [COPYUID ...]" BEFORE the EXPUNGEs.
          // Developer can return either legacy array or {dstUidValidity, mapping}.
          let code = buildCopyUidCode(mapping);
          if (code) {
            sendUntagged('OK [' + code + '] Moved');
          }

          // Emit EXPUNGE for each moved message (in decreasing seq order)
          sendExpungeResponses(messages);
          sendTagged(tag, 'OK', (byUid ? 'UID ' : '') + 'MOVE completed');
        });
      });
  }



  // --- NAMESPACE (RFC 2342) ---
  //
  //   * NAMESPACE (personal) (otherUsers) (shared)
  //
  // Each group is NIL or a parenthesized list of ("prefix" "delimiter")
  // pairs. The developer supplies a flat array; we classify by `type` and
  // emit the three groups.
  //
  // Event signature:
  //   session.on('namespace', function(cb) {
  //     cb(null, [
  //       { type: 'personal',   prefix: '',         delimiter: '/' },
  //       { type: 'shared',     prefix: '#shared/', delimiter: '/' }
  //     ]);
  //   });
  //
  // If no listener is registered, the server returns a sensible default:
  //   personal namespace with prefix '' and delimiter '/'.
  function handleNamespace(tag) {
    if (context.state !== STATE.AUTHENTICATED && context.state !== STATE.SELECTED) {
      sendTagged(tag, 'BAD', 'NAMESPACE requires authentication');
      return;
    }

    function respond(entries) {
      entries = entries || [];
      // Classify by type (with alias support)
      let personal = [], others = [], shared = [];
      for (let i = 0; i < entries.length; i++) {
        let e = entries[i];
        let typ = String(e.type || 'personal').toLowerCase();
        if (typ === 'personal')        personal.push(e);
        else if (typ === 'otherusers' ||
                 typ === 'other' ||
                 typ === 'otheruser')  others.push(e);
        else if (typ === 'shared')     shared.push(e);
      }
      // Default: a single personal namespace with empty prefix
      if (personal.length === 0 && others.length === 0 && shared.length === 0) {
        personal = [{ prefix: '', delimiter: '/' }];
      }

      sendUntagged('NAMESPACE ' +
        buildNamespaceGroup(personal) + ' ' +
        buildNamespaceGroup(others) + ' ' +
        buildNamespaceGroup(shared));
      sendTagged(tag, 'OK', 'NAMESPACE completed');
    }

    if (ev.listenerCount('namespace') === 0) {
      respond(null);   // default namespace
      return;
    }
    ev.emit('namespace', function(err, entries) {
      if (err) {
        sendTagged(tag, 'NO', err.message || 'NAMESPACE failed');
        return;
      }
      respond(entries);
    });
  }

  // Build one namespace group: "NIL" if empty, otherwise
  // '(("prefix1" "delim1")("prefix2" "delim2")...)'. Delimiter may be null →
  // emits NIL inside the tuple (legal per RFC 2342 §5).
  function buildNamespaceGroup(entries) {
    if (!entries || entries.length === 0) return 'NIL';
    let parts = [];
    for (let i = 0; i < entries.length; i++) {
      let e = entries[i];
      parts.push('(' + nsQuote(e.prefix) + ' ' + nsQuote(e.delimiter) + ')');
    }
    return '(' + parts.join('') + ')';
  }

  function nsQuote(s) {
    if (s === null || s === undefined) return 'NIL';
    return '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  }

  // --- QUOTA (RFC 9208 — obsoletes RFC 2087) ---
  //
  //   GETQUOTA <quota-root>         → "* QUOTA <root> (<resource> <usage> <limit> ...)"
  //   GETQUOTAROOT <mailbox>        → "* QUOTAROOT <mailbox> <root1> <root2> ..."
  //                                   + one QUOTA response per root
  //   SETQUOTA (NOT supported — server is auth-time only)
  //
  // A "quota root" groups one or more mailboxes that share a resource budget.
  // A user's mailbox typically has one root (named after the user or "")
  // covering STORAGE and/or MESSAGE resources. Our event contract:
  //
  //   session.on('quota', function(root, cb) {
  //     cb(null, {
  //       root: root,                          // echoes input, or canonical name
  //       resources: [
  //         { name: 'STORAGE', usage: 15000, limit: 100000 },  // in KB per RFC
  //         { name: 'MESSAGE', usage: 42,    limit: 1000 }
  //       ]
  //     });
  //   });
  //
  //   session.on('quotaRoot', function(mailbox, cb) {
  //     cb(null, ['<root>', ...]);    // usually one root for the user's mailbox
  //   });
  //
  // If no 'quota' listener is registered the server returns NO — clients then
  // know not to display quota bars. This keeps the feature fully opt-in.
  function handleGetQuota(tag, args) {
    if (!requireAuth(tag)) return;
    if (args.length < 1) {
      sendTagged(tag, 'BAD', 'GETQUOTA requires a quota root name');
      return;
    }
    if (ev.listenerCount('quota') === 0) {
      sendTagged(tag, 'NO', 'Quota not implemented');
      return;
    }
    let root = getStringValue(args[0]);
    ev.emit('quota', root, function(err, info) {
      if (err) {
        sendTagged(tag, 'NO', err.message || 'Quota lookup failed');
        return;
      }
      if (info) emitQuotaResponse(info);
      sendTagged(tag, 'OK', 'GETQUOTA completed');
    });
  }

  function handleGetQuotaRoot(tag, args) {
    if (!requireAuth(tag)) return;
    if (args.length < 1) {
      sendTagged(tag, 'BAD', 'GETQUOTAROOT requires a mailbox name');
      return;
    }
    if (ev.listenerCount('quotaRoot') === 0 && ev.listenerCount('quota') === 0) {
      sendTagged(tag, 'NO', 'Quota not implemented');
      return;
    }
    let mailbox = getStringValue(args[0]);

    // If the developer didn't register quotaRoot, fall back to a single
    // implicit root named "" that we query via the 'quota' event.
    let roots;
    function afterRoots() {
      sendUntagged('QUOTAROOT ' + quoteMailbox(mailbox) +
        (roots.length ? ' ' + roots.map(nsQuote).join(' ') : ''));

      if (roots.length === 0) {
        sendTagged(tag, 'OK', 'GETQUOTAROOT completed');
        return;
      }
      let pending = roots.length;
      function oneRoot() { if (--pending === 0) sendTagged(tag, 'OK', 'GETQUOTAROOT completed'); }
      for (let i = 0; i < roots.length; i++) {
        (function(r) {
          ev.emit('quota', r, function(err, info) {
            if (!err && info) emitQuotaResponse(info);
            oneRoot();
          });
        })(roots[i]);
      }
    }

    if (ev.listenerCount('quotaRoot') > 0) {
      ev.emit('quotaRoot', mailbox, function(err, list) {
        roots = Array.isArray(list) ? list : [];
        afterRoots();
      });
    } else {
      roots = [''];   // implicit single root
      afterRoots();
    }
  }

  // Emit one "* QUOTA <root> (<name> <usage> <limit> ...)" line.
  function emitQuotaResponse(info) {
    let rootName = info.root != null ? String(info.root) : '';
    let pairs = [];
    let resources = info.resources || [];
    for (let i = 0; i < resources.length; i++) {
      let r = resources[i];
      if (!r || !r.name) continue;
      pairs.push(String(r.name).toUpperCase());
      pairs.push(Math.max(0, Math.floor(r.usage || 0)));
      pairs.push(Math.max(0, Math.floor(r.limit || 0)));
    }
    sendUntagged('QUOTA ' + nsQuote(rootName) + ' (' + pairs.join(' ') + ')');
  }

  s.handleList        = handleList;
  s.handleSelect      = handleSelect;
  s.handleCreate      = handleCreate;
  s.handleDelete      = handleDelete;
  s.handleRename      = handleRename;
  s.handleSubscribe   = handleSubscribe;
  s.handleUnsubscribe = handleUnsubscribe;
  s.handleStatus      = handleStatus;
  s.handleClose       = handleClose;
  s.handleUnselect    = handleUnselect;
  s.handleAppend      = handleAppend;
  s.handleExpunge     = handleExpunge;
  s.handleMove        = handleMove;
  s.handleNamespace   = handleNamespace;
  s.handleGetQuota    = handleGetQuota;
  s.handleGetQuotaRoot= handleGetQuotaRoot;
}
