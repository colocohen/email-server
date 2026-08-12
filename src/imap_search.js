// ============================================================================
//  imap_search.js
// ----------------------------------------------------------------------------
//  Server-side handlers for query commands: SEARCH, SORT, THREAD (+ UID
//  variants). These three share the same overall shape — accept a criteria
//  expression, delegate the actual matching to the developer via an event,
//  then format the results — so it's natural to group them in one module.
//
//  Commands covered:
//    SEARCH (RFC 3501 §6.4.4)
//    SORT   (RFC 5256 §3)
//    THREAD (RFC 5256 §4)  — ORDEREDSUBJECT / REFERENCES algorithms
//
//  The CONDSTORE MODSEQ search-result option (RFC 7162 §3.1.5) is implemented
//  here via `criteriaContainsModseq` + conditional MODSEQ response appending.
//
//  Dependencies injected via the `s` session interface passed to
//  `registerSearchHandlers(s)`. The function attaches three handlers:
//
//     s.handleSearch(tag, args, byUid)
//     s.handleSort  (tag, args, byUid)
//     s.handleThread(tag, args, byUid)
//
//  which the session dispatcher then calls. `s` provides:
//
//     s.context         — session state (currentFolder, condstoreEnabled, total)
//     s.ev              — EventEmitter (for search/sort/thread events)
//     s.sendTagged      — send tagged OK/NO/BAD reply
//     s.sendUntagged    — send untagged response
//     s.requireSelected — guard: verify SELECTED state
// ============================================================================

import { TOK } from './imap_wire.js';
import { parseSearchCriteria, compressUids } from './imap_helpers.js';


export function registerSearchHandlers(s) {
  const context        = s.context;
  const ev             = s.ev;
  const sendTagged     = s.sendTagged;
  const sendUntagged   = s.sendUntagged;
  const requireSelected = s.requireSelected;

  // --- SEARCH / UID SEARCH ---
  //
  // Three RFCs meet in this one command:
  //   RFC 3501 §6.4.4 — the base form, answered with "* SEARCH n n n"
  //   RFC 4731        — SEARCH RETURN (MIN MAX ALL COUNT), answered with
  //                     "* ESEARCH (TAG "a1") [UID] MIN n MAX n ALL 1:5 COUNT n"
  //   RFC 5182        — RETURN (SAVE) stores the result set under "$", which
  //                     later commands reference in place of a sequence set
  //
  // RETURN is what distinguishes them: absent, the reply is the classic
  // untagged SEARCH line, exactly as before. Present, the reply is ESEARCH.
  // Clients that never send RETURN see no change at all.
  function handleSearch(tag, args, byUid) {
    if (!requireSelected(tag)) return;

    let start = 0;

    // Optional RETURN (...) — must come first, before CHARSET (RFC 4731 §3.1)
    let returnOpts = null;
    if (args.length >= 2 && String(args[0].value || '').toUpperCase() === 'RETURN' &&
        args[1] && args[1].type === TOK.LIST) {
      returnOpts = parseReturnOptions(args[1]);
      if (!returnOpts) {
        sendTagged(tag, 'BAD', 'Invalid SEARCH RETURN options');
        return;
      }
      start = 2;
    }

    // Optional CHARSET argument per RFC 3501 §6.4.4:
    //   SEARCH [CHARSET <charset>] <criteria...>
    // We accept and ignore it — the developer's matcher is charset-agnostic.
    if (args.length >= start + 2 && String(args[start].value || '').toUpperCase() === 'CHARSET') {
      start += 2;
    }
    if (start >= args.length) {
      sendTagged(tag, 'BAD', 'SEARCH requires criteria');
      return;
    }

    let parsed = parseSearchCriteria(args, start, context.currentFolderTotal);
    let criteria = parsed.node;

    // Criteria must have at least one child — otherwise the client sent nothing meaningful
    if (!criteria.children || criteria.children.length === 0) {
      sendTagged(tag, 'BAD', 'SEARCH requires criteria');
      return;
    }

    // RFC 7162 §3.1.5: if the criteria includes MODSEQ, the server MUST include
    // the MODSEQ search-result option. Also implicitly enables CONDSTORE.
    let hasModseqCriterion = criteriaContainsModseq(criteria);
    if (hasModseqCriterion) context.condstoreEnabled = true;

    ev.emit('search', context.currentFolder, criteria, function(err, results) {
      if (err) {
        sendTagged(tag, 'NO', err.message || 'SEARCH failed');
        return;
      }
      results = results || [];

      // Extract seq or uid numbers AND track highest modseq.
      // Two accepted shapes (both appear naturally in developer code):
      //   [{seq, uid, modseq?}, ...]  — the documented rich form
      //   [3, 7, 12]                  — plain numbers (seq or uid per command
      //                                 type); previously this yielded an
      //                                 EMPTY "* SEARCH" with zero feedback.
      let nums = [];
      let uidsForSave = [];
      let highestModseq = 0;
      for (let i = 0; i < results.length; i++) {
        let r = results[i];
        if (r == null) continue;
        if (typeof r === 'number') { nums.push(r); uidsForSave.push(r); continue; }
        let n = byUid ? r.uid : r.seq;
        if (typeof n === 'number') nums.push(n);
        // SEARCHRES stores UIDs when available so the saved set survives the
        // sequence renumbering that an EXPUNGE causes (RFC 5182 §2.1).
        if (typeof r.uid === 'number') uidsForSave.push(r.uid);
        else if (typeof n === 'number') uidsForSave.push(n);
        if (typeof r.modseq === 'number' && r.modseq > highestModseq) highestModseq = r.modseq;
      }

      // RFC 5182 — RETURN (SAVE) records the result for later "$" references.
      if (returnOpts && returnOpts.save) {
        context.savedSearchResult = { uids: uidsForSave.slice(), byUid: byUid };
      }

      if (returnOpts) {
        sendEsearchResponse(tag, byUid, nums, returnOpts, hasModseqCriterion, highestModseq);
      } else {
        let respLine = 'SEARCH' + (nums.length ? ' ' + nums.join(' ') : '');
        // Append (MODSEQ N) search-result option when required or when developer supplied it
        if ((hasModseqCriterion || context.condstoreEnabled) && highestModseq > 0) {
          respLine += ' (MODSEQ ' + highestModseq + ')';
        }
        sendUntagged(respLine);
      }
      sendTagged(tag, 'OK', (byUid ? 'UID ' : '') + 'SEARCH completed');
    });
  }

  // Parse the RETURN (...) option list. Returns null on an unknown option so
  // the caller can answer BAD rather than silently ignoring what the client
  // asked for. An EMPTY list is legal and means ALL (RFC 4731 §3.1).
  function parseReturnOptions(listTok) {
    let opts = { min: false, max: false, all: false, count: false, save: false };
    let any = false;
    for (let i = 0; i < listTok.value.length; i++) {
      let t = listTok.value[i];
      if (!t) return null;
      let name = String(t.value || '').toUpperCase();
      if      (name === 'MIN')   opts.min = true;
      else if (name === 'MAX')   opts.max = true;
      else if (name === 'ALL')   opts.all = true;
      else if (name === 'COUNT') opts.count = true;
      else if (name === 'SAVE')  opts.save = true;
      else return null;
      any = true;
    }
    // "RETURN ()" — default to ALL. Likewise "RETURN (SAVE)" alone: the
    // client wants the set stored but no data echoed back (§2.1), so ALL
    // stays off in that case.
    if (!any) opts.all = true;
    return opts;
  }

  // Build "* ESEARCH (TAG "<tag>") [UID] MIN n MAX n ALL <set> COUNT n".
  // Items appear only when requested. Per RFC 4731 §3.1 an empty result set
  // omits MIN/MAX/ALL entirely (COUNT 0 is still sent when asked).
  function sendEsearchResponse(tag, byUid, nums, opts, hasModseq, highestModseq) {
    let parts = ['(TAG "' + tag + '")'];
    if (byUid) parts.push('UID');

    if (nums.length > 0) {
      if (opts.min) parts.push('MIN ' + Math.min.apply(null, nums));
      if (opts.max) parts.push('MAX ' + Math.max.apply(null, nums));
      if (opts.all) parts.push('ALL ' + compressUids(nums));
    }
    if (opts.count) parts.push('COUNT ' + nums.length);
    if ((hasModseq || context.condstoreEnabled) && highestModseq > 0) {
      parts.push('MODSEQ ' + highestModseq);
    }

    // A RETURN (SAVE)-only request produces no data items — the tagged OK is
    // the whole answer, so skip the untagged line rather than emit a bare tag.
    if (parts.length === 1 || (parts.length === 2 && byUid)) return;
    sendUntagged('ESEARCH ' + parts.join(' '));
  }

  // Walk a criteria tree looking for any MODSEQ predicate.
  function criteriaContainsModseq(node) {
    if (!node) return false;
    if (node.op === 'modseq') return true;
    if (node.children) {
      for (let i = 0; i < node.children.length; i++) {
        if (criteriaContainsModseq(node.children[i])) return true;
      }
    }
    if (node.child && criteriaContainsModseq(node.child)) return true;
    return false;
  }


  // ============================================================
  //  SORT / THREAD (RFC 5256)
  // ============================================================

  // Valid SORT keys per RFC 5256 §3. Developer receives these as lowercase in
  // the sortCriteria tree. REVERSE is a modifier, not a key — folded into
  // {key, reverse:true} during parsing.
  const SORT_KEYS = {
    ARRIVAL:1, CC:1, DATE:1, FROM:1, SIZE:1, SUBJECT:1, TO:1
    // (we also accept `DISPLAYFROM` / `DISPLAYTO` from RFC 5957 as passthrough)
  };

  // Parse the parenthesized sort criteria list into a JS array.
  // Wire:    (REVERSE DATE SUBJECT)
  // Tree:    [{key: 'date', reverse: true}, {key: 'subject', reverse: false}]
  //
  // Returns null on parse error so the caller can send BAD.
  function parseSortCriteria(listTok) {
    if (!listTok || listTok.type !== TOK.LIST) return null;
    let out = [];
    let reverseNext = false;
    for (let i = 0; i < listTok.value.length; i++) {
      let t = listTok.value[i];
      if (!t || t.type !== TOK.ATOM) return null;
      let name = String(t.value || '').toUpperCase();
      if (name === 'REVERSE') {
        if (reverseNext) return null;  // REVERSE REVERSE is illegal
        reverseNext = true;
        continue;
      }
      // Accept any atom that looks like a sort key — unknown keys passthrough
      // so extensions (DISPLAYFROM etc.) work without code changes.
      out.push({ key: name.toLowerCase(), reverse: reverseNext });
      reverseNext = false;
    }
    if (reverseNext) return null;  // trailing REVERSE with no key
    if (out.length === 0) return null;
    return out;
  }

  // --- SORT / UID SORT ---
  //   SORT (<criteria>) <charset> <search-criteria...>
  //
  // Emits 'sort' event; developer returns sorted [{uid, seq}] pairs.
  function handleSort(tag, args, byUid) {
    if (!requireSelected(tag)) return;
    if (args.length < 3) {
      sendTagged(tag, 'BAD', 'SORT requires criteria, charset, and search keys');
      return;
    }

    // args[0] = sort criteria list
    let sortCriteria = parseSortCriteria(args[0]);
    if (!sortCriteria) {
      sendTagged(tag, 'BAD', 'Invalid SORT criteria');
      return;
    }

    // args[1] = charset (ignored — developer's matcher is charset-agnostic)

    // args[2+] = search criteria
    let parsed = parseSearchCriteria(args, 2, context.currentFolderTotal);
    if (!parsed.node.children || parsed.node.children.length === 0) {
      sendTagged(tag, 'BAD', 'SORT requires search criteria');
      return;
    }

    ev.emit('sort', context.currentFolder, sortCriteria, parsed.node, function(err, results) {
      if (err) {
        sendTagged(tag, 'NO', err.message || 'SORT failed');
        return;
      }
      results = results || [];
      let nums = [];
      for (let i = 0; i < results.length; i++) {
        let r = results[i];
        if (!r) continue;
        let n = byUid ? r.uid : r.seq;
        if (typeof n === 'number') nums.push(n);
      }
      sendUntagged('SORT' + (nums.length ? ' ' + nums.join(' ') : ''));
      sendTagged(tag, 'OK', (byUid ? 'UID ' : '') + 'SORT completed');
    });
  }

  // --- THREAD / UID THREAD ---
  //   THREAD <algorithm> <charset> <search-criteria...>
  //
  // Developer returns a forest of thread nodes:
  //   [ { uid, seq, children?: [...] }, ... ]
  function handleThread(tag, args, byUid) {
    if (!requireSelected(tag)) return;
    if (args.length < 3) {
      sendTagged(tag, 'BAD', 'THREAD requires algorithm, charset, and search keys');
      return;
    }

    let algo = String(args[0].value || '').toLowerCase();
    if (!algo) {
      sendTagged(tag, 'BAD', 'Invalid THREAD algorithm');
      return;
    }

    // args[1] = charset (ignored)
    let parsed = parseSearchCriteria(args, 2, context.currentFolderTotal);
    if (!parsed.node.children || parsed.node.children.length === 0) {
      sendTagged(tag, 'BAD', 'THREAD requires search criteria');
      return;
    }

    ev.emit('thread', context.currentFolder, algo, parsed.node, function(err, forest) {
      if (err) {
        sendTagged(tag, 'NO', err.message || 'THREAD failed');
        return;
      }
      forest = forest || [];
      sendUntagged('THREAD' + (forest.length ? ' ' + serializeThreadForest(forest, byUid) : ''));
      sendTagged(tag, 'OK', (byUid ? 'UID ' : '') + 'THREAD completed');
    });
  }

  // Serialize a forest of thread nodes into the RFC 5256 §4 paren form.
  //   [{uid:3, seq:3, children:[{uid:6, seq:6, children:[
  //     {uid:4, seq:4, children:[{uid:23, seq:23}]},
  //     {uid:44, seq:44, children:[{uid:7, seq:7, children:[{uid:96, seq:96}]}]}
  //   ]}]}]
  //   →  "(3 6 (4 23)(44 7 96))"
  function serializeThreadForest(forest, byUid) {
    let parts = [];
    for (let i = 0; i < forest.length; i++) {
      parts.push('(' + serializeThreadNode(forest[i], byUid) + ')');
    }
    return parts.join('');
  }

  function serializeThreadNode(node, byUid) {
    let id = byUid ? node.uid : node.seq;
    let out = String(id);
    let children = node.children || [];

    if (children.length === 0) return out;

    if (children.length === 1) {
      // Linear reply: no extra parens around the child
      return out + ' ' + serializeThreadNode(children[0], byUid);
    }

    // Multiple children — each becomes its own branch "(child...)"
    let branches = [];
    for (let i = 0; i < children.length; i++) {
      branches.push('(' + serializeThreadNode(children[i], byUid) + ')');
    }
    return out + ' ' + branches.join('');
  }
  s.handleSearch = handleSearch;
  s.handleSort   = handleSort;
  s.handleThread = handleThread;
}
