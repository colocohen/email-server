// ============================================================================
//  imap_metadata.js — IMAP METADATA (RFC 5464) handlers
// ----------------------------------------------------------------------------
//  METADATA lets clients attach arbitrary annotations to mailboxes or to the
//  server as a whole, keyed by hierarchical paths. Typical uses:
//    • Apple Mail: /private/color, /private/notes
//    • Thunderbird: /private/sort-order, /private/columns
//    • iOS Mail: sync state
//
//  Path conventions (from the RFC):
//    /private/<name>  — visible only to the authenticating user
//    /shared/<name>   — visible to everyone with access to the mailbox
//
//  Both GETMETADATA and SETMETADATA operate at two scopes:
//    • A named mailbox:  GETMETADATA "INBOX" (/private/color)
//    • The server itself: GETMETADATA "" (/shared/admin)
//
//  This module is the protocol layer only — the library emits two events:
//
//     session.on('getMetadata', function(mailbox, paths, cb) {
//       // mailbox = '' for server-scope, else folder name
//       // paths = ['/private/color', '/shared/admin']
//       cb(null, { '/private/color': '#ff0000', '/shared/admin': null });
//     });
//
//     session.on('setMetadata', function(mailbox, entries, cb) {
//       // entries = { '/private/color': '#ff0000', '/private/notes': null }
//       //           null value = delete
//       cb(null);
//     });
//
//  The developer decides where to persist the values. If no listener is
//  registered the server returns NO and the client falls back to local storage.
// ============================================================================

import { TOK } from './imap_wire.js';


// Maximum value size advertised in CAPABILITY. Clients MUST NOT exceed this.
// 2 KB is Dovecot's default and is plenty for colors, sort orders, notes.
const DEFAULT_MAXSIZE = 2048;


export function registerMetadataHandlers(s) {
  const context           = s.context;
  const ev                = s.ev;
  const sendTagged        = s.sendTagged;
  const sendUntagged      = s.sendUntagged;
  const getStringValue    = s.getStringValue;

  // Per-session config — bumped later if developer sets server.metadataMaxSize
  const maxSize = DEFAULT_MAXSIZE;


  // --- GETMETADATA ---
  //   GETMETADATA [ (options) ] <mailbox> (<entry> <entry> ...)
  //
  // Options (all optional, all rare in practice):
  //   MAXSIZE <n>    — client asks server to skip values > n bytes
  //   DEPTH 0 | 1 | infinity  — sub-path traversal; we implement depth 0 only
  //                             (explicit paths; no "all under /private/*" yet).
  //
  // Most clients just send the basic form. We parse options leniently and
  // ignore anything we don't implement.
  function handleGetMetadata(tag, args) {
    if (ev.listenerCount('getMetadata') === 0) {
      sendTagged(tag, 'NO', 'METADATA not implemented');
      return;
    }
    if (args.length < 2) {
      sendTagged(tag, 'BAD', 'GETMETADATA requires mailbox and entry list');
      return;
    }

    let cursor = 0;
    let clientMaxSize = null;
    let depth = 0;

    // Optional leading options list
    if (args[cursor].type === TOK.LIST) {
      let optTok = args[cursor++];
      for (let i = 0; i + 1 < optTok.value.length; i += 2) {
        let name = String(optTok.value[i].value || '').toUpperCase();
        let val  = optTok.value[i + 1];
        if (name === 'MAXSIZE') {
          clientMaxSize = (val.type === TOK.NUMBER) ? val.value : parseInt(val.value, 10);
        } else if (name === 'DEPTH') {
          let d = String(val.value || '').toLowerCase();
          depth = (d === 'infinity') ? -1 : (parseInt(d, 10) || 0);
        }
      }
    }

    if (cursor >= args.length) {
      sendTagged(tag, 'BAD', 'GETMETADATA requires mailbox');
      return;
    }
    let mailbox = getStringValue(args[cursor++]);

    // Entry list — either a single atom or a parenthesized list
    let paths = [];
    if (cursor < args.length) {
      let entryTok = args[cursor++];
      if (entryTok.type === TOK.LIST) {
        for (let i = 0; i < entryTok.value.length; i++) {
          let p = getStringValue(entryTok.value[i]);
          if (p) paths.push(p);
        }
      } else {
        let p = getStringValue(entryTok);
        if (p) paths.push(p);
      }
    }

    // Validate paths — must start with /private/ or /shared/
    for (let i = 0; i < paths.length; i++) {
      if (!validPath(paths[i])) {
        sendTagged(tag, 'BAD', 'Invalid METADATA path: ' + paths[i]);
        return;
      }
    }

    ev.emit('getMetadata', mailbox, paths, function(err, values) {
      if (err) {
        sendTagged(tag, 'NO', err.message || 'GETMETADATA failed');
        return;
      }
      values = values || {};

      // Honor client-supplied MAXSIZE: entries with values exceeding it are
      // reported with a LONGENTRIES response code rather than the value.
      let effMax = (clientMaxSize != null && clientMaxSize < maxSize) ? clientMaxSize : maxSize;
      let longest = 0;

      // Build METADATA untagged response — one line with all key/value pairs
      //   "* METADATA <mailbox> (<key> <value> <key> <value> ...)"
      let parts = [];
      for (let i = 0; i < paths.length; i++) {
        let p = paths[i];
        let v = values[p];
        if (v === null || v === undefined) continue;   // not set → skip
        let str = String(v);
        if (Buffer.byteLength(str, 'utf-8') > effMax) {
          if (Buffer.byteLength(str, 'utf-8') > longest) longest = Buffer.byteLength(str, 'utf-8');
          continue;
        }
        parts.push(p);
        parts.push(serializeValue(str));
      }

      if (parts.length > 0) {
        sendUntagged('METADATA ' + quoteMailbox(mailbox) + ' (' + parts.join(' ') + ')');
      }

      let code = null;
      if (longest > 0) code = 'METADATA LONGENTRIES ' + longest;
      sendTagged(tag, 'OK', 'GETMETADATA completed', code);
    });
  }


  // --- SETMETADATA ---
  //   SETMETADATA <mailbox> (<entry> <value> <entry> <value> ...)
  //
  // Value of NIL (as atom, unquoted) means delete the entry. Strings may be
  // quoted or literal. Paths must start with /private/ or /shared/.
  function handleSetMetadata(tag, args) {
    if (ev.listenerCount('setMetadata') === 0) {
      sendTagged(tag, 'NO', 'METADATA not implemented');
      return;
    }
    if (args.length < 2) {
      sendTagged(tag, 'BAD', 'SETMETADATA requires mailbox and entry list');
      return;
    }
    let mailbox = getStringValue(args[0]);
    let entryTok = args[1];
    if (!entryTok || entryTok.type !== TOK.LIST) {
      sendTagged(tag, 'BAD', 'SETMETADATA requires entry-value list');
      return;
    }

    let entries = {};
    let toks = entryTok.value;
    if (toks.length % 2 !== 0) {
      sendTagged(tag, 'BAD', 'SETMETADATA entries must be name/value pairs');
      return;
    }

    for (let i = 0; i + 1 < toks.length; i += 2) {
      let path = getStringValue(toks[i]);
      if (!validPath(path)) {
        sendTagged(tag, 'BAD', 'Invalid METADATA path: ' + path);
        return;
      }
      let valTok = toks[i + 1];
      let val;
      if (valTok.type === TOK.NIL) {
        val = null;   // delete
      } else if (valTok.type === TOK.LITERAL) {
        // Literal is a Uint8Array of bytes; convert to string
        val = Buffer.from(valTok.value).toString('utf-8');
      } else {
        val = String(valTok.value != null ? valTok.value : '');
      }

      // Enforce server-side MAXSIZE
      if (val !== null && Buffer.byteLength(val, 'utf-8') > maxSize) {
        sendTagged(tag, 'NO', 'Value exceeds METADATA MAXSIZE',
          'METADATA MAXSIZE ' + maxSize);
        return;
      }
      entries[path] = val;
    }

    ev.emit('setMetadata', mailbox, entries, function(err) {
      if (err) {
        // RFC 5464 defines specific codes:
        //   METADATA TOOMANY     — too many entries in mailbox
        //   METADATA NOPRIVATE   — server doesn't accept /private/
        // We default to a generic NO; the developer's error object can
        // override by setting err.code.
        sendTagged(tag, 'NO', err.message || 'SETMETADATA failed', err.code || null);
        return;
      }
      sendTagged(tag, 'OK', 'SETMETADATA completed');
    });
  }


  // Paths must be case-insensitive-ish, start with /private/ or /shared/,
  // and not contain '*', '%', or NULL. RFC 5464 §2.1.
  function validPath(path) {
    if (!path || typeof path !== 'string') return false;
    if (path.charAt(0) !== '/') return false;
    let lower = path.toLowerCase();
    if (!lower.startsWith('/private/') && !lower.startsWith('/shared/')) return false;
    if (/[*%\x00-\x1F]/.test(path)) return false;
    return true;
  }

  // Quote a mailbox name for the wire (minimal quoting — handles empty
  // and names with spaces/specials by wrapping in "..." with escapes).
  function quoteMailbox(name) {
    if (name === '') return '""';
    if (/^[A-Za-z0-9._\-\/]+$/.test(name)) return name;
    return '"' + String(name).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  }

  // Serialize a value. Short ASCII → quoted; long or containing CR/LF → literal.
  // RFC 5464 §4.3: values may be binary; we emit as literal when non-ASCII.
  function serializeValue(str) {
    // Use literal for values that contain CR/LF, NUL, or very long content —
    // otherwise quoted form is fine and cheaper to parse.
    let bytes = Buffer.from(str, 'utf-8');
    let needsLiteral = false;
    for (let i = 0; i < bytes.length; i++) {
      let b = bytes[i];
      if (b === 0 || b === 13 || b === 10) { needsLiteral = true; break; }
    }
    if (!needsLiteral && bytes.length > 1024) needsLiteral = true;
    if (needsLiteral) {
      return '{' + bytes.length + '}\r\n' + str;
    }
    // Quoted form
    let esc = str.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    return '"' + esc + '"';
  }

  // Expose handlers for the dispatcher
  s.handleGetMetadata = handleGetMetadata;
  s.handleSetMetadata = handleSetMetadata;
}
