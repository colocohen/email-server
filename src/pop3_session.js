// ============================================================================
//  pop3_session.js  —  POP3 protocol session (RFC 1939)
// ----------------------------------------------------------------------------
//  Server-side POP3 session. Maps RFC 1939 commands onto the same
//  `mailboxSession` event handlers that the IMAP implementation uses — so the
//  developer writes ONE set of storage callbacks (`openFolder`,
//  `resolveMessages`, `messageMeta`, `messageBody`, `setFlags`, `expunge`) and
//  it works for both protocols.
//
//  Unlike IMAP, POP3 exposes only the INBOX — there is no folder hierarchy,
//  no flags (beyond an implicit \Deleted that only exists in-session), and
//  sequence numbers are stable within a session.
//
//  State machine (RFC 1939 §3-6):
//
//     NEW         → send banner →        AUTHORIZATION
//     AUTHORIZATION → USER+PASS accepted →  TRANSACTION
//     TRANSACTION → QUIT →              UPDATE
//     UPDATE → deletions applied →      CLOSED
//
//  Command mapping:
//
//     USER / PASS      →  emit 'pop3Auth' (server layer maps to unified 'auth')
//     AUTH PLAIN       →  same, via SASL PLAIN (RFC 5034)
//     STAT             →  count + totalSize from openFolder result
//     LIST [msg]       →  per-message size from messageMeta
//     UIDL [msg]       →  per-message uid   from messageMeta
//     RETR msg         →  raw body from messageBody
//     TOP  msg n       →  raw body → extract header + first N body lines
//     DELE msg         →  mark as \Deleted (in-session only; applied at QUIT)
//     RSET             →  un-delete all marks
//     QUIT (TRANSACTION) → setFlags(\Deleted) + expunge for marked messages
//     CAPA             →  advertise capabilities
//     STLS             →  signal STARTTLS upgrade (server layer handles TLS)
//     NOOP             →  no-op
//
//  This file only implements server mode. A client mode may be added later
//  for pulling messages from external POP3 accounts.
// ============================================================================

import { EventEmitter } from 'node:events';
import { toU8, u8ToStr, indexOfCRLF } from './utils.js';


// ============================================================
//  Constants
// ============================================================

const DEFAULT_HOSTNAME    = 'localhost';
const DEFAULT_MAX_COMMAND = 8 * 1024;   // POP3 lines are short; 8K is generous

// Session states (RFC 1939 §3-6)
const STATE = {
  NEW:           'new',
  GREETING:      'greeting',         // client-side: awaiting banner
  AUTHORIZATION: 'authorization',    // pre-login
  TRANSACTION:   'transaction',      // logged in
  UPDATE:        'update',           // during QUIT, applying deletions
  CLOSED:        'closed'
};

// Default SASL mechanisms advertised. PLAIN for basic auth, XOAUTH2 for
// bearer-token auth (Gmail, Outlook, and other modern providers). The
// developer validates XOAUTH2 tokens themselves by inspecting authMethod on
// the auth event and calling the provider's introspection endpoint.
const DEFAULT_AUTH_METHODS = ['PLAIN', 'XOAUTH2'];


// ============================================================
//  Byte-stuffing helper for multi-line responses (RFC 1939 §3)
// ============================================================
//
// Any body line beginning with `.` must have another `.` prepended, and the
// stream is terminated by `\r\n.\r\n`. This function takes raw message bytes
// and returns a Buffer ready to send (without the leading "+OK ..." and
// without the trailing terminator — caller adds those).

function dotStuff(raw) {
  // Work byte-wise to avoid UTF-8 splitting of binary content.
  let out = [];
  let len = raw.length;
  let lineStart = true;
  for (let i = 0; i < len; i++) {
    let b = raw[i];
    if (lineStart && b === 0x2E /* '.' */) {
      out.push(0x2E);  // prepend dot
    }
    out.push(b);
    lineStart = (b === 0x0A /* '\n' */);
  }
  // Ensure trailing CRLF before the terminator dot
  if (out.length >= 2) {
    let n = out.length;
    if (!(out[n - 2] === 0x0D && out[n - 1] === 0x0A)) {
      out.push(0x0D); out.push(0x0A);
    }
  } else {
    out.push(0x0D); out.push(0x0A);
  }
  return new Uint8Array(out);
}

// Extract the headers + first `bodyLines` body lines from raw RFC 5322 bytes.
// The header block ends at the first CRLF CRLF (or LF LF). Beyond that, count
// CRLF terminators. Returns a Uint8Array.
function extractTopBytes(raw, bodyLines) {
  let n = raw.length;
  // Locate end of header block
  let headerEnd = -1;
  for (let i = 0; i < n - 3; i++) {
    if (raw[i] === 0x0D && raw[i+1] === 0x0A && raw[i+2] === 0x0D && raw[i+3] === 0x0A) {
      headerEnd = i + 4; break;
    }
    if (raw[i] === 0x0A && raw[i+1] === 0x0A) {
      headerEnd = i + 2; break;
    }
  }
  if (headerEnd < 0) return raw.slice(0, n);  // No body separator — return all

  if (bodyLines <= 0) return raw.slice(0, headerEnd);

  // Count `bodyLines` CRLF-terminated lines after the header
  let linesSeen = 0;
  let pos = headerEnd;
  while (pos < n && linesSeen < bodyLines) {
    if (raw[pos] === 0x0A) linesSeen++;
    pos++;
  }
  return raw.slice(0, pos);
}


// ============================================================
//  POP3Session factory
// ============================================================

function POP3Session(options) {
  if (!(this instanceof POP3Session)) return new POP3Session(options);
  options = options || {};

  const ev = new EventEmitter();
  ev.setMaxListeners(50);

  let context = {
    state: STATE.NEW,
    isServer: options.isServer !== false,

    hostname:       options.hostname       || DEFAULT_HOSTNAME,
    maxCommandSize: options.maxCommandSize || DEFAULT_MAX_COMMAND,
    remoteAddress:  options.remoteAddress  || null,
    isTLS:          !!options.isTLS,
    tlsOptions:     options.tlsOptions     || null,   // truthy → STLS advertised

    // Input buffer
    inputBuf: new Uint8Array(0),

    // Auth flow
    pendingUser:    null,   // username from USER, awaiting PASS
    authInProgress: null,   // { mech, step } during SASL

    // Transaction state
    authenticated:  false,
    username:       null,
    folderInfo:     null,   // whatever openFolder returned (total, totalSize, uidValidity)
    messages:       null,   // [{seq, uid, size, deleted}]  — loaded at auth

    // --- Client-only state ---
    // When isServer === false, the session sends commands and parses replies
    // into developer callbacks. Only one command may be in-flight at a time
    // (POP3 is strictly serial) — queued commands wait in commandQueue.
    pendingCommand: null,   // { type: 'single'|'multi', cb, multiAccum? }
    commandQueue:   []      // [{ line, pending }]
  };

  // ============================================================
  //  Input buffer
  // ============================================================

  function appendInput(chunk) {
    let buf = context.inputBuf;
    let merged = new Uint8Array(buf.length + chunk.length);
    merged.set(buf, 0);
    merged.set(chunk, buf.length);
    context.inputBuf = merged;
  }

  // ============================================================
  //  Send helpers
  // ============================================================

  function send(data) {
    if (typeof data === 'string') data = toU8(data);
    ev.emit('send', data);
  }
  function sendOk(text)   { send('+OK '  + (text || '') + '\r\n'); }
  function sendErr(text)  { send('-ERR ' + (text || '') + '\r\n'); }
  function sendLine(text) { send(text + '\r\n'); }
  // Multi-line terminator: single dot on its own line.
  function sendEnd()      { send('.\r\n'); }


  // ============================================================
  //  SERVER MODE — feed loop
  // ============================================================

  function feedServer() {
    while (context.state !== STATE.CLOSED) {
      // Size guard — protect against slow-loris / garbage
      if (context.inputBuf.length > context.maxCommandSize) {
        sendErr('Line too long');
        doClose();
        return;
      }

      let idx = indexOfCRLF(context.inputBuf);
      if (idx < 0) return;
      let lineBytes = context.inputBuf.subarray(0, idx);
      let line = u8ToStr(lineBytes);
      context.inputBuf = context.inputBuf.subarray(idx + 2);

      // SASL continuation — the line is base64 payload, not a command
      if (context.authInProgress) {
        handleAuthContinuation(line);
        continue;
      }

      dispatchCommand(line);
    }
  }


  // ============================================================
  //  Command dispatch
  // ============================================================

  function dispatchCommand(line) {
    let trimmed = line.trim();
    if (trimmed.length === 0) { sendErr('Empty command'); return; }

    // Split on first whitespace — everything after is args
    let spaceIdx = trimmed.indexOf(' ');
    let cmd  = (spaceIdx < 0 ? trimmed : trimmed.substring(0, spaceIdx)).toUpperCase();
    let argStr = spaceIdx < 0 ? '' : trimmed.substring(spaceIdx + 1);
    let args = argStr.length > 0 ? argStr.split(/\s+/) : [];

    switch (cmd) {
      case 'CAPA': return handleCapa();
      case 'NOOP': return handleNoop();
      case 'QUIT': return handleQuit();

      // AUTHORIZATION state
      case 'USER': return handleUser(args);
      case 'PASS': return handlePass(args);
      case 'AUTH': return handleAuth(args);
      case 'STLS': return handleStls();
      case 'APOP': sendErr('APOP not supported'); return;

      // TRANSACTION state
      case 'STAT': return handleStat();
      case 'LIST': return handleList(args);
      case 'UIDL': return handleUidl(args);
      case 'RETR': return handleRetr(args);
      case 'TOP':  return handleTop(args);
      case 'DELE': return handleDele(args);
      case 'RSET': return handleRset();

      default:
        sendErr('Unknown command: ' + cmd);
    }
  }


  // ============================================================
  //  AUTHORIZATION state handlers
  // ============================================================

  function handleCapa() {
    // Per RFC 2449, CAPA is multi-line and always allowed.
    sendOk('Capability list follows');
    sendLine('USER');
    sendLine('UIDL');
    sendLine('TOP');
    sendLine('RESP-CODES');
    sendLine('PIPELINING');
    // SASL mechanisms (RFC 5034)
    let mechs = DEFAULT_AUTH_METHODS.slice();
    if (options.extraAuthMechs) {
      for (let i = 0; i < options.extraAuthMechs.length; i++) {
        if (mechs.indexOf(options.extraAuthMechs[i]) < 0) mechs.push(options.extraAuthMechs[i]);
      }
    }
    sendLine('SASL ' + mechs.join(' '));
    // STLS (RFC 2595) — advertise only if TLS is available and we're not yet secure
    if (context.tlsOptions && !context.isTLS) sendLine('STLS');
    sendLine('IMPLEMENTATION email-server');
    sendEnd();
  }

  function handleNoop() {
    sendOk('');
  }

  function handleStls() {
    if (context.state !== STATE.AUTHORIZATION) {
      sendErr('STLS only in authorization'); return;
    }
    if (!context.tlsOptions) { sendErr('STLS not available'); return; }
    if (context.isTLS)       { sendErr('Already under TLS'); return; }
    sendOk('Begin TLS negotiation');
    ev.emit('starttls', { tlsOptions: context.tlsOptions });
    // The server layer performs the socket upgrade and then calls
    // session.onTlsUpgraded() which resets some state.
  }

  // USER <username>
  function handleUser(args) {
    if (context.state !== STATE.AUTHORIZATION) { sendErr('Already logged in'); return; }
    if (args.length < 1) { sendErr('USER requires username'); return; }
    context.pendingUser = args.join(' ');  // username may contain spaces (rare but valid)
    sendOk('User accepted');
  }

  // PASS <password>
  function handlePass(args) {
    if (context.state !== STATE.AUTHORIZATION) { sendErr('Already logged in'); return; }
    if (!context.pendingUser) { sendErr('USER first'); return; }
    if (args.length < 1)      { sendErr('PASS requires password'); return; }

    let username = context.pendingUser;
    let password = args.join(' ');
    context.pendingUser = null;

    emitAuth(username, password, 'plain');
  }

  // AUTH <mechanism> [<initial-response>]
  function handleAuth(args) {
    if (context.state !== STATE.AUTHORIZATION) { sendErr('Already logged in'); return; }
    if (args.length < 1) { sendErr('AUTH requires mechanism'); return; }
    let mech = args[0].toUpperCase();
    let initial = args.length > 1 ? args[1] : null;

    if (mech === 'PLAIN') {
      if (initial) {
        processSaslPlain(initial);
      } else {
        context.authInProgress = { mech: 'PLAIN' };
        send('+ \r\n');
      }
    } else if (mech === 'XOAUTH2') {
      // RFC 7628 / Google XOAUTH2. Payload is:
      //   base64("user=" <email> \x01 "auth=Bearer " <token> \x01 \x01)
      // May be provided inline as the second arg, or via continuation.
      if (initial) {
        processSaslXoauth2(initial);
      } else {
        context.authInProgress = { mech: 'XOAUTH2' };
        send('+ \r\n');
      }
    } else {
      sendErr('Unsupported AUTH mechanism: ' + mech);
    }
  }

  function handleAuthContinuation(line) {
    let auth = context.authInProgress;
    if (!auth) return;

    // Cancellation (RFC 5034) — client sends "*"
    if (line === '*') {
      context.authInProgress = null;
      sendErr('AUTH cancelled');
      return;
    }

    if (auth.mech === 'PLAIN') {
      context.authInProgress = null;
      processSaslPlain(line);
    } else if (auth.mech === 'XOAUTH2') {
      context.authInProgress = null;
      processSaslXoauth2(line);
    }
  }

  // Decode a SASL PLAIN payload and emit auth.
  // Format: base64( [authzid] \0 username \0 password )
  function processSaslPlain(b64) {
    let decoded;
    try {
      decoded = Buffer.from(b64, 'base64').toString('utf-8');
    } catch (e) {
      sendErr('Invalid base64'); return;
    }
    let parts = decoded.split('\0');
    if (parts.length !== 3) { sendErr('Malformed PLAIN'); return; }
    let username = parts[1] || '';
    let password = parts[2] || '';
    if (!username) { sendErr('Empty username'); return; }
    emitAuth(username, password, 'plain');
  }

  // Decode a SASL XOAUTH2 payload and emit auth.
  // Format (base64-decoded):
  //   "user=" <email> \x01 "auth=Bearer " <access-token> \x01 \x01
  //
  // On rejection, RFC 7628 §3.2.3 expects the server to send a base64
  // error object in a continuation, wait for an empty client response,
  // and THEN send the final -ERR. For simplicity we just -ERR immediately;
  // real clients retry with a refreshed token on any failure anyway.
  function processSaslXoauth2(b64) {
    let decoded;
    try {
      decoded = Buffer.from(b64, 'base64').toString('utf-8');
    } catch (e) {
      sendErr('Invalid base64'); return;
    }
    // Parse: split on \x01 separators, look for user= and auth=Bearer
    let username = null;
    let token = null;
    let parts = decoded.split('\x01');
    for (let i = 0; i < parts.length; i++) {
      let p = parts[i];
      if (p.indexOf('user=') === 0) {
        username = p.substring(5);
      } else if (p.indexOf('auth=Bearer ') === 0) {
        token = p.substring(12);
      }
    }
    if (!username || !token) { sendErr('Malformed XOAUTH2'); return; }

    // Pass the token as the "password" — the developer inspects authMethod
    // and validates the bearer token against their IdP (Google introspection,
    // Microsoft Graph, etc.). The library does not validate OAuth2 tokens.
    emitAuth(username, token, 'xoauth2');
  }

  // Unified auth path — emit 'pop3Auth' with accept/reject handles so the
  // server layer can map it onto the same auth event as IMAP/SMTP.
  function emitAuth(username, password, authMethod) {
    let decided = false;

    let authCtx = {
      protocol:      'pop3',
      username:      username,
      password:      password,
      authMethod:    authMethod,
      remoteAddress: context.remoteAddress,
      isTLS:         context.isTLS,

      accept: function() {
        if (decided) return;
        decided = true;
        context.authenticated = true;
        context.username = username;
        // Load the inbox — openFolder → resolveMessages → messageMeta
        loadInbox(function(err) {
          if (err) {
            sendErr('Mailbox unavailable');
            doClose();
            return;
          }
          context.state = STATE.TRANSACTION;
          sendOk(username + ' authenticated (' + (context.messages ? context.messages.length : 0) + ' messages)');
        });
      },
      reject: function(msg) {
        if (decided) return;
        decided = true;
        sendErr(msg || 'Authentication failed');
      },

      on:   function(name, fn) { ev.on(name, fn);   return authCtx; },
      off:  function(name, fn) { ev.off(name, fn);  return authCtx; },
      once: function(name, fn) { ev.once(name, fn); return authCtx; }
    };

    ev.emit('pop3Auth', authCtx);
  }


  // ============================================================
  //  Inbox loading (called once right after authentication)
  // ============================================================

  function loadInbox(cb) {
    // Step 1: openFolder('INBOX') → { total, totalSize?, uidValidity?, ... }
    if (ev.listenerCount('openFolder') === 0) {
      cb(new Error('No openFolder handler registered'));
      return;
    }
    ev.emit('openFolder', 'INBOX', function(err, info) {
      if (err) { cb(err); return; }
      info = info || {};
      context.folderInfo = info;

      let total = typeof info.total === 'number' ? info.total : 0;
      if (total === 0) {
        context.messages = [];
        cb(null);
        return;
      }

      // Step 2: resolveMessages with range 1..* → [{seq, uid}, ...]
      if (ev.listenerCount('resolveMessages') === 0) {
        cb(new Error('No resolveMessages handler registered'));
        return;
      }
      // Flat half-open range format used elsewhere in this library
      let query = { ranges: [1, Infinity], isUid: false, total: total };
      ev.emit('resolveMessages', 'INBOX', query, function(err, pairs) {
        if (err) { cb(err); return; }
        pairs = pairs || [];
        // Sort by seq to match POP3 ordering semantics
        pairs.sort(function(a, b) { return a.seq - b.seq; });

        if (pairs.length === 0) {
          context.messages = [];
          cb(null);
          return;
        }

        // Step 3: messageMeta → sizes
        if (ev.listenerCount('messageMeta') === 0) {
          // Sizes unknown — best-effort: use 0 so LIST still works
          context.messages = pairs.map(function(p) {
            return { seq: p.seq, uid: p.uid, size: 0, deleted: false };
          });
          cb(null);
          return;
        }
        let uids = pairs.map(function(p) { return p.uid; });
        ev.emit('messageMeta', 'INBOX', uids, function(err, metas) {
          if (err) { cb(err); return; }
          metas = metas || [];
          let metaByUid = {};
          for (let i = 0; i < metas.length; i++) {
            if (metas[i] && metas[i].uid != null) metaByUid[metas[i].uid] = metas[i];
          }
          context.messages = pairs.map(function(p) {
            let m = metaByUid[p.uid] || {};
            return {
              seq:     p.seq,
              uid:     p.uid,
              size:    typeof m.size === 'number' ? m.size : 0,
              deleted: false
            };
          });
          cb(null);
        });
      });
    });
  }


  // ============================================================
  //  TRANSACTION state handlers
  // ============================================================

  function requireTransaction() {
    if (context.state !== STATE.TRANSACTION) {
      sendErr('Not in transaction state');
      return false;
    }
    return true;
  }

  // Find a message by its 1-based sequence number, skipping deleted ones?
  // Per RFC 1939 §8, DELE'd messages remain in the sequence space until QUIT,
  // but RETR/DELE/etc on a deleted message return -ERR.
  function getMessage(n) {
    if (!context.messages) return null;
    for (let i = 0; i < context.messages.length; i++) {
      if (context.messages[i].seq === n) return context.messages[i];
    }
    return null;
  }

  // STAT — +OK <count> <total-size>  (non-deleted only)
  function handleStat() {
    if (!requireTransaction()) return;
    let count = 0, size = 0;
    for (let i = 0; i < context.messages.length; i++) {
      if (!context.messages[i].deleted) {
        count++;
        size += context.messages[i].size || 0;
      }
    }
    sendOk(count + ' ' + size);
  }

  // LIST               — multi-line listing of all non-deleted
  // LIST <msg>         — single line for one message
  function handleList(args) {
    if (!requireTransaction()) return;
    if (args.length === 0) {
      sendOk('scan listing follows');
      for (let i = 0; i < context.messages.length; i++) {
        let m = context.messages[i];
        if (!m.deleted) sendLine(m.seq + ' ' + (m.size || 0));
      }
      sendEnd();
      return;
    }
    let n = parseInt(args[0], 10);
    if (isNaN(n)) { sendErr('Invalid message number'); return; }
    let m = getMessage(n);
    if (!m || m.deleted) { sendErr('No such message'); return; }
    sendOk(m.seq + ' ' + (m.size || 0));
  }

  // UIDL [<msg>] — same as LIST but using uid (stable across sessions)
  function handleUidl(args) {
    if (!requireTransaction()) return;
    if (args.length === 0) {
      sendOk('unique-id listing follows');
      for (let i = 0; i < context.messages.length; i++) {
        let m = context.messages[i];
        if (!m.deleted) sendLine(m.seq + ' ' + m.uid);
      }
      sendEnd();
      return;
    }
    let n = parseInt(args[0], 10);
    if (isNaN(n)) { sendErr('Invalid message number'); return; }
    let m = getMessage(n);
    if (!m || m.deleted) { sendErr('No such message'); return; }
    sendOk(m.seq + ' ' + m.uid);
  }

  // RETR <msg> — full raw message, dot-stuffed
  function handleRetr(args) {
    if (!requireTransaction()) return;
    if (args.length < 1)    { sendErr('RETR requires message number'); return; }
    let n = parseInt(args[0], 10);
    if (isNaN(n))           { sendErr('Invalid message number'); return; }
    let m = getMessage(n);
    if (!m || m.deleted)    { sendErr('No such message'); return; }

    if (ev.listenerCount('messageBody') === 0) {
      sendErr('Message body not available'); return;
    }

    // Responder pattern — matches the IMAP messageBody event.
    let decided = false;
    let responder = {
      respond: function(raw) {
        if (decided) return;
        decided = true;
        if (!raw || raw.length === 0) { sendErr('Empty body'); return; }
        let bytes = raw instanceof Uint8Array ? raw : toU8(raw);
        sendOk('message follows');
        send(dotStuff(bytes));
        sendEnd();
      },
      error: function(msg) {
        if (decided) return;
        decided = true;
        sendErr(msg || 'Retrieve failed');
      }
    };
    ev.emit('messageBody', 'INBOX', m.uid, responder);
  }

  // TOP <msg> <n> — header + first <n> body lines, dot-stuffed
  function handleTop(args) {
    if (!requireTransaction()) return;
    if (args.length < 2)  { sendErr('TOP requires message number and line count'); return; }
    let n = parseInt(args[0], 10);
    let lines = parseInt(args[1], 10);
    if (isNaN(n) || isNaN(lines) || lines < 0) { sendErr('Invalid argument'); return; }
    let m = getMessage(n);
    if (!m || m.deleted) { sendErr('No such message'); return; }

    if (ev.listenerCount('messageBody') === 0) {
      sendErr('Message body not available'); return;
    }

    let decided = false;
    let responder = {
      respond: function(raw) {
        if (decided) return;
        decided = true;
        if (!raw || raw.length === 0) { sendErr('Empty body'); return; }
        let bytes = raw instanceof Uint8Array ? raw : toU8(raw);
        let sliced = extractTopBytes(bytes, lines);
        sendOk('top of message follows');
        send(dotStuff(sliced));
        sendEnd();
      },
      error: function(msg) {
        if (decided) return;
        decided = true;
        sendErr(msg || 'Retrieve failed');
      }
    };
    ev.emit('messageBody', 'INBOX', m.uid, responder);
  }

  // DELE <msg> — mark for deletion at QUIT
  function handleDele(args) {
    if (!requireTransaction()) return;
    if (args.length < 1) { sendErr('DELE requires message number'); return; }
    let n = parseInt(args[0], 10);
    if (isNaN(n))        { sendErr('Invalid message number'); return; }
    let m = getMessage(n);
    if (!m || m.deleted) { sendErr('No such message'); return; }
    m.deleted = true;
    sendOk('message ' + n + ' marked for deletion');
  }

  // RSET — unmark all deletions
  function handleRset() {
    if (!requireTransaction()) return;
    for (let i = 0; i < context.messages.length; i++) {
      context.messages[i].deleted = false;
    }
    sendOk('reset');
  }


  // ============================================================
  //  QUIT — enters UPDATE state and applies deletions
  // ============================================================

  function handleQuit() {
    // If already in AUTHORIZATION, just close cleanly (RFC 1939 §3)
    if (context.state === STATE.AUTHORIZATION) {
      sendOk(context.hostname + ' POP3 server signing off');
      doClose();
      return;
    }
    if (context.state !== STATE.TRANSACTION) {
      sendErr('QUIT in invalid state');
      doClose();
      return;
    }

    // UPDATE state: apply deletions
    context.state = STATE.UPDATE;
    let toDelete = [];
    for (let i = 0; i < context.messages.length; i++) {
      if (context.messages[i].deleted) toDelete.push(context.messages[i].uid);
    }

    if (toDelete.length === 0) {
      sendOk(context.hostname + ' POP3 server signing off (no changes)');
      doClose();
      return;
    }

    // Step 1: setFlags(+\Deleted) for the marked messages.
    // Step 2: expunge.
    // Both events are the same ones used by IMAP.
    applyDeletions(toDelete, function() {
      sendOk(context.hostname + ' POP3 server signing off (' + toDelete.length + ' deleted)');
      doClose();
    });
  }

  function applyDeletions(uids, done) {
    let waitSet  = ev.listenerCount('setFlags') > 0;
    let waitExp  = ev.listenerCount('expunge')  > 0;

    function doExpunge() {
      if (!waitExp) { done(); return; }
      // Match the IMAP expunge event shape: (folder, opts, cb)
      let query = { ranges: [], uids: uids.slice() };
      ev.emit('expunge', 'INBOX', { uids: uids.slice() }, function(err) {
        // We don't surface errors to the client at this point (QUIT has succeeded
        // up to this call). Emit an internal 'error' for developer logging.
        if (err) ev.emit('error', err);
        done();
      });
    }

    if (!waitSet) { doExpunge(); return; }

    // setFlags signature: (folder, { ranges, uids, flags, mode }, cb)
    let query = {
      isUid: true,
      uids:  uids.slice(),
      flags: ['Deleted'],
      mode:  'add',
      silent: true
    };
    ev.emit('setFlags', 'INBOX', query, function(err) {
      if (err) ev.emit('error', err);
      doExpunge();
    });
  }


  // ============================================================
  //  CLIENT MODE — response parser + command pipeline
  // ============================================================
  //
  // POP3 is strictly serial: exactly one outstanding command at a time. The
  // client sends a line, the server responds with either:
  //   • a single line starting "+OK ..." or "-ERR ..." (simple commands), or
  //   • "+OK ..."  followed by zero or more body lines, terminated by a lone
  //     "." line  (multi-line commands: CAPA, LIST-all, UIDL-all, RETR, TOP).
  //
  // The pending-command object describes what shape of reply to expect.
  //
  // `commandQueue` holds commands issued while another is in flight; they are
  // fired one at a time as the previous completes.

  function feedClient() {
    while (context.state !== STATE.CLOSED) {
      if (context.inputBuf.length > context.maxCommandSize && context.pendingCommand &&
          context.pendingCommand.type !== 'multi') {
        // Single-line responses should be small; something is wrong.
        // For multi-line (RETR/TOP) we allow large bodies.
      }

      let idx = indexOfCRLF(context.inputBuf, 0);
      if (idx < 0) return;
      let lineBytes = context.inputBuf.subarray(0, idx);
      let line = u8ToStr(lineBytes);
      context.inputBuf = context.inputBuf.subarray(idx + 2);

      // --- Banner ---
      if (context.state === STATE.GREETING) {
        context.state = STATE.AUTHORIZATION;
        ev.emit('banner', line);
        // Developer may now issue commands; nothing else to do here.
        continue;
      }

      let pending = context.pendingCommand;
      if (!pending) {
        // Unexpected unsolicited line — ignore.
        continue;
      }

      // --- Multi-line response accumulation ---
      if (pending.type === 'multi' && pending.multiAccum) {
        if (line === '.') {
          // End of multi-line body
          let accum = pending.multiAccum;
          let status = pending.multiStatus;
          context.pendingCommand = null;
          pumpQueue();
          pending.cb(null, { status: status, lines: accum });
          continue;
        }
        // Un-dot-stuff per RFC 1939 §3
        if (line.charAt(0) === '.') line = line.slice(1);
        pending.multiAccum.push(line);
        continue;
      }

      // --- Status line (first line of any response) ---
      let isOk = line.indexOf('+OK') === 0;
      let isErr = line.indexOf('-ERR') === 0;

      if (!isOk && !isErr) {
        // Malformed — treat as error so we don't hang
        context.pendingCommand = null;
        pumpQueue();
        pending.cb(new Error('Unexpected response: ' + line));
        continue;
      }

      if (isErr) {
        let msg = line.substring(4).trim() || 'POP3 error';
        context.pendingCommand = null;
        pumpQueue();
        pending.cb(new Error(msg));
        continue;
      }

      // isOk — either the whole response, or the start of a multi-line body.
      if (pending.type === 'multi') {
        pending.multiAccum = [];
        pending.multiStatus = line;
        continue;
      }

      // Single-line success
      let statusText = line.substring(3).trim();   // strip "+OK"
      context.pendingCommand = null;
      pumpQueue();
      pending.cb(null, statusText);
    }
  }

  function issueCommand(line, type, cb) {
    if (context.isServer) {
      cb(new Error('issueCommand is for client mode only'));
      return;
    }
    if (context.state === STATE.CLOSED) {
      cb(new Error('Session closed'));
      return;
    }
    let entry = { line: line, pending: { type: type, cb: cb } };
    if (context.pendingCommand) {
      context.commandQueue.push(entry);
      return;
    }
    context.pendingCommand = entry.pending;
    send(line + '\r\n');
  }

  function pumpQueue() {
    if (context.pendingCommand) return;
    let next = context.commandQueue.shift();
    if (!next) return;
    context.pendingCommand = next.pending;
    send(next.line + '\r\n');
  }

  // --- Client API methods ---

  // USER / PASS — classic plaintext auth.
  function clientLogin(username, password, cb) {
    issueCommand('USER ' + username, 'single', function(err) {
      if (err) { cb(err); return; }
      issueCommand('PASS ' + password, 'single', function(err, status) {
        if (err) { cb(err); return; }
        context.authenticated = true;
        context.username = username;
        cb(null, status);
      });
    });
  }

  // AUTH XOAUTH2 — bearer-token auth for Gmail / Outlook / etc.
  //   base64( "user=" email \x01 "auth=Bearer " token \x01 \x01 )
  function clientXoauth2(username, token, cb) {
    let payload = Buffer.from(
      'user=' + username + '\x01auth=Bearer ' + token + '\x01\x01',
      'utf-8'
    ).toString('base64');
    issueCommand('AUTH XOAUTH2 ' + payload, 'single', function(err, status) {
      if (err) { cb(err); return; }
      context.authenticated = true;
      context.username = username;
      cb(null, status);
    });
  }

  // CAPA — multi-line list of capabilities.
  function clientCapa(cb) {
    issueCommand('CAPA', 'multi', function(err, result) {
      if (err) { cb(err); return; }
      cb(null, result.lines);
    });
  }

  // STAT — returns { count, totalSize }.
  function clientStat(cb) {
    issueCommand('STAT', 'single', function(err, status) {
      if (err) { cb(err); return; }
      let parts = status.split(/\s+/);
      cb(null, {
        count:     parseInt(parts[0], 10) || 0,
        totalSize: parseInt(parts[1], 10) || 0
      });
    });
  }

  // LIST (no arg) — multi-line scan listing. Returns [{ seq, size }].
  // LIST n          — single-line. Returns { seq, size }.
  function clientList(seq, cb) {
    if (typeof seq === 'function') { cb = seq; seq = null; }
    if (seq == null) {
      issueCommand('LIST', 'multi', function(err, result) {
        if (err) { cb(err); return; }
        let out = [];
        for (let i = 0; i < result.lines.length; i++) {
          let p = result.lines[i].split(/\s+/);
          out.push({ seq: parseInt(p[0], 10), size: parseInt(p[1], 10) });
        }
        cb(null, out);
      });
    } else {
      issueCommand('LIST ' + seq, 'single', function(err, status) {
        if (err) { cb(err); return; }
        let p = status.split(/\s+/);
        cb(null, { seq: parseInt(p[0], 10), size: parseInt(p[1], 10) });
      });
    }
  }

  // UIDL (no arg) — multi-line. Returns [{ seq, uid }].
  // UIDL n          — single-line. Returns { seq, uid }.
  function clientUidl(seq, cb) {
    if (typeof seq === 'function') { cb = seq; seq = null; }
    if (seq == null) {
      issueCommand('UIDL', 'multi', function(err, result) {
        if (err) { cb(err); return; }
        let out = [];
        for (let i = 0; i < result.lines.length; i++) {
          let p = result.lines[i].split(/\s+/);
          out.push({ seq: parseInt(p[0], 10), uid: p[1] });
        }
        cb(null, out);
      });
    } else {
      issueCommand('UIDL ' + seq, 'single', function(err, status) {
        if (err) { cb(err); return; }
        let p = status.split(/\s+/);
        cb(null, { seq: parseInt(p[0], 10), uid: p[1] });
      });
    }
  }

  // RETR n — fetch full message bytes. Returns the raw body (Uint8Array)
  // with dot-stuffing removed and lines joined by CRLF.
  function clientRetr(seq, cb) {
    issueCommand('RETR ' + seq, 'multi', function(err, result) {
      if (err) { cb(err); return; }
      // Rejoin lines with CRLF; also terminate with CRLF for a clean RFC 5322 blob.
      let joined = result.lines.join('\r\n');
      if (joined.length > 0) joined += '\r\n';
      cb(null, Buffer.from(joined, 'utf-8'));
    });
  }

  // TOP n lines — fetch headers + first N body lines.
  function clientTop(seq, lines, cb) {
    issueCommand('TOP ' + seq + ' ' + lines, 'multi', function(err, result) {
      if (err) { cb(err); return; }
      let joined = result.lines.join('\r\n');
      if (joined.length > 0) joined += '\r\n';
      cb(null, Buffer.from(joined, 'utf-8'));
    });
  }

  function clientDele(seq, cb) { issueCommand('DELE ' + seq, 'single', cb); }
  function clientRset(cb)      { issueCommand('RSET',       'single', cb); }
  function clientNoop(cb)      { issueCommand('NOOP',       'single', cb); }

  function clientQuit(cb) {
    issueCommand('QUIT', 'single', function(err, status) {
      // Server closes the socket after QUIT; mark state accordingly.
      if (!err) context.state = STATE.CLOSED;
      cb(err, status);
    });
  }


  // ============================================================
  //  Greet (start the session)
  // ============================================================

  function greet() {
    if (context.state !== STATE.NEW) return;
    if (context.isServer) {
      context.state = STATE.AUTHORIZATION;
      sendOk(context.hostname + ' POP3 ready');
    } else {
      // Client mode — wait for server banner
      context.state = STATE.GREETING;
    }
  }


  // ============================================================
  //  TLS upgrade (called by server layer after STARTTLS)
  // ============================================================

  function onTlsUpgraded() {
    context.isTLS = true;
    // Per RFC 2595 §4, all state is reset after STLS (including any
    // authenticated identity — but in POP3 we only enter STLS before auth).
    context.pendingUser = null;
    context.authInProgress = null;
    context.inputBuf = new Uint8Array(0);
  }


  // ============================================================
  //  Close
  // ============================================================

  function doClose() {
    if (context.state === STATE.CLOSED) return;
    context.state = STATE.CLOSED;
    context.inputBuf = new Uint8Array(0);
    context.pendingUser = null;
    context.authInProgress = null;
    context.messages = null;
    ev.emit('close');
    ev.removeAllListeners();
  }


  // ============================================================
  //  Public feed — single entry point for incoming bytes
  // ============================================================

  function feed(chunk) {
    if (context.state === STATE.CLOSED) return;
    appendInput(toU8(chunk));
    if (context.isServer) feedServer();
    else                  feedClient();
  }


  // ============================================================
  //  API
  // ============================================================

  let api = {
    context: context,
    on:    function(name, fn) { ev.on(name, fn); },
    off:   function(name, fn) { ev.off(name, fn); },
    feed:  feed,
    greet: greet,
    close: doClose,
    onTlsUpgraded: onTlsUpgraded,

    // Client commands (no-ops in server mode)
    login:     clientLogin,
    xoauth2:   clientXoauth2,
    capa:      clientCapa,
    stat:      clientStat,
    list:      clientList,
    uidl:      clientUidl,
    retr:      clientRetr,
    top:       clientTop,
    dele:      clientDele,
    rset:      clientRset,
    noop:      clientNoop,
    quit:      clientQuit,

    get state()          { return context.state; },
    get isServer()       { return context.isServer; },
    get isTLS()          { return context.isTLS; },
    get authenticated()  { return context.authenticated; },
    get username()       { return context.username; },
    get remoteAddress()  { return context.remoteAddress; }
  };

  for (let k in api) {
    if (Object.prototype.hasOwnProperty.call(api, k)) {
      let desc = Object.getOwnPropertyDescriptor(api, k);
      if (desc && (desc.get || desc.set)) Object.defineProperty(this, k, desc);
      else                                this[k] = api[k];
    }
  }
  return this;
}


export default POP3Session;
export { POP3Session, STATE };
