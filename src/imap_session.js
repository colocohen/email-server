
import { EventEmitter } from 'node:events';

import {
  parseCommand,
  parseResponse,
  buildTagged,
  buildUntagged,
  buildContinuation,
  buildCommand,
  buildCommandRaw,
  makeTagGenerator,
  serializeValue,
  PARSE,
  RESP,
  TOK
} from './imap_wire.js';

import {
  toU8,
  u8ToStr,
  indexOfCRLF
} from './utils.js';

import {
  parseMessageTree,
  parseAddressList
} from './message.js';

import flatRanges from 'flat-ranges';

import { registerMessageHandlers } from './imap_messages.js';
import { registerSearchHandlers } from './imap_search.js';
import { registerFolderHandlers } from './imap_folders.js';
import { registerMetadataHandlers } from './imap_metadata.js';

// Pure helpers — extracted to their own module for clarity and direct re-use.
// These are also re-exported from this file so existing external imports keep working.
import {
  // Public constants
  SPECIAL_USE,
  FLAGS,
  DEFAULT_FLAGS,

  // Flag / special-use normalization
  normalizeSpecialUse,
  normalizeFlag,
  serializeFlag,
  serializeFlagList,

  // LIST / hierarchy
  makeWildcardMatcher,
  hasChildren,

  // Sequence sets / UID compression
  parseSequenceSet,
  rangesContain,
  compressUids,
  formatRanges,
  buildCopyUidCode,

  // INTERNALDATE
  formatInternalDate,
  parseInternalDate,

  // BODY[...] section
  parseBodySection,
  buildBodyResponseName,

  // SEARCH
  parseSearchDate,
  formatSearchDate,
  parseSearchRanges,
  parseSearchCriteria,

  // Token helper
  tokenToString,

  // ENVELOPE / BODYSTRUCTURE builders
  buildEnvelope,
  buildBodyStructure,
  buildEnvelopeFromJson,
  buildBodyStructureFromJson,

  // Raw message → JSON extractors
  extractEnvelope,
  extractBodyStructure,
  extractMessageMetadata
} from './imap_helpers.js';


// ============================================================
//  Session-internal constants
// ============================================================

const DEFAULT_HOSTNAME        = 'localhost';
const DEFAULT_MAX_COMMAND     = 100 * 1024 * 1024;  // 100 MB (mostly for APPEND)
const DEFAULT_AUTH_TIMEOUT    = 30000;
const DEFAULT_DELIMITER       = '/';                 // hierarchy separator

// IMAP connection states (RFC 3501 §3)
const STATE = {
  NEW:               'new',                // pre-greet
  GREETING:          'greeting',           // client: waiting for banner
  NOT_AUTHENTICATED: 'not_authenticated',  // post-greet, pre-login
  AUTHENTICATED:     'authenticated',      // logged in, no folder selected
  SELECTED:          'selected',           // a folder is open (read or read-write)
  LOGOUT:            'logout',             // LOGOUT sent/received
  CLOSED:            'closed'
};

// Default SASL mechanisms supported. PLAIN + LOGIN for password auth,
// XOAUTH2 for bearer-token auth (Gmail, Outlook, and other modern providers).
// The developer validates XOAUTH2 tokens themselves by inspecting authMethod
// on the auth event and calling the provider's introspection endpoint.
const DEFAULT_AUTH_METHODS = ['PLAIN', 'LOGIN', 'XOAUTH2'];

// Base capabilities always advertised by the server
const BASE_CAPABILITIES = ['IMAP4rev1', 'LITERAL+', 'SPECIAL-USE'];



// ============================================================
//  IMAPSession
// ============================================================

function IMAPSession(options) {
  if (!(this instanceof IMAPSession)) return new IMAPSession(options);
  options = options || {};

  const ev = new EventEmitter();
  // IMAP mailboxSession has many handlers (folders / openFolder / messageMeta /
  // messageBody / messageEnvelope / messageBodyStructure / setFlags / append /
  // copyMessages / move / expunge / createFolder / deleteFolder / renameFolder /
  // subscribe / unsubscribe / status / search / sort / thread / namespace /
  // qresync / resolveVanished / close — ~24 different events). Node's default
  // max is 10, which triggers MaxListenersExceededWarning on realistic setups.
  // 50 is a comfortable ceiling that still catches actual runaway listeners.
  ev.setMaxListeners(50);

  let context = {
    state: STATE.NEW,
    isServer: options.isServer !== false,   // default: true

    // Server identity / connection info
    hostname:       options.hostname       || DEFAULT_HOSTNAME,
    maxCommandSize: options.maxCommandSize || DEFAULT_MAX_COMMAND,
    authTimeout:    options.authTimeout    || DEFAULT_AUTH_TIMEOUT,
    delimiter:      options.delimiter      || DEFAULT_DELIMITER,   // hierarchy separator
    remoteAddress:  options.remoteAddress  || null,
    localAddress:   options.localAddress   || null,

    // TLS
    isTLS:          !!options.isTLS,
    tlsOptions:     options.tlsOptions || null,
    advertiseTLS:   !options.isTLS && !!options.tlsOptions,

    // Compression (RFC 4978 COMPRESS=DEFLATE). Set true after COMPRESS
    // activates; once true it cannot be reset within this session.
    compressed:     false,

    // Server: allowed auth mechanisms
    authMethods: options.authMethods || DEFAULT_AUTH_METHODS.slice(),

    // Authentication state
    authenticated:   false,
    authUsername:    null,
    authInProgress:  null,  // { mechanism, tag, step, username? } during SASL flow

    // Selected-folder state (populated after successful SELECT/EXAMINE, cleared on CLOSE/UNSELECT)
    currentFolder:             null,
    currentFolderReadOnly:     false,
    currentFolderUidValidity:  null,
    currentFolderTotal:        0,
    currentFolderHighestModseq: 0,   // RFC 7162: tracked per folder

    // IDLE state (RFC 2177)
    idling:    false,
    idleTag:   null,   // server: tag of in-flight IDLE command
    idleCb:    null,   // client: callback for "idle started" confirmation
    idleDoneCb: null,  // client: callback for DONE acknowledgement

    // ENABLE-activated features (RFC 5161)
    condstoreEnabled: false,   // RFC 7162
    qresyncEnabled:   false,   // RFC 7162 — enables VANISHED in place of EXPUNGE

    // Input buffer (shared server + client)
    //
    // Implementation: a growing backing buffer (`inputBacking`) with read and
    // write offsets. `inputBuf` is a view — `inputBacking.subarray(readOff, writeOff)`.
    //
    // • appendInput: grows the backing if needed (doubling), writes new bytes
    //   at writeOff. Never overwrites already-consumed bytes, so subarrays the
    //   parser extracted (e.g. literal body buffers) stay valid.
    // • consumeInput: advances readOff. When fully drained, drops the backing
    //   buffer so GC can reclaim — prevents memory buildup across large FETCHes.
    //
    // Previous impl used Buffer.concat on every chunk which was O(n²) — a 50MB
    // body delivered in 64KB chunks triggered 800× 50MB copies. Now amortized O(n).
    inputBuf:     Buffer.alloc(0),
    inputBacking: null,
    readOff:      0,
    writeOff:     0,

    // --- Server-only state ---
    // When parseCommand returns NEED_CONTINUATION, we send "+ Ready" once (unless LITERAL+)
    // and then wait for enough bytes to complete the command. awaitingLiteral prevents
    // re-sending the continuation on subsequent incomplete parses.
    awaitingLiteral: false,

    // --- Client-only state ---
    tagGen:          null,   // tag generator (A0001, A0002, ...)
    pendingCommand:  null,   // { tag, untagged: [], cb } waiting for tagged response
    remoteCaps:      null    // { IMAP4REV1: true, STARTTLS: true, ... } — populated from CAPABILITY
  };

  if (!context.isServer) {
    context.tagGen = makeTagGenerator('A');
  }


  // ============================================================
  //  Input buffer management
  // ============================================================

  function appendInput(chunk) {
    if (!Buffer.isBuffer(chunk)) chunk = Buffer.from(chunk);

    // Fast path — no pending data. Small-response common case (99% of traffic).
    // Just copy the chunk directly; no backing allocation needed.
    if (context.inputBuf.length === 0) {
      context.inputBuf = Buffer.from(chunk);
      context.inputBacking = null;
      context.readOff = 0;
      context.writeOff = context.inputBuf.length;
      return;
    }

    // Combining path — partial response in buffer. Use a growing backing
    // buffer so many small chunks combining into a large literal don't trigger
    // O(n²) reallocation.
    let unread = context.writeOff - context.readOff;
    let needed = unread + chunk.length;

    if (!context.inputBacking || needed > context.inputBacking.length) {
      // First combine OR need to grow. Double capacity to amortize.
      let newCap = Math.max(needed, (context.inputBacking ? context.inputBacking.length : 4096) * 2);
      let newBuf = Buffer.allocUnsafe(newCap);
      context.inputBuf.copy(newBuf, 0, 0, unread);
      context.inputBacking = newBuf;
      context.readOff = 0;
      context.writeOff = unread;
    }

    chunk.copy(context.inputBacking, context.writeOff);
    context.writeOff += chunk.length;
    context.inputBuf = context.inputBacking.subarray(context.readOff, context.writeOff);
  }

  function consumeInput(n) {
    if (n >= context.inputBuf.length) {
      // Fully drained — drop any backing to release memory
      context.inputBuf = Buffer.alloc(0);
      context.inputBacking = null;
      context.readOff = 0;
      context.writeOff = 0;
    } else if (context.inputBacking) {
      // Partial consume within a backed buffer
      context.readOff += n;
      context.inputBuf = context.inputBacking.subarray(context.readOff, context.writeOff);
    } else {
      // Partial consume of a fresh (non-backed) chunk — zero-copy slice
      context.inputBuf = context.inputBuf.subarray(n);
    }
  }


  // ============================================================
  //  Send helpers
  // ============================================================

  // Send data to the peer. Accepts:
  //   • a single Buffer  — emitted as one 'send' event
  //   • an array of Buffers — each emitted as its own 'send' event (in order)
  //
  // The array form enables zero-copy passthrough of large message bodies:
  // instead of Buffer.concat'ing a 50MB body into one mega-buffer, we can
  // emit [smallHeader, bigBodyView, smallFooter] — the bigBodyView being a
  // subarray of the original storage buffer, no allocation.
  function send(data) {
    if (context.state === STATE.CLOSED) return;
    if (Array.isArray(data)) {
      for (let i = 0; i < data.length; i++) {
        if (data[i] && data[i].length > 0) ev.emit('send', data[i]);
      }
    } else {
      ev.emit('send', data);
    }
  }

  function sendTagged(tag, status, text, code) {
    send(buildTagged(tag, status, text, code));
  }

  function sendUntagged(data) {
    send(buildUntagged(data));
  }

  function sendContinuation(text) {
    send(buildContinuation(text));
  }


  // ============================================================
  //  Capabilities (server advertises these in banner + CAPABILITY response)
  // ============================================================

  function getCapabilities() {
    let caps = BASE_CAPABILITIES.slice();

    if (context.advertiseTLS) {
      caps.push('STARTTLS');
      // RFC 3501 §6.2.3: server MUST NOT allow LOGIN until STARTTLS is complete,
      // and MUST advertise LOGINDISABLED to signal this.
      caps.push('LOGINDISABLED');
    } else {
      // Only advertise AUTH= mechanisms when TLS is active (or TLS isn't required)
      for (let i = 0; i < context.authMethods.length; i++) {
        caps.push('AUTH=' + context.authMethods[i]);
      }
    }

    // Phase 4 extensions
    caps.push('IDLE');       // RFC 2177 — long-lived notification channel
    caps.push('UIDPLUS');    // RFC 4315 — APPENDUID, COPYUID, UID EXPUNGE
    caps.push('NAMESPACE');  // RFC 2342 — mailbox namespace discovery
    caps.push('SORT');                    // RFC 5256
    caps.push('THREAD=ORDEREDSUBJECT');   // RFC 5256
    caps.push('THREAD=REFERENCES');       // RFC 5256
    caps.push('ENABLE');                  // RFC 5161 — feature enablement
    caps.push('CONDSTORE');               // RFC 7162 — conditional store + MODSEQ
    caps.push('QRESYNC');                 // RFC 7162 — quick resync
    caps.push('LIST-EXTENDED');           // RFC 5258 — selection/return options
    caps.push('LIST-STATUS');             // RFC 5819 — STATUS in LIST RETURN
    caps.push('SPECIAL-USE');             // RFC 6154 — \Sent \Drafts \Trash etc.
    caps.push('WITHIN');                  // RFC 5032 — SEARCH YOUNGER/OLDER

    // MOVE (RFC 6851) is advertised only when the developer has registered a 'move'
    // handler — otherwise the client would try MOVE and get a NO every time. Falling
    // back to COPY+STORE+EXPUNGE is the client's standard plan in that case.
    if (ev.listenerCount('move') > 0) caps.push('MOVE');

    // QUOTA (RFC 9208) — advertise only when the developer has wired up a 'quota'
    // handler. Include resource tags (STORAGE, MESSAGE) per the RFC so clients
    // can query only what we support. For this library we leave both on because
    // the developer decides what to populate; clients that ask about an unknown
    // resource will simply get it missing from the response.
    if (ev.listenerCount('quota') > 0) {
      caps.push('QUOTA');
      caps.push('QUOTA=RES-STORAGE');
      caps.push('QUOTA=RES-MESSAGE');
    }

    // COMPRESS=DEFLATE (RFC 4978) — once compression is active, RFC 4978 §4
    // says the capability MUST NOT be re-advertised. Also skip if TLS will
    // first be required and isn't yet in effect — no point compressing before
    // the real session can start.
    if (!context.compressed && !context.advertiseTLS) {
      caps.push('COMPRESS=DEFLATE');
    }

    // METADATA (RFC 5464) — advertise only when the developer has wired up
    // either handler. The RFC distinguishes METADATA (mailbox-scoped) from
    // METADATA-SERVER (server-wide annotations). We advertise both because
    // the dispatch path is the same — the mailbox argument "" just means
    // the server-wide scope.
    if (ev.listenerCount('getMetadata') > 0 || ev.listenerCount('setMetadata') > 0) {
      caps.push('METADATA');
      caps.push('METADATA-SERVER');
    }

    return caps;
  }

  function loginAllowed() {
    // LOGIN (and AUTHENTICATE) are forbidden until STARTTLS when TLS is available
    // but not yet active — we advertised LOGINDISABLED in that case.
    return !(context.advertiseTLS && !context.isTLS);
  }


  // ============================================================
  //  Extract string from a token value (handles atom/quoted/literal)
  // ============================================================

  function getStringValue(tok) {
    if (!tok) return '';
    if (tok.type === TOK.LITERAL) return u8ToStr(tok.value);
    if (tok.value === null) return '';
    return String(tok.value);
  }


  // ============================================================
  //  SERVER MODE — feed loop
  // ============================================================

  function feedServer() {
    while (context.state !== STATE.CLOSED) {

      // --- IDLE mode ---
      // RFC 2177: during IDLE, the only valid client input is "DONE\r\n".
      // Everything else is silently ignored.
      if (context.idling) {
        let cr = indexOfCRLF(context.inputBuf, 0);
        if (cr < 0) break;  // wait for full line
        let line = u8ToStr(context.inputBuf.subarray(0, cr)).trim();
        consumeInput(cr + 2);
        if (line.toUpperCase() === 'DONE') {
          let tag = context.idleTag;
          context.idling = false;
          context.idleTag = null;
          sendTagged(tag, 'OK', 'IDLE terminated');
          ev.emit('idleEnd');
        }
        // If the client sends anything else during IDLE, we drop it per
        // "stray line" tolerance. Real clients never do this.
        continue;
      }

      // --- AUTHENTICATE continuation mode ---
      // While AUTHENTICATE is in progress, client sends raw base64 lines (not commands).
      if (context.authInProgress) {
        let cr = indexOfCRLF(context.inputBuf, 0);
        if (cr < 0) break;  // wait for full line
        let line = u8ToStr(context.inputBuf.subarray(0, cr)).trim();
        consumeInput(cr + 2);
        handleAuthContinuation(line);
        continue;
      }

      // --- Command size guard (protects against slow-loris / huge literals) ---
      if (context.inputBuf.length > context.maxCommandSize) {
        sendTagged('*', 'BAD', 'Command too large');
        ev.emit('error', new Error('Command size limit exceeded'));
        doClose();
        return;
      }

      // --- COMMAND mode ---
      let result = parseCommand(context.inputBuf, 0);

      if (result.status === PARSE.INCOMPLETE) break;

      if (result.status === PARSE.NEED_CONTINUATION) {
        // Literal seen mid-command. For sync literals, send "+" once.
        // For LITERAL+ (nonSync), client sends bytes without waiting.
        // In both cases we simply wait for more data.
        if (!context.awaitingLiteral) {
          if (!result.nonSync) sendContinuation('Ready for literal');
          context.awaitingLiteral = true;
        }
        break;
      }

      // Command completed (either OK or ERROR) — reset literal wait flag
      context.awaitingLiteral = false;

      if (result.status === PARSE.ERROR) {
        // Reply BAD; use '*' if no tag was parsed
        sendTagged(result.tag || '*', 'BAD', result.reason || 'Syntax error');
        if (result.end) consumeInput(result.end);
        else {
          // Skip to next CRLF to recover
          let cr = indexOfCRLF(context.inputBuf, 0);
          if (cr < 0) break;
          consumeInput(cr + 2);
        }
        continue;
      }

      // status === OK
      consumeInput(result.end);
      processCommand(result.command);
    }
  }


  // ============================================================
  //  SERVER MODE — command dispatch
  // ============================================================

  function processCommand(cmd) {
    ev.emit('command', cmd);

    let tag = cmd.tag;
    let name = cmd.name;
    let args = cmd.args || [];

    switch (name) {
      case 'CAPABILITY':   handleCapability(tag);         break;
      case 'NOOP':         handleNoop(tag);               break;
      case 'LOGOUT':       handleLogout(tag);             break;
      case 'STARTTLS':     handleStartTLS(tag);           break;
      case 'LOGIN':        handleLogin(tag, args);        break;
      case 'AUTHENTICATE': handleAuthenticate(tag, args); break;

      // Phase 2 — folder management + SELECT
      case 'LIST':         s.handleList(tag, args, false);  break;
      case 'LSUB':         s.handleList(tag, args, true);   break;
      case 'SELECT':       s.handleSelect(tag, args, false); break;
      case 'EXAMINE':      s.handleSelect(tag, args, true);  break;
      case 'CREATE':       s.handleCreate(tag, args);       break;
      case 'DELETE':       s.handleDelete(tag, args);       break;
      case 'RENAME':       s.handleRename(tag, args);       break;
      case 'SUBSCRIBE':    s.handleSubscribe(tag, args);    break;
      case 'UNSUBSCRIBE':  s.handleUnsubscribe(tag, args);  break;
      case 'STATUS':       s.handleStatus(tag, args);       break;
      case 'CLOSE':        s.handleClose(tag);              break;
      case 'UNSELECT':     s.handleUnselect(tag);           break;

      // Phase 3a — message operations (FETCH, STORE, COPY, UID variants)
      case 'FETCH':        s.handleFetch(tag, args, false); break;
      case 'STORE':        s.handleStore(tag, args, false); break;
      case 'COPY':         s.handleCopy(tag, args, false);  break;
      case 'SEARCH':       s.handleSearch(tag, args, false); break;
      case 'UID':          handleUid(tag, args);          break;

      // Phase 4 — write operations + push
      case 'APPEND':       s.handleAppend(tag, args);        break;
      case 'EXPUNGE':      s.handleExpunge(tag, null);       break;
      case 'MOVE':         s.handleMove(tag, args, false);   break;
      case 'IDLE':         handleIdle(tag);                break;
      case 'NAMESPACE':    s.handleNamespace(tag);           break;

      // RFC 9208 — QUOTA
      case 'GETQUOTA':     s.handleGetQuota(tag, args);      break;
      case 'GETQUOTAROOT': s.handleGetQuotaRoot(tag, args);  break;

      // RFC 5256 — SORT / THREAD
      case 'SORT':         s.handleSort(tag, args, false);   break;
      case 'THREAD':       s.handleThread(tag, args, false); break;

      // RFC 5161 — ENABLE (activates capabilities like CONDSTORE)
      case 'ENABLE':       handleEnable(tag, args);        break;

      // RFC 4978 — COMPRESS=DEFLATE
      case 'COMPRESS':     handleCompress(tag, args);      break;

      // RFC 5464 — METADATA
      case 'GETMETADATA':  s.handleGetMetadata(tag, args); break;
      case 'SETMETADATA':  s.handleSetMetadata(tag, args); break;

      default:
        // Unknown or unimplemented command
        sendTagged(tag, 'BAD', 'Unknown command: ' + name);
    }
  }


  // ============================================================
  //  SERVER MODE — command handlers
  // ============================================================

  function handleCapability(tag) {
    sendUntagged('CAPABILITY ' + getCapabilities().join(' '));
    sendTagged(tag, 'OK', 'CAPABILITY completed');
  }

  function handleNoop(tag) {
    // In SELECTED state (Phase 2), NOOP may emit untagged status updates.
    // For now, just acknowledge.
    sendTagged(tag, 'OK', 'NOOP completed');
  }

  function handleLogout(tag) {
    sendUntagged('BYE IMAP server signing off');
    sendTagged(tag, 'OK', 'LOGOUT completed');
    context.state = STATE.LOGOUT;
    // Transport layer should close after receiving this — we emit 'close' too.
    ev.emit('close');
  }

  function handleStartTLS(tag) {
    if (context.isTLS) {
      sendTagged(tag, 'BAD', 'Already in TLS');
      return;
    }
    if (!context.tlsOptions) {
      sendTagged(tag, 'NO', 'STARTTLS not available');
      return;
    }
    sendTagged(tag, 'OK', 'Begin TLS negotiation now');
    // Transport layer handles the upgrade; caller will invoke tlsUpgraded().
    ev.emit('starttls');
  }

  // --- RFC 4978 COMPRESS ---
  //   C: x COMPRESS DEFLATE
  //   S: x OK DEFLATE active
  //   <from here on both directions are deflate-compressed>
  //
  // Client commonly issues this right after auth to save bandwidth —
  // Thunderbird mobile and Gmail mobile both use it. Activation is one-shot
  // and cannot be reversed during the session.
  function handleCompress(tag, args) {
    if (context.state === STATE.NOT_AUTHENTICATED || context.state === STATE.LOGOUT) {
      sendTagged(tag, 'BAD', 'COMPRESS requires authenticated state');
      return;
    }
    if (context.compressed) {
      // RFC 4978 §4: "A server MUST NOT accept a COMPRESS command if a
      // compression layer is already active." We return NO with the standard
      // response code per §3.
      sendTagged(tag, 'NO', 'Compression already active', 'COMPRESSIONACTIVE');
      return;
    }
    if (args.length < 1 || String(args[0].value || '').toUpperCase() !== 'DEFLATE') {
      sendTagged(tag, 'BAD', 'COMPRESS requires DEFLATE algorithm');
      return;
    }

    // Mark compressed BEFORE sending OK — so the server-side listener knows
    // not to double-wrap, and so any concurrent feedFn calls take the new
    // path. The OK response itself is the last uncompressed byte stream;
    // transport layer swaps pipelines once it sees this event.
    context.compressed = true;
    sendTagged(tag, 'OK', 'DEFLATE active');
    ev.emit('compress');
  }

  function handleLogin(tag, args) {
    if (context.authenticated) {
      sendTagged(tag, 'BAD', 'Already authenticated');
      return;
    }
    if (args.length < 2) {
      sendTagged(tag, 'BAD', 'LOGIN requires username and password');
      return;
    }
    if (!loginAllowed()) {
      sendTagged(tag, 'NO', 'LOGIN disabled — use STARTTLS first');
      return;
    }

    let username = getStringValue(args[0]);
    let password = getStringValue(args[1]);
    emitAuth(username, password, tag, 'plain');
  }

  function handleAuthenticate(tag, args) {
    if (context.authenticated) {
      sendTagged(tag, 'BAD', 'Already authenticated');
      return;
    }
    if (args.length < 1) {
      sendTagged(tag, 'BAD', 'AUTHENTICATE requires a mechanism');
      return;
    }
    if (!loginAllowed()) {
      sendTagged(tag, 'NO', 'AUTHENTICATE disabled — use STARTTLS first');
      return;
    }

    let mechanism = getStringValue(args[0]).toUpperCase();
    if (context.authMethods.indexOf(mechanism) < 0) {
      sendTagged(tag, 'NO', 'Unsupported authentication mechanism');
      return;
    }

    if (mechanism === 'PLAIN') {
      // SASL-IR (RFC 4959): initial response may be provided inline as args[1].
      if (args.length > 1) {
        handleSaslPlain(tag, getStringValue(args[1]));
      } else {
        context.authInProgress = { mechanism: 'PLAIN', tag: tag, step: 1 };
        sendContinuation('');  // empty challenge
      }
    } else if (mechanism === 'LOGIN') {
      context.authInProgress = { mechanism: 'LOGIN', tag: tag, step: 1 };
      sendContinuation(Buffer.from('Username:').toString('base64'));
    } else if (mechanism === 'XOAUTH2') {
      // RFC 7628 / Google XOAUTH2. Token may be inline (SASL-IR) or via
      // continuation. See handleSaslXoauth2 for format.
      if (args.length > 1) {
        handleSaslXoauth2(tag, getStringValue(args[1]));
      } else {
        context.authInProgress = { mechanism: 'XOAUTH2', tag: tag, step: 1 };
        sendContinuation('');
      }
    }
    // Other mechanisms rejected above; kept open for future SCRAM/CRAM-MD5.
  }

  // Client sent a line during AUTHENTICATE — handle per mechanism.
  function handleAuthContinuation(line) {
    let auth = context.authInProgress;
    if (!auth) return;

    // RFC 3501 §6.2.2: client may cancel with "*"
    if (line === '*') {
      sendTagged(auth.tag, 'BAD', 'AUTHENTICATE cancelled');
      context.authInProgress = null;
      return;
    }

    if (auth.mechanism === 'PLAIN') {
      handleSaslPlain(auth.tag, line);
      context.authInProgress = null;
      return;
    }

    if (auth.mechanism === 'XOAUTH2') {
      handleSaslXoauth2(auth.tag, line);
      context.authInProgress = null;
      return;
    }

    if (auth.mechanism === 'LOGIN') {
      if (auth.step === 1) {
        // First line = username
        try {
          auth.username = Buffer.from(line, 'base64').toString('utf-8');
        } catch(e) {
          sendTagged(auth.tag, 'BAD', 'Invalid base64 in username');
          context.authInProgress = null;
          return;
        }
        auth.step = 2;
        sendContinuation(Buffer.from('Password:').toString('base64'));
      } else {
        // Second line = password
        let password;
        try {
          password = Buffer.from(line, 'base64').toString('utf-8');
        } catch(e) {
          sendTagged(auth.tag, 'BAD', 'Invalid base64 in password');
          context.authInProgress = null;
          return;
        }
        let username = auth.username;
        let tag = auth.tag;
        context.authInProgress = null;
        emitAuth(username, password, tag, 'login');
      }
    }
  }

  // SASL PLAIN format: authzid \0 authcid \0 password
  function handleSaslPlain(tag, b64) {
    let decoded;
    try {
      decoded = Buffer.from(b64, 'base64').toString('utf-8');
    } catch(e) {
      sendTagged(tag, 'BAD', 'Invalid base64');
      return;
    }
    let parts = decoded.split('\0');
    if (parts.length < 3) {
      sendTagged(tag, 'BAD', 'Malformed PLAIN response');
      return;
    }
    // authzid may be empty; use authcid as username
    let username = parts[1] || parts[0];
    let password = parts[2];
    emitAuth(username, password, tag, 'plain');
  }

  // SASL XOAUTH2 format (RFC 7628 / Google / Microsoft):
  //   base64( "user=" <email> \x01 "auth=Bearer " <access-token> \x01 \x01 )
  //
  // The developer validates the bearer token against their identity provider
  // (Google's tokeninfo endpoint, Microsoft Graph, a local JWT verifier, etc.).
  // The library does no token introspection — that's outside its scope.
  //
  // On rejection, RFC 7628 §3.2.3 asks the server to send a base64 error
  // payload in a continuation, wait for an empty client response, and THEN
  // emit the tagged NO. We just send the tagged NO directly — clients retry
  // with a refreshed token on any failure, so the elaborate dance adds
  // nothing in practice.
  function handleSaslXoauth2(tag, b64) {
    let decoded;
    try {
      decoded = Buffer.from(b64, 'base64').toString('utf-8');
    } catch(e) {
      sendTagged(tag, 'BAD', 'Invalid base64');
      return;
    }
    let parts = decoded.split('\x01');
    let username = null;
    let token = null;
    for (let i = 0; i < parts.length; i++) {
      let p = parts[i];
      if (p.indexOf('user=') === 0)              username = p.substring(5);
      else if (p.indexOf('auth=Bearer ') === 0)  token    = p.substring(12);
    }
    if (!username || !token) {
      sendTagged(tag, 'BAD', 'Malformed XOAUTH2 response');
      return;
    }
    // Token arrives in `password` position — the developer inspects
    // authMethod === 'xoauth2' to know it's a bearer token, not a password.
    emitAuth(username, token, tag, 'xoauth2');
  }

  // Common auth emit — fires 'imapAuth' event. Developer calls accept/reject to respond.
  // authMethod is 'plain' | 'login' | 'xoauth2' — lets the developer tell
  // traditional password auth apart from bearer-token (OAuth2) auth.
  function emitAuth(username, password, tag, authMethod) {
    let settled = false;
    let timer = null;

    if (context.authTimeout > 0) {
      timer = setTimeout(function() {
        if (settled) return;
        settled = true;
        sendTagged(tag, 'NO', 'Authentication timed out');
      }, context.authTimeout);
    }

    let authCtx = {
      username: username,
      password: password,
      authMethod: authMethod || 'plain',
      remoteAddress: context.remoteAddress,
      isTLS: context.isTLS,

      accept: function() {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        context.authenticated = true;
        context.authUsername = username;
        context.state = STATE.AUTHENTICATED;
        // Defer the OK response by one tick so the developer has time to
        // register per-session handlers after calling `accept()`:
        //
        //   auth.accept();
        //   auth.on('folders', ...);    ← must be set before client sends next cmd
        //
        // Without this defer, the OK would be sent synchronously, the client
        // would fire its login callback, issue the next command (e.g. SELECT),
        // and our server would look for an 'openFolder' handler before the
        // developer registered it.
        //
        // We also piggyback the fresh CAPABILITY list on this OK (RFC 3501
        // §7.1 allows this as a response code). That matters because some
        // capabilities are listener-gated — MOVE, METADATA, QUOTA — and
        // only become available AFTER the developer wires up their handlers
        // during the mailboxSession event. Without this, a client would see
        // the pre-auth capability list (no listeners registered yet) and
        // miss every handler-gated feature until the next explicit CAPABILITY.
        setImmediate(function() {
          let caps = getCapabilities().join(' ');
          sendTagged(tag, 'OK', 'Authentication successful', 'CAPABILITY ' + caps);
        });
      },

      reject: function(msg) {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        setImmediate(function() {
          sendTagged(tag, 'NO', msg || 'Invalid credentials');
        });
      },

      // Event registration — forwards to the session's internal EventEmitter.
      // The server layer (or developer using IMAPSession directly) registers
      // handlers here for folders / messageMeta / messageBody / etc. All such
      // handlers naturally share the `authCtx.username` closure — no artificial
      // `user` argument is needed on any event.
      on:   function(name, fn) { ev.on(name, fn);   return authCtx; },
      off:  function(name, fn) { ev.off(name, fn);  return authCtx; },
      once: function(name, fn) { ev.once(name, fn); return authCtx; }
    };

    ev.emit('imapAuth', authCtx);
  }




  // ============================================================
  //  SERVER MODE — Phase 3a handlers: FETCH / STORE / COPY (+ UID variants)
  // ============================================================

  // Guard: FETCH/STORE/COPY require SELECTED state
  function requireSelected(tag) {
    if (context.state !== STATE.SELECTED) {
      sendTagged(tag, 'BAD', 'No folder selected');
      return false;
    }
    return true;
  }

  // Message operation handlers (FETCH / STORE / COPY) are defined in
  // imap_messages.js for modularity. We pass a minimal session interface `s`
  // — the handlers attach themselves to it as s.handleFetch / s.handleStore /
  // s.handleCopy and the dispatcher below calls through that.
  let s = {
    context:         context,
    ev:              ev,
    STATE:           STATE,
    sendTagged:      sendTagged,
    sendUntagged:    sendUntagged,
    send:            send,
    requireSelected: requireSelected,
    getStringValue:  getStringValue
  };
  registerMessageHandlers(s);  // must be before folders (emitFetchResponse needed by QRESYNC)
  registerSearchHandlers(s);
  registerFolderHandlers(s);
  registerMetadataHandlers(s);

  // --- UID dispatcher — "UID FETCH", "UID STORE", "UID COPY" ---
  function handleUid(tag, args) {
    if (!requireSelected(tag)) return;
    if (args.length < 1) {
      sendTagged(tag, 'BAD', 'UID requires a sub-command');
      return;
    }
    let sub = String(args[0].value || '').toUpperCase();
    let rest = args.slice(1);

    switch (sub) {
      case 'FETCH':   s.handleFetch(tag, rest, true);      break;
      case 'STORE':   s.handleStore(tag, rest, true);      break;
      case 'COPY':    s.handleCopy(tag,  rest, true);      break;
      case 'SEARCH':  s.handleSearch(tag, rest, true);     break;
      case 'EXPUNGE': s.handleExpunge(tag, rest);          break;  // RFC 4315
      case 'MOVE':    s.handleMove(tag, rest, true);       break;  // RFC 6851
      case 'SORT':    s.handleSort(tag, rest, true);       break;  // RFC 5256
      case 'THREAD':  s.handleThread(tag, rest, true);     break;  // RFC 5256
      default:
        sendTagged(tag, 'BAD', 'Unsupported UID sub-command: ' + sub);
    }
  }



  // ============================================================
  //  Phase 4 — APPEND, EXPUNGE, MOVE, IDLE
  // ============================================================


  // --- IDLE (RFC 2177) ---
  // Enter idle mode: send "+ idling" continuation, then wait for "DONE" from client.
  // While idling, the developer can call session.notifyXxx() to push untagged responses.
  function handleIdle(tag) {
    if (context.state !== STATE.AUTHENTICATED && context.state !== STATE.SELECTED) {
      sendTagged(tag, 'BAD', 'IDLE requires authentication');
      return;
    }
    context.idling  = true;
    context.idleTag = tag;
    sendContinuation('idling');
    ev.emit('idleStart', context.currentFolder);
  }





  // ============================================================
  //  ENABLE (RFC 5161) + CONDSTORE (RFC 7162)
  // ============================================================

  //   ENABLE <capability> [<capability> ...]
  //   → * ENABLED <capability-1> <capability-2> ...
  //   → tag OK ENABLE completed
  //
  // Server echoes only the capabilities it agreed to enable. Unknown names
  // are silently ignored per RFC 5161 §3.1.
  function handleEnable(tag, args) {
    if (context.state !== STATE.AUTHENTICATED) {
      // RFC 5161: ENABLE only in authenticated (not selected) state
      sendTagged(tag, 'BAD', 'ENABLE only valid in authenticated state');
      return;
    }
    if (args.length === 0) {
      sendTagged(tag, 'BAD', 'ENABLE requires at least one capability');
      return;
    }

    let enabled = [];
    for (let i = 0; i < args.length; i++) {
      let name = String(args[i].value || '').toUpperCase();
      if (name === 'CONDSTORE') {
        context.condstoreEnabled = true;
        enabled.push('CONDSTORE');
      }
      else if (name === 'QRESYNC') {
        // RFC 7162 §3.2.3: QRESYNC implies CONDSTORE
        context.condstoreEnabled = true;
        context.qresyncEnabled = true;
        enabled.push('QRESYNC');
      }
      // Future: other capabilities
    }

    if (enabled.length > 0) {
      sendUntagged('ENABLED ' + enabled.join(' '));
    }
    sendTagged(tag, 'OK', 'ENABLE completed');
  }


  // ============================================================
  //  Push notifications — server calls these to notify a connected client
  //  about mailbox changes. Valid anytime after SELECT; no-op otherwise.
  // ============================================================

  // New message count. Updates the session's view of total and sends "* N EXISTS".
  function notifyExists(total) {
    if (!context.isServer) return;
    if (context.state !== STATE.SELECTED) return;
    if (typeof total === 'number') context.currentFolderTotal = total;
    sendUntagged(context.currentFolderTotal + ' EXISTS');
  }

  // "Recent" flag count (decoupled from total — clients use this for notification badges).
  function notifyRecent(count) {
    if (!context.isServer) return;
    if (context.state !== STATE.SELECTED) return;
    sendUntagged(count + ' RECENT');
  }

  // A single message was expunged. Sends "* N EXPUNGE" and decrements total.
  // If multiple messages are expunged at once, the caller must send notifyExpunge
  // for each one in DECREASING seq order (otherwise sequence numbers shift incorrectly).
  // Message expunged. Sends "* N EXPUNGE" — or, when QRESYNC is enabled and a
  // UID is provided, "* VANISHED <uid>" per RFC 7162 §3.2.10.
  //
  //   session.notifyExpunge(seq)        — classic, always EXPUNGE
  //   session.notifyExpunge(seq, uid)   — VANISHED when QRESYNC enabled, else EXPUNGE
  function notifyExpunge(seq, uid) {
    if (!context.isServer) return;
    if (context.state !== STATE.SELECTED) return;
    if (typeof seq !== 'number') return;

    // RFC 7162 §3.2.10: once QRESYNC is enabled, the server MUST use VANISHED
    // in place of EXPUNGE. We need the UID for this — if the caller didn't
    // supply one, we fall back to EXPUNGE (best-effort; may be non-compliant).
    if (context.qresyncEnabled && typeof uid === 'number') {
      sendUntagged('VANISHED ' + uid);
    } else {
      sendUntagged(seq + ' EXPUNGE');
    }
    if (context.currentFolderTotal > 0) context.currentFolderTotal--;
  }

  // Bulk variant: explicitly send a VANISHED response for multiple UIDs at once.
  // Efficient for large deletions. Requires QRESYNC to be enabled by the client.
  // Accepts either:
  //   • array of UIDs:               [120, 121, 122]
  //   • object with flat ranges:     { ranges: [120, 123] }
  //   • object with uids list:       { uids: [120, 121, 122] }
  function notifyVanished(arg) {
    if (!context.isServer) return;
    if (context.state !== STATE.SELECTED) return;

    let str = null;
    let count = 0;
    if (Array.isArray(arg) && arg.length > 0) {
      str = compressUids(arg);
      count = arg.length;
    } else if (arg && arg.ranges && arg.ranges.length > 0) {
      str = formatRanges(arg.ranges);
      for (let i = 0; i < arg.ranges.length; i += 2) count += (arg.ranges[i + 1] - arg.ranges[i]);
    } else if (arg && arg.uids && arg.uids.length > 0) {
      str = compressUids(arg.uids);
      count = arg.uids.length;
    }
    if (!str) return;

    // Unsolicited VANISHED is NOT tagged with (EARLIER) per RFC 7162 §3.2.10
    sendUntagged('VANISHED ' + str);
    if (context.currentFolderTotal > count) context.currentFolderTotal -= count;
    else context.currentFolderTotal = 0;
  }

  // Message flags changed. Sends "* N FETCH (UID x FLAGS (...))".
  // seq is required; uid is optional but recommended (clients use it for tracking).
  function notifyFlags(seq, uid, flags) {
    if (!context.isServer) return;
    if (context.state !== STATE.SELECTED) return;
    if (typeof seq !== 'number') return;

    let items = [];
    if (uid != null) items.push('UID ' + uid);
    let flagList = (flags || []).map(serializeFlag).join(' ');
    items.push('FLAGS (' + flagList + ')');
    sendUntagged(seq + ' FETCH (' + items.join(' ') + ')');
  }


  // ============================================================
  //  CLIENT MODE — feed loop
  // ============================================================

  function feedClient() {
    // Lazy state transition: if data arrives before greet() was called,
    // transition to GREETING automatically. Makes the API order-independent.
    if (context.state === STATE.NEW) {
      context.state = STATE.GREETING;
    }

    while (context.state !== STATE.CLOSED) {
      let result = parseResponse(context.inputBuf, 0);
      if (result.status === PARSE.INCOMPLETE) break;

      if (result.status === PARSE.ERROR) {
        // Malformed response — advance past the bad line and carry on.
        // In production, the client might also want to emit an error event.
        if (result.end) consumeInput(result.end);
        else {
          let cr = indexOfCRLF(context.inputBuf, 0);
          if (cr < 0) break;
          consumeInput(cr + 2);
        }
        continue;
      }

      consumeInput(result.end);
      routeResponse(result.response);
    }
  }


  // ============================================================
  //  CLIENT MODE — response routing
  // ============================================================

  function routeResponse(resp) {
    // Special case: first response in GREETING state is the server banner.
    if (context.state === STATE.GREETING && resp.kind === RESP.UNTAGGED) {
      handleClientBanner(resp);
      return;
    }

    if (resp.kind === RESP.UNTAGGED) {
      // Update known capabilities from "* CAPABILITY ..." responses
      maybeUpdateCapsFromUntagged(resp);

      // Accumulate into the current pending command (if any) so the callback
      // can see all untagged data that arrived before the tagged response.
      if (context.pendingCommand) {
        context.pendingCommand.untagged.push(resp);
      }

      // Also emit for observers (future IDLE handlers, etc.)
      ev.emit('untagged', resp);
      return;
    }

    if (resp.kind === RESP.CONTINUATION) {
      // IDLE continuation: server sent "+ idling" to confirm IDLE is active.
      // Fire the callback registered by clientIdle, then leave state as idling.
      if (context.idling && context.idleCb) {
        let cb = context.idleCb;
        context.idleCb = null;
        cb(null);
        return;
      }
      // AUTHENTICATE continuation — the pending command may have registered
      // an onContinuation handler (used by XOAUTH2 to ACK RFC 7628 error
      // payloads with an empty line so the server can finish with its NO).
      if (context.pendingCommand && context.pendingCommand.onContinuation) {
        context.pendingCommand.onContinuation(resp);
        return;
      }
      // Otherwise forward for other continuation scenarios
      ev.emit('continuation', resp);
      return;
    }

    if (resp.kind === RESP.TAGGED) {
      // IDLE tagged completion: arrives AFTER we've sent DONE.
      // Fire the done callback (if any) and exit idle state.
      if (context.idling && resp.tag === context.idleTag) {
        let cb = context.idleDoneCb;
        context.idling     = false;
        context.idleTag    = null;
        context.idleDoneCb = null;
        context.idleCb     = null;
        if (cb) cb(null, { status: resp.status, text: resp.text, code: resp.code });
        return;
      }
      // Match with the pending command by tag
      let pending = context.pendingCommand;
      if (pending && pending.tag === resp.tag) {
        context.pendingCommand = null;
        // RFC 3501 §7.1 — a tagged OK may carry "[CAPABILITY ...]" response
        // code. Common after LOGIN/AUTHENTICATE because the set of advertised
        // capabilities changes post-auth (handler-gated caps like METADATA,
        // MOVE, QUOTA become available once the developer wires up their
        // mailboxSession handlers). Update remoteCaps so client.capabilities
        // reflects reality without a second explicit CAPABILITY round-trip.
        if (resp.code && /^CAPABILITY\b/i.test(resp.code)) {
          parseCapsFromString(resp.code.replace(/^CAPABILITY\s*/i, ''));
        }
        let info = {
          status:   resp.status,
          text:     resp.text,
          code:     resp.code,
          untagged: pending.untagged
        };
        if (pending.cb) pending.cb(null, info);
      } else {
        // Unmatched tagged response — log/ignore
        ev.emit('untagged', resp);
      }
      return;
    }
  }

  function handleClientBanner(resp) {
    // Banner is an untagged OK/PREAUTH/BYE.
    // If BYE, server is refusing us — error out.
    let statusTok = resp.data && resp.data[0];
    let statusVal = statusTok ? String(statusTok.value || '').toUpperCase() : '';

    if (statusVal === 'BYE') {
      ev.emit('error', new Error('Server rejected connection: ' + tokenText(resp)));
      return;
    }

    // PREAUTH = server already authenticated us (common in localhost trust setups)
    if (statusVal === 'PREAUTH') {
      context.authenticated = true;
      context.state = STATE.AUTHENTICATED;
    } else {
      context.state = STATE.NOT_AUTHENTICATED;
    }

    // Banners often include [CAPABILITY ...] as a response code.
    // For untagged responses, the respcode appears inside data[] as a token with type='respcode'.
    let code = null;
    if (resp.data) {
      for (let i = 1; i < resp.data.length; i++) {
        if (resp.data[i] && resp.data[i].type === 'respcode') {
          code = resp.data[i].value;
          break;
        }
      }
    }

    if (code && /^CAPABILITY\b/i.test(code)) {
      parseCapsFromString(code.replace(/^CAPABILITY\s*/i, ''));
      ev.emit('ready');
      return;
    }

    // No capabilities in banner — fetch them explicitly.
    clientCapability(function(err) {
      if (err) { ev.emit('error', err); return; }
      ev.emit('ready');
    });
  }

  function maybeUpdateCapsFromUntagged(resp) {
    // "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN ..."
    if (!resp.data || resp.data.length < 2) return;
    let first = resp.data[0];
    if (!first || String(first.value).toUpperCase() !== 'CAPABILITY') return;

    context.remoteCaps = {};
    for (let i = 1; i < resp.data.length; i++) {
      let v = String(resp.data[i].value || '').toUpperCase();
      if (v) context.remoteCaps[v] = true;
    }
  }

  function parseCapsFromString(str) {
    let tokens = str.trim().split(/\s+/);
    context.remoteCaps = {};
    for (let i = 0; i < tokens.length; i++) {
      if (tokens[i]) context.remoteCaps[tokens[i].toUpperCase()] = true;
    }
  }

  // If the given tagged response carries a "[CAPABILITY ...]" response code,
  // refresh our cached remoteCaps from it. Servers emit this on the OK for
  // LOGIN/AUTHENTICATE (and after STARTTLS) to announce listener-gated
  // capabilities that only become available post-auth — MOVE, METADATA,
  // QUOTA, etc. Without parsing this, the client sticks with the pre-auth
  // caps list and never learns about those features until a manual CAPABILITY.
  function maybeUpdateCapsFromCode(info) {
    if (!info || !info.code) return;
    let code = String(info.code).trim();
    if (!/^CAPABILITY\b/i.test(code)) return;
    parseCapsFromString(code.replace(/^CAPABILITY\s*/i, ''));
  }

  function tokenText(resp) {
    if (!resp.data) return '';
    let parts = [];
    for (let i = 0; i < resp.data.length; i++) {
      let t = resp.data[i];
      parts.push(t && t.value != null ? String(t.value) : '');
    }
    return parts.join(' ');
  }


  // ============================================================
  //  CLIENT MODE — command methods
  // ============================================================

  // Lowest level: build, queue, send. cb(err, { status, text, code, untagged: [] })
  function clientSend(command, args, cb) {
    if (context.state === STATE.CLOSED) {
      if (cb) cb(new Error('Session is closed'));
      return;
    }
    if (context.idling) {
      // RFC 2177: client must send DONE before issuing another command
      if (cb) cb(new Error('Cannot send command while idling — call done() first'));
      return;
    }
    if (context.pendingCommand) {
      // Phase 1 is strictly sequential — no pipelining yet.
      // Future: queue commands here.
      if (cb) cb(new Error('Another command is pending'));
      return;
    }

    let tag = context.tagGen();
    context.pendingCommand = { tag: tag, untagged: [], cb: cb };
    send(buildCommand(tag, command, args || []));
  }

  function clientCapability(cb) {
    clientSend('CAPABILITY', [], function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('CAPABILITY failed: ' + info.text));
      // context.remoteCaps is a map {CAP: true}; expose as sorted array for the API
      let list = context.remoteCaps ? Object.keys(context.remoteCaps).sort() : [];
      if (cb) cb(null, { capabilities: list });
    });
  }

  // --- ENABLE (RFC 5161) ---
  //   client.enable(['CONDSTORE'], cb)  →  cb(null, { enabled: ['CONDSTORE'] })
  function clientEnable(capabilities, cb) {
    if (typeof capabilities === 'string') capabilities = [capabilities];
    if (!Array.isArray(capabilities) || capabilities.length === 0) {
      if (cb) cb(new Error('enable() requires an array of capabilities'));
      return;
    }
    let args = capabilities.map(function(c) {
      return { type: TOK.ATOM, value: String(c).toUpperCase() };
    });
    clientSend('ENABLE', args, function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('ENABLE failed: ' + info.text));

      // Parse "* ENABLED CAP1 CAP2 ..." from untagged
      let enabled = [];
      for (let i = 0; i < info.untagged.length; i++) {
        let r = info.untagged[i];
        if (!r.data || !r.data[0]) continue;
        if (String(r.data[0].value || '').toUpperCase() !== 'ENABLED') continue;
        for (let j = 1; j < r.data.length; j++) {
          if (r.data[j].value) enabled.push(String(r.data[j].value).toUpperCase());
        }
      }
      for (let i = 0; i < enabled.length; i++) {
        if (enabled[i] === 'CONDSTORE') context.condstoreEnabled = true;
        if (enabled[i] === 'QRESYNC')   { context.condstoreEnabled = true; context.qresyncEnabled = true; }
      }
      if (cb) cb(null, { enabled: enabled });
    });
  }

  // --- NAMESPACE (RFC 2342) ---
  //   client.namespace(cb)  →  cb(null, { namespaces: [{type, prefix, delimiter}, ...] })
  function clientNamespace(cb) {
    clientSend('NAMESPACE', [], function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('NAMESPACE failed: ' + info.text));

      let namespaces = [];
      for (let i = 0; i < info.untagged.length; i++) {
        let r = info.untagged[i];
        if (!r.data || !r.data[0]) continue;
        if (String(r.data[0].value || '').toUpperCase() !== 'NAMESPACE') continue;
        pushNamespaceGroup(namespaces, r.data[1], 'personal');
        pushNamespaceGroup(namespaces, r.data[2], 'otherUsers');
        pushNamespaceGroup(namespaces, r.data[3], 'shared');
        break;
      }
      if (cb) cb(null, { namespaces: namespaces });
    });
  }

  // --- QUOTA (RFC 9208) ---
  //
  //   client.getQuota(root, cb)     →  cb(null, { root, resources: [{name, usage, limit}] })
  //   client.getQuotaRoot(mbox, cb) →  cb(null, { roots: [...], quotas: { <root>: {resources} } })
  function clientGetQuota(root, cb) {
    clientSend('GETQUOTA', [{ type: TOK.QUOTED, value: String(root == null ? '' : root) }],
      function(err, info) {
        if (err) return cb && cb(err);
        if (info.status !== 'OK') return cb && cb(new Error('GETQUOTA failed: ' + info.text));
        let parsed = parseQuotaUntagged(info.untagged);
        if (cb) cb(null, parsed.quotas[root] || { root: root, resources: [] });
      });
  }

  function clientGetQuotaRoot(mailbox, cb) {
    clientSend('GETQUOTAROOT', [{ type: TOK.ATOM, value: String(mailbox) }],
      function(err, info) {
        if (err) return cb && cb(err);
        if (info.status !== 'OK') return cb && cb(new Error('GETQUOTAROOT failed: ' + info.text));
        let roots = [];
        for (let i = 0; i < info.untagged.length; i++) {
          let r = info.untagged[i];
          if (!r.data || !r.data[0]) continue;
          if (String(r.data[0].value || '').toUpperCase() !== 'QUOTAROOT') continue;
          // r.data[1] = mailbox, r.data[2..] = root names
          for (let j = 2; j < r.data.length; j++) {
            let v = tokenString(r.data[j]);
            if (v != null) roots.push(v);
          }
          break;
        }
        let parsed = parseQuotaUntagged(info.untagged);
        if (cb) cb(null, { roots: roots, quotas: parsed.quotas });
      });
  }

  // Extract all "* QUOTA <root> (<name> <usage> <limit> ...)" lines.
  function parseQuotaUntagged(untagged) {
    let quotas = {};
    for (let i = 0; i < untagged.length; i++) {
      let r = untagged[i];
      if (!r.data || !r.data[0]) continue;
      if (String(r.data[0].value || '').toUpperCase() !== 'QUOTA') continue;
      let root = tokenString(r.data[1]);
      let listTok = r.data[2];
      let resources = [];
      if (listTok && listTok.type === TOK.LIST) {
        let items = listTok.value;
        for (let j = 0; j + 2 < items.length; j += 3) {
          resources.push({
            name:  String(items[j].value || '').toUpperCase(),
            usage: items[j + 1].value,
            limit: items[j + 2].value
          });
        }
      }
      quotas[root != null ? root : ''] = { root: root, resources: resources };
    }
    return { quotas: quotas };
  }

  // --- METADATA (RFC 5464) ---
  //
  //   client.getMetadata(mailbox, paths, cb)
  //       → cb(null, { '/private/color': '#ff0000', '/shared/admin': null })
  //   client.setMetadata(mailbox, entries, cb)
  //       → entries = { '/private/color': '#00aaff', '/private/note': null }
  //
  // Use '' as the mailbox for server-wide annotations.
  function clientGetMetadata(mailbox, paths, cb) {
    if (!Array.isArray(paths)) paths = [paths];
    let args = [
      { type: TOK.QUOTED, value: String(mailbox == null ? '' : mailbox) },
      { type: TOK.LIST,
        value: paths.map(function(p) { return { type: TOK.ATOM, value: String(p) }; })
      }
    ];
    clientSend('GETMETADATA', args, function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('GETMETADATA failed: ' + info.text));

      // Parse "* METADATA <mailbox> (<key> <value> <key> <value> ...)"
      let values = {};
      for (let i = 0; i < info.untagged.length; i++) {
        let r = info.untagged[i];
        if (!r.data || !r.data[0]) continue;
        if (String(r.data[0].value || '').toUpperCase() !== 'METADATA') continue;
        let listTok = r.data[2];
        if (!listTok || listTok.type !== TOK.LIST) continue;
        for (let j = 0; j + 1 < listTok.value.length; j += 2) {
          let k = tokenString(listTok.value[j]);
          let v = tokenString(listTok.value[j + 1]);
          if (k) values[k] = v;
        }
      }
      // Paths not present in response → null (not set)
      for (let i = 0; i < paths.length; i++) {
        if (!(paths[i] in values)) values[paths[i]] = null;
      }
      if (cb) cb(null, values);
    });
  }

  function clientSetMetadata(mailbox, entries, cb) {
    let pairs = [];
    let keys = Object.keys(entries);
    for (let i = 0; i < keys.length; i++) {
      let k = keys[i];
      let v = entries[k];
      pairs.push({ type: TOK.ATOM, value: k });
      if (v === null || v === undefined) {
        pairs.push({ type: TOK.ATOM, value: 'NIL' });
      } else {
        pairs.push({ type: TOK.QUOTED, value: String(v) });
      }
    }
    let args = [
      { type: TOK.QUOTED, value: String(mailbox == null ? '' : mailbox) },
      { type: TOK.LIST, value: pairs }
    ];
    clientSend('SETMETADATA', args, function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('SETMETADATA failed: ' + info.text));
      if (cb) cb(null, info);
    });
  }

  // Parse one namespace group token into entries and append to `out`.
  // Each group is either NIL or a list of (prefix, delimiter, ...ext) tuples.
  function pushNamespaceGroup(out, groupTok, typeName) {
    if (!groupTok || groupTok.type === TOK.NIL) return;
    if (groupTok.type !== TOK.LIST) return;
    for (let i = 0; i < groupTok.value.length; i++) {
      let entry = groupTok.value[i];
      if (!entry || entry.type !== TOK.LIST || entry.value.length < 2) continue;
      let prefixTok = entry.value[0];
      let delimTok  = entry.value[1];
      out.push({
        type:      typeName,
        prefix:    prefixTok.type === TOK.NIL ? null : String(prefixTok.value || ''),
        delimiter: delimTok.type  === TOK.NIL ? null : String(delimTok.value  || '')
      });
    }
  }

  function clientLogin(username, password, cb) {
    clientSend('LOGIN', [username, password], function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('LOGIN failed: ' + info.text));
      context.authenticated = true;
      context.authUsername = username;
      context.state = STATE.AUTHENTICATED;
      maybeUpdateCapsFromCode(info);
      if (cb) cb(null, info);
    });
  }

  // AUTHENTICATE XOAUTH2 — bearer-token auth for Gmail / Outlook / iCloud / etc.
  //
  //   C: A001 AUTHENTICATE XOAUTH2 <base64>
  //   where <base64> decodes to "user=" <email> \x01 "auth=Bearer " <token> \x01 \x01
  //
  // We use SASL-IR (RFC 4959) to provide the token inline — avoids a
  // continuation round-trip. Most providers that support XOAUTH2 support IR;
  // if not, this will need a two-step variant.
  //
  // On success the server returns "A001 OK ..." (possibly preceded by an
  // untagged CAPABILITY response, which we let clientSend ignore as usual).
  // On failure — stale token, wrong user, etc. — some servers send a
  // continuation with a JSON error payload before the final NO. We just
  // reply to any continuation with an empty line so the server can finish
  // emitting its NO.
  function clientXoauth2(username, token, cb) {
    if (context.state === STATE.CLOSED) {
      if (cb) cb(new Error('Session is closed'));
      return;
    }
    if (context.pendingCommand) {
      if (cb) cb(new Error('Another command is pending'));
      return;
    }

    let payload = Buffer.from(
      'user=' + username + '\x01auth=Bearer ' + token + '\x01\x01',
      'utf-8'
    ).toString('base64');

    let tag = context.tagGen();
    // Mark pending command with a continuation hook — if the server asks us
    // for more data (RFC 7628 error-payload flow), we send "\r\n" and let the
    // command complete normally on the next tagged line.
    context.pendingCommand = {
      tag: tag,
      untagged: [],
      onContinuation: function() { send('\r\n'); },
      cb: function(err, info) {
        if (err) return cb && cb(err);
        if (info.status !== 'OK') {
          return cb && cb(new Error('XOAUTH2 failed: ' + info.text));
        }
        context.authenticated = true;
        context.authUsername = username;
        context.state = STATE.AUTHENTICATED;
        maybeUpdateCapsFromCode(info);
        if (cb) cb(null, info);
      }
    };
    send(buildCommandRaw(tag, 'AUTHENTICATE', 'XOAUTH2 ' + payload));
  }

  function clientLogout(cb) {
    clientSend('LOGOUT', [], function(err, info) {
      if (err) return cb && cb(err);
      context.state = STATE.LOGOUT;
      if (cb) cb(null, info);
    });
  }

  function clientStartTLS(cb) {
    if (context.isTLS) {
      if (cb) cb(new Error('Already in TLS'));
      return;
    }
    clientSend('STARTTLS', [], function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('STARTTLS rejected: ' + info.text));
      // Transport layer performs the TLS handshake, then calls session.tlsUpgraded().
      ev.emit('starttls');
      if (cb) cb(null, info);
    });
  }

  // COMPRESS=DEFLATE (RFC 4978) — client side.
  //
  // Flow:
  //   1. Caller invokes `session.compress(cb)`.
  //   2. Library sends "COMPRESS DEFLATE", awaits tagged OK.
  //   3. On OK, library marks context.compressed = true and emits 'compress'.
  //   4. The caller's 'compress' listener MUST swap the transport pipelines:
  //      run incoming socket bytes through zlib.createInflateRaw() before
  //      feeding them to session.feed(), and run session-output bytes through
  //      zlib.createDeflateRaw() before writing to the socket. Use
  //      Z_SYNC_FLUSH after every write.
  //   5. The callback `cb(null, info)` fires AFTER the emit, so the caller's
  //      pipeline wiring is in place before any subsequent command runs.
  //
  // Pattern the caller writes (client mode, raw TCP):
  //
  //   session.on('compress', () => {
  //     const inflate = zlib.createInflateRaw();
  //     const deflate = zlib.createDeflateRaw({ flush: zlib.constants.Z_SYNC_FLUSH });
  //     socket.removeAllListeners('data');
  //     socket.on('data',   chunk => inflate.write(chunk));
  //     inflate.on('data',  chunk => session.feed(chunk));
  //     session.removeAllListeners('send');
  //     session.on('send',  data => { deflate.write(data); deflate.flush(zlib.constants.Z_SYNC_FLUSH); });
  //     deflate.on('data',  chunk => socket.write(chunk));
  //   });
  //
  //   session.compress(err => { /* now talking compressed */ });
  function clientCompress(cb) {
    if (context.compressed) {
      if (cb) cb(new Error('Already compressed'));
      return;
    }
    clientSend('COMPRESS', [{ type: TOK.ATOM, value: 'DEFLATE' }], function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('COMPRESS rejected: ' + info.text));
      context.compressed = true;
      // Emit BEFORE firing the callback so the caller's listener has swapped
      // its pipelines by the time cb runs and the next command is sent.
      ev.emit('compress');
      if (cb) cb(null, info);
    });
  }

  // Parse "* LIST (\HasChildren \Sent) "/" "INBOX"" into a folder object
  // suitable for the developer. Returns null if the untagged response isn't LIST/LSUB.
  function parseListUntagged(resp) {
    if (!resp.data || resp.data.length < 4) return null;
    let kind = String(resp.data[0].value || '').toUpperCase();
    if (kind !== 'LIST' && kind !== 'LSUB') return null;

    let attrsTok = resp.data[1];   // list of backslash-attrs
    let delimTok = resp.data[2];   // quoted delimiter or NIL
    let nameTok  = resp.data[3];

    let attrs = [];
    if (attrsTok && attrsTok.type === TOK.LIST) {
      for (let i = 0; i < attrsTok.value.length; i++) {
        attrs.push(String(attrsTok.value[i].value || ''));
      }
    }

    let delimiter = null;
    if (delimTok && delimTok.type !== TOK.NIL) {
      delimiter = String(delimTok.value || '');
    }

    let name;
    if (nameTok && nameTok.type === TOK.LITERAL) name = u8ToStr(nameTok.value);
    else name = String(nameTok ? (nameTok.value || '') : '');

    // Derive specialUse from attributes (for developer convenience)
    let specialUse = null;
    for (let i = 0; i < attrs.length; i++) {
      let canon = normalizeSpecialUse(attrs[i]);
      if (canon) { specialUse = canon; break; }
    }

    return {
      name: name,
      delimiter: delimiter,
      attributes: attrs,
      specialUse: specialUse,
      hasChildren: attrs.indexOf('\\HasChildren') >= 0
    };
  }

  // Parse "* 42 EXISTS" / "* 3 RECENT" / status response codes from SELECT
  function parseSelectUntagged(info, resp) {
    if (!resp.data || resp.data.length < 1) return;

    // "* N EXISTS" / "* N RECENT"
    let first = resp.data[0];
    if (first.type === TOK.NUMBER && resp.data[1]) {
      let kind = String(resp.data[1].value || '').toUpperCase();
      if (kind === 'EXISTS') info.exists = first.value;
      else if (kind === 'RECENT') info.recent = first.value;
      return;
    }

    // "* FLAGS (...)"
    if (first.type === TOK.ATOM && String(first.value).toUpperCase() === 'FLAGS') {
      if (resp.data[1] && resp.data[1].type === TOK.LIST) {
        info.flags = resp.data[1].value.map(function(t) { return normalizeFlag(t.value); });
      }
      return;
    }

    // "* OK [UIDVALIDITY 123] ..." / "* OK [UIDNEXT 5] ..." / "* OK [UNSEEN 12] ..." /
    // "* OK [PERMANENTFLAGS (...)] ..." / "* OK [READ-WRITE] ..." / [READ-ONLY]
    if (String(first.value).toUpperCase() === 'OK') {
      for (let i = 1; i < resp.data.length; i++) {
        if (resp.data[i].type === 'respcode') {
          parseRespCode(info, resp.data[i].value);
          break;
        }
      }
    }
  }

  function parseRespCode(info, code) {
    let m;
    if ((m = /^UIDVALIDITY\s+(\d+)/i.exec(code)))  info.uidValidity = parseInt(m[1], 10);
    else if ((m = /^UIDNEXT\s+(\d+)/i.exec(code))) info.uidNext = parseInt(m[1], 10);
    else if ((m = /^UNSEEN\s+(\d+)/i.exec(code)))  info.unseen = parseInt(m[1], 10);
    else if (/^READ-ONLY/i.test(code))             info.readOnly = true;
    else if (/^READ-WRITE/i.test(code))            info.readOnly = false;
    else if ((m = /^PERMANENTFLAGS\s+\((.*)\)/i.exec(code))) {
      info.permanentFlags = m[1].trim().split(/\s+/).filter(Boolean).map(normalizeFlag);
    }
    // RFC 7162 CONDSTORE
    else if ((m = /^HIGHESTMODSEQ\s+(\d+)/i.exec(code))) info.highestModseq = parseInt(m[1], 10);
    else if (/^NOMODSEQ/i.test(code))                    info.noModseq = true;
  }

  // --- Client commands for Phase 2 ---
  function clientList(reference, pattern, cb) {
    clientSend('LIST', [reference || '', pattern || '*'], function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('LIST failed: ' + info.text));
      let folders = [];
      for (let i = 0; i < info.untagged.length; i++) {
        let f = parseListUntagged(info.untagged[i]);
        if (f) folders.push(f);
      }
      if (cb) cb(null, { folders: folders });
    });
  }

  // LIST-EXTENDED (RFC 5258) — selection + return options. Signature:
  //
  //   client.listExtended({
  //     reference: '',                         // default ''
  //     patterns:  ['*']  or '*',              // single or multiple
  //     selection: { subscribed, remote, recursiveMatch },
  //     return:    { children, subscribed, specialUse, status: ['MESSAGES','UNSEEN'] }
  //   }, cb)
  //
  // Callback receives { folders, statuses }.
  //   folders = same shape as clientList
  //   statuses = { <folderName>: { messages, uidnext, uidvalidity, unseen, ... } }
  //              when RETURN (STATUS ...) was requested.
  function clientListExtended(opts, cb) {
    opts = opts || {};

    let args = [];
    // Selection options
    let selTok = [];
    if (opts.selection) {
      if (opts.selection.subscribed)     selTok.push({ type: TOK.ATOM, value: 'SUBSCRIBED' });
      if (opts.selection.remote)         selTok.push({ type: TOK.ATOM, value: 'REMOTE' });
      if (opts.selection.recursiveMatch) selTok.push({ type: TOK.ATOM, value: 'RECURSIVEMATCH' });
    }
    args.push({ type: TOK.LIST, value: selTok });

    // Reference
    args.push({ type: TOK.QUOTED, value: opts.reference || '' });

    // Patterns — single atom or a list
    let patterns = opts.patterns || '*';
    if (!Array.isArray(patterns)) patterns = [patterns];
    if (patterns.length === 1) {
      args.push({ type: TOK.QUOTED, value: patterns[0] });
    } else {
      args.push({ type: TOK.LIST,
        value: patterns.map(function(p) { return { type: TOK.QUOTED, value: p }; })
      });
    }

    // RETURN clause
    if (opts.return) {
      args.push({ type: TOK.ATOM, value: 'RETURN' });
      let retTok = [];
      if (opts.return.children)   retTok.push({ type: TOK.ATOM, value: 'CHILDREN' });
      if (opts.return.subscribed) retTok.push({ type: TOK.ATOM, value: 'SUBSCRIBED' });
      if (opts.return.specialUse) retTok.push({ type: TOK.ATOM, value: 'SPECIAL-USE' });
      if (opts.return.status && opts.return.status.length > 0) {
        retTok.push({ type: TOK.ATOM, value: 'STATUS' });
        retTok.push({ type: TOK.LIST,
          value: opts.return.status.map(function(s) { return { type: TOK.ATOM, value: String(s).toUpperCase() }; })
        });
      }
      args.push({ type: TOK.LIST, value: retTok });
    }

    clientSend('LIST', args, function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('LIST failed: ' + info.text));
      let folders  = [];
      let statuses = {};
      for (let i = 0; i < info.untagged.length; i++) {
        let r = info.untagged[i];
        let f = parseListUntagged(r);
        if (f) { folders.push(f); continue; }
        // Also match "* STATUS <mailbox> (<items>)" responses
        if (r.data && r.data.length >= 3 &&
            String(r.data[0].value || '').toUpperCase() === 'STATUS') {
          let name = tokenString(r.data[1]);
          let listTok = r.data[2];
          if (name != null && listTok && listTok.type === TOK.LIST) {
            let stats = {};
            let items = listTok.value;
            for (let j = 0; j + 1 < items.length; j += 2) {
              let k = String(items[j].value || '').toUpperCase();
              let v = items[j + 1].value;
              if (k === 'MESSAGES')      stats.messages      = v;
              else if (k === 'UIDNEXT')  stats.uidnext       = v;
              else if (k === 'UIDVALIDITY') stats.uidvalidity = v;
              else if (k === 'UNSEEN')   stats.unseen        = v;
              else if (k === 'RECENT')   stats.recent        = v;
              else if (k === 'HIGHESTMODSEQ') stats.highestmodseq = v;
            }
            statuses[name] = stats;
          }
        }
      }
      if (cb) cb(null, { folders: folders, statuses: statuses });
    });
  }

  function clientLsub(reference, pattern, cb) {
    clientSend('LSUB', [reference || '', pattern || '*'], function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('LSUB failed: ' + info.text));
      let folders = [];
      for (let i = 0; i < info.untagged.length; i++) {
        let f = parseListUntagged(info.untagged[i]);
        if (f) folders.push(f);
      }
      if (cb) cb(null, { folders: folders });
    });
  }

  function clientSelect(name, options, cb) {
    if (typeof options === 'function') { cb = options; options = null; }
    clientDoSelect('SELECT', name, options, cb);
  }
  function clientExamine(name, options, cb) {
    if (typeof options === 'function') { cb = options; options = null; }
    clientDoSelect('EXAMINE', name, options, cb);
  }

  function clientDoSelect(cmd, name, options, cb) {
    let args = [{ type: TOK.ATOM, value: String(name) }];

    // Optional parameter list: (CONDSTORE) or (QRESYNC (...))
    if (options) {
      let paramList = [];
      if (options.condstore) {
        paramList.push({ type: TOK.ATOM, value: 'CONDSTORE' });
      }
      if (options.qresync) {
        let q = options.qresync;
        // Build (QRESYNC (uidvalidity lastModseq [knownUids]))
        let qlist = [
          { type: TOK.NUMBER, value: q.uidValidity },
          { type: TOK.NUMBER, value: q.lastKnownModseq }
        ];
        if (q.knownUids) {
          // Accept flat ranges or a string
          let str = Array.isArray(q.knownUids) ? formatRanges(q.knownUids) : String(q.knownUids);
          qlist.push({ type: TOK.ATOM, value: str });
        }
        paramList.push({ type: TOK.ATOM, value: 'QRESYNC' });
        paramList.push({ type: TOK.LIST, value: qlist });
      }
      if (paramList.length > 0) {
        args.push({ type: TOK.LIST, value: paramList });
      }
    }

    clientSend(cmd, args, function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error(cmd + ' failed: ' + info.text));

      // Collect all the SELECT response pieces from untagged + resp code
      let sel = { name: name };
      let vanishedRanges = [];
      let changedMessages = [];
      for (let i = 0; i < info.untagged.length; i++) {
        let u = info.untagged[i];
        parseSelectUntagged(sel, u);
        // RFC 7162: VANISHED (EARLIER) responses during SELECT resync
        let v = parseVanishedUntagged(u);
        if (v) vanishedRanges = mergeFlatRanges(vanishedRanges, v.ranges);
        // FETCH responses during SELECT (QRESYNC changed messages)
        let f = parseFetchUntagged(u);
        if (f) changedMessages.push(f);
      }
      if (info.code) parseRespCode(sel, info.code);

      // Attach resync data only if QRESYNC was requested
      if (options && options.qresync) {
        sel.vanishedUids = vanishedRanges;   // flat half-open
        sel.changedMessages = changedMessages;
      }

      // Update client state
      context.state                    = STATE.SELECTED;
      context.currentFolder            = name;
      context.currentFolderReadOnly    = !!sel.readOnly;
      context.currentFolderUidValidity = sel.uidValidity || null;
      context.currentFolderTotal       = sel.exists || 0;
      if (options && (options.condstore || options.qresync)) {
        context.condstoreEnabled = true;
        if (options.qresync) context.qresyncEnabled = true;
      }

      if (cb) cb(null, sel);
    });
  }

  // Parse an untagged "VANISHED [(EARLIER)] <seq-set>" response.
  // Returns {earlier: bool, ranges: flat half-open} or null.
  function parseVanishedUntagged(resp) {
    if (!resp.data || !resp.data[0]) return null;
    if (String(resp.data[0].value || '').toUpperCase() !== 'VANISHED') return null;

    let earlier = false;
    let setIdx = 1;
    if (resp.data.length >= 2 && resp.data[1].type === TOK.LIST) {
      // Check if it's (EARLIER)
      let first = resp.data[1].value[0];
      if (first && first.type === TOK.ATOM && String(first.value).toUpperCase() === 'EARLIER') {
        earlier = true;
        setIdx = 2;
      }
    }
    if (setIdx >= resp.data.length) return null;

    let setStr = String(resp.data[setIdx].value || '');
    let parsed = parseSequenceSet(setStr, {});
    if (parsed.error) return null;
    return { earlier: earlier, ranges: parsed.ranges };
  }

  // Merge two flat-range arrays using flatRanges.add
  function mergeFlatRanges(a, b) {
    if (!a || a.length === 0) return b || [];
    if (!b || b.length === 0) return a;
    let out = a.slice();
    for (let i = 0; i < b.length; i += 2) {
      flatRanges.add(out, [b[i], b[i + 1]]);
    }
    return out;
  }

  function clientCreate(name, cb) {
    clientSend('CREATE', [name], function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('CREATE failed: ' + info.text));
      if (cb) cb(null, info);
    });
  }

  function clientDelete(name, cb) {
    clientSend('DELETE', [name], function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('DELETE failed: ' + info.text));
      if (cb) cb(null, info);
    });
  }

  function clientRename(oldName, newName, cb) {
    clientSend('RENAME', [oldName, newName], function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('RENAME failed: ' + info.text));
      if (cb) cb(null, info);
    });
  }

  function clientSubscribe(name, cb) {
    clientSend('SUBSCRIBE', [name], function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('SUBSCRIBE failed: ' + info.text));
      if (cb) cb(null, info);
    });
  }

  function clientUnsubscribe(name, cb) {
    clientSend('UNSUBSCRIBE', [name], function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('UNSUBSCRIBE failed: ' + info.text));
      if (cb) cb(null, info);
    });
  }

  function clientStatus(name, items, cb) {
    items = items || ['MESSAGES', 'UIDNEXT', 'UIDVALIDITY', 'UNSEEN'];
    let itemList = items.map(function(s) { return { type: TOK.ATOM, value: String(s).toUpperCase() }; });
    clientSend('STATUS', [name, { type: TOK.LIST, value: itemList }], function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('STATUS failed: ' + info.text));

      // Find untagged STATUS response
      let statusInfo = { name: name };
      for (let i = 0; i < info.untagged.length; i++) {
        let r = info.untagged[i];
        if (r.data && r.data[0] && String(r.data[0].value).toUpperCase() === 'STATUS') {
          // "* STATUS mbox (MESSAGES 10 UIDNEXT 11)"
          // r.data[1] = mbox, r.data[2] = list of (key value key value ...)
          let listTok = r.data[2];
          if (listTok && listTok.type === TOK.LIST) {
            for (let j = 0; j + 1 < listTok.value.length; j += 2) {
              let key = String(listTok.value[j].value || '').toUpperCase();
              let val = listTok.value[j + 1].value;
              if      (key === 'MESSAGES')    statusInfo.messages    = val;
              else if (key === 'RECENT')      statusInfo.recent      = val;
              else if (key === 'UIDNEXT')     statusInfo.uidNext     = val;
              else if (key === 'UIDVALIDITY') statusInfo.uidValidity = val;
              else if (key === 'UNSEEN')      statusInfo.unseen      = val;
            }
          }
          break;
        }
      }
      if (cb) cb(null, statusInfo);
    });
  }

  function clientClose(cb) {
    clientSend('CLOSE', [], function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('CLOSE failed: ' + info.text));
      // Exit SELECTED on the client side too
      context.state = STATE.AUTHENTICATED;
      context.currentFolder = null;
      context.currentFolderReadOnly = false;
      context.currentFolderUidValidity = null;
      context.currentFolderTotal = 0;
      if (cb) cb(null, info);
    });
  }

  function clientUnselect(cb) {
    clientSend('UNSELECT', [], function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('UNSELECT failed: ' + info.text));
      context.state = STATE.AUTHENTICATED;
      context.currentFolder = null;
      context.currentFolderReadOnly = false;
      context.currentFolderUidValidity = null;
      context.currentFolderTotal = 0;
      if (cb) cb(null, info);
    });
  }

  // Parse an untagged FETCH response into a structured object.
  // "* 42 FETCH (UID 1337 FLAGS (\Seen) RFC822.SIZE 2048 RFC822.HEADER {50}\r\n<bytes>)"
  function parseFetchUntagged(resp) {
    if (!resp.data || resp.data.length < 3) return null;
    if (resp.data[0].type !== TOK.NUMBER) return null;
    if (String(resp.data[1].value || '').toUpperCase() !== 'FETCH') return null;
    if (resp.data[2].type !== TOK.LIST) return null;

    let out = { seq: resp.data[0].value };
    let items = resp.data[2].value;
    for (let i = 0; i + 1 < items.length; i += 2) {
      let keyTok = items[i];
      let key = String(keyTok.value || '').toUpperCase();
      let val = items[i + 1];

      if      (key === 'UID')          out.uid = val.value;
      else if (key === 'RFC822.SIZE')  out.size = val.value;
      else if (key === 'INTERNALDATE') out.internalDate = parseInternalDate(val.value);
      else if (key === 'FLAGS') {
        out.flags = [];
        if (val.type === TOK.LIST) {
          for (let j = 0; j < val.value.length; j++) {
            out.flags.push(normalizeFlag(val.value[j].value));
          }
        }
      }
      else if (key === 'RFC822' || key === 'RFC822.HEADER' || key === 'RFC822.TEXT') {
        let bytes = fetchValueToBuffer(val);
        if      (key === 'RFC822')        out.body    = bytes;
        else if (key === 'RFC822.HEADER') out.headers = bytes;
        else if (key === 'RFC822.TEXT')   out.text    = bytes;
      }
      else if (key === 'BODY' && keyTok.section !== undefined) {
        // BODY[...] section response — store in a sections map keyed by the exact
        // response name (e.g. "BODY[HEADER]", "BODY[1.TEXT]<0>", "BODY[HEADER.FIELDS (FROM)]").
        let responseName = 'BODY[' + keyTok.section + ']';
        if (keyTok.partial) responseName += '<' + keyTok.partial.offset + '>';
        if (!out.sections) out.sections = {};
        out.sections[responseName] = fetchValueToBuffer(val);
        // Common convenience aliases: the most-used sections also populate flat fields
        if (keyTok.section === '')        out.body    = fetchValueToBuffer(val);
        else if (keyTok.section === 'HEADER') out.headers = fetchValueToBuffer(val);
        else if (keyTok.section === 'TEXT')   out.text    = fetchValueToBuffer(val);
      }
      else if (key === 'BODY' && keyTok.section === undefined) {
        // Plain "BODY" (no brackets) = non-extended BODYSTRUCTURE
        out.bodyStructure = parseBodyStructureTokens(val);
      }
      else if (key === 'BODYSTRUCTURE') {
        out.bodyStructure = parseBodyStructureTokens(val);
      }
      else if (key === 'ENVELOPE') {
        out.envelope = parseEnvelopeTokens(val);
      }
      // RFC 7162 CONDSTORE: MODSEQ comes wrapped in parens as "MODSEQ (12345)"
      else if (key === 'MODSEQ') {
        if (val.type === TOK.LIST && val.value.length >= 1 && val.value[0].type === TOK.NUMBER) {
          out.modseq = val.value[0].value;
        } else if (val.type === TOK.NUMBER) {
          out.modseq = val.value;  // lenient: accept bare number
        }
      }
    }
    return out;
  }

  // ---- Helpers for parsing server-built tokens back into clean JS objects ----

  function tokenString(tok) {
    if (!tok || tok.type === TOK.NIL) return null;
    if (tok.type === TOK.LITERAL)     return u8ToStr(tok.value);
    return tok.value !== undefined ? String(tok.value) : null;
  }

  function parseAddressTokens(listTok) {
    if (!listTok || listTok.type === TOK.NIL) return null;
    if (listTok.type !== TOK.LIST) return null;
    let out = [];
    for (let i = 0; i < listTok.value.length; i++) {
      let a = listTok.value[i];
      if (!a || a.type !== TOK.LIST || a.value.length < 4) continue;
      out.push({
        name:    tokenString(a.value[0]),
        adl:     tokenString(a.value[1]),
        mailbox: tokenString(a.value[2]),
        host:    tokenString(a.value[3])
      });
    }
    return out;
  }

  function parseEnvelopeTokens(list) {
    if (!list || list.type !== TOK.LIST || list.value.length < 10) return null;
    return {
      date:      tokenString(list.value[0]),
      subject:   tokenString(list.value[1]),
      from:      parseAddressTokens(list.value[2]),
      sender:    parseAddressTokens(list.value[3]),
      replyTo:   parseAddressTokens(list.value[4]),
      to:        parseAddressTokens(list.value[5]),
      cc:        parseAddressTokens(list.value[6]),
      bcc:       parseAddressTokens(list.value[7]),
      inReplyTo: tokenString(list.value[8]),
      messageId: tokenString(list.value[9])
    };
  }

  function parseParamsTokens(tok) {
    if (!tok || tok.type === TOK.NIL) return {};
    if (tok.type !== TOK.LIST) return {};
    let out = {};
    for (let i = 0; i + 1 < tok.value.length; i += 2) {
      let k = tokenString(tok.value[i]);
      let v = tokenString(tok.value[i + 1]);
      if (k !== null && v !== null) out[k.toLowerCase()] = v;
    }
    return out;
  }

  // Parse a BODYSTRUCTURE token tree into a simplified JS object.
  // Detects multipart (first element is itself a list) vs single-part.
  function parseBodyStructureTokens(tok) {
    if (!tok || tok.type === TOK.NIL) return null;
    if (tok.type !== TOK.LIST || tok.value.length === 0) return null;

    // Multipart — first element is a sub-list (a child body-structure)
    if (tok.value[0].type === TOK.LIST) {
      let parts = [];
      let subtype = null;
      for (let i = 0; i < tok.value.length; i++) {
        let el = tok.value[i];
        if (el.type === TOK.LIST) parts.push(parseBodyStructureTokens(el));
        else { subtype = tokenString(el); break; }
      }
      return {
        type: 'multipart/' + (subtype ? subtype.toLowerCase() : 'mixed'),
        parts: parts
      };
    }

    // Single part: first two elements are type/subtype strings
    let type    = tokenString(tok.value[0]) || 'text';
    let subtype = tokenString(tok.value[1]) || 'plain';
    let result = {
      type:        type.toLowerCase() + '/' + subtype.toLowerCase(),
      params:      parseParamsTokens(tok.value[2]),
      id:          tokenString(tok.value[3]),
      description: tokenString(tok.value[4]),
      encoding:    tokenString(tok.value[5]),
      size:        tok.value[6] && tok.value[6].type === TOK.NUMBER ? tok.value[6].value : 0
    };

    // Type-specific extras
    let idx = 7;
    let typeLow = type.toLowerCase();
    let subLow = subtype.toLowerCase();
    if (typeLow === 'text') {
      result.lines = tok.value[idx] && tok.value[idx].type === TOK.NUMBER ? tok.value[idx].value : 0;
      idx++;
    } else if (typeLow === 'message' && subLow === 'rfc822') {
      result.envelope      = parseEnvelopeTokens(tok.value[idx]);
      result.bodyStructure = parseBodyStructureTokens(tok.value[idx + 1]);
      result.lines         = tok.value[idx + 2] && tok.value[idx + 2].type === TOK.NUMBER ? tok.value[idx + 2].value : 0;
      idx += 3;
    }

    // Optional extension data (BODYSTRUCTURE only — BODY doesn't include it)
    if (idx < tok.value.length) result.md5         = tokenString(tok.value[idx++]);
    if (idx < tok.value.length) {
      let d = tok.value[idx++];
      if (d && d.type === TOK.LIST && d.value.length >= 2) {
        result.disposition       = tokenString(d.value[0]);
        result.dispositionParams = parseParamsTokens(d.value[1]);
      }
    }
    if (idx < tok.value.length) result.language = tokenString(tok.value[idx++]);
    if (idx < tok.value.length) result.location = tokenString(tok.value[idx++]);

    return result;
  }

  // Convert a FETCH item value token (literal or quoted) to a Buffer.
  function fetchValueToBuffer(val) {
    if (!val) return Buffer.alloc(0);
    if (val.type === TOK.LITERAL) return Buffer.from(val.value);
    if (val.type === TOK.QUOTED)  return Buffer.from(String(val.value), 'utf-8');
    if (val.type === TOK.NIL)     return Buffer.alloc(0);
    return Buffer.alloc(0);
  }

  // --- Client FETCH / STORE / COPY + UID variants ---
  function clientFetch(seqSet, items, options, cb) {
    if (typeof options === 'function') { cb = options; options = null; }
    clientDoFetch(false, seqSet, items, options, cb);
  }
  function clientUidFetch(seqSet, items, options, cb) {
    if (typeof options === 'function') { cb = options; options = null; }
    clientDoFetch(true, seqSet, items, options, cb);
  }

  function clientDoFetch(byUid, seqSet, items, options, cb) {
    // items: string or array; we build a list of atoms
    let itemArg;
    if (Array.isArray(items)) {
      itemArg = { type: TOK.LIST, value: items.map(function(s) { return { type: TOK.ATOM, value: String(s).toUpperCase() }; }) };
    } else {
      itemArg = { type: TOK.ATOM, value: String(items).toUpperCase() };
    }
    let cmd  = byUid ? 'UID' : 'FETCH';
    let args = byUid ? [{ type: TOK.ATOM, value: 'FETCH' }, { type: TOK.ATOM, value: String(seqSet) }, itemArg]
                     : [{ type: TOK.ATOM, value: String(seqSet) }, itemArg];

    // RFC 7162: modifier list — (CHANGEDSINCE <modseq>) and/or (VANISHED)
    if (options && (options.changedSince != null || options.vanished)) {
      let modList = [];
      if (options.changedSince != null) {
        modList.push({ type: TOK.ATOM, value: 'CHANGEDSINCE' });
        modList.push({ type: TOK.NUMBER, value: options.changedSince });
      }
      if (options.vanished) {
        modList.push({ type: TOK.ATOM, value: 'VANISHED' });
      }
      args.push({ type: TOK.LIST, value: modList });
    }

    clientSend(cmd, args, function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('FETCH failed: ' + info.text));
      let messages = [];
      let vanishedRanges = [];
      for (let i = 0; i < info.untagged.length; i++) {
        let f = parseFetchUntagged(info.untagged[i]);
        if (f) { messages.push(f); continue; }
        let v = parseVanishedUntagged(info.untagged[i]);
        if (v) vanishedRanges = mergeFlatRanges(vanishedRanges, v.ranges);
      }
      let result = { messages: messages };
      if (vanishedRanges.length > 0) result.vanishedUids = vanishedRanges;
      if (cb) cb(null, result);
    });
  }

  function clientStore(seqSet, mode, flags, options, cb) {
    if (typeof options === 'function') { cb = options; options = null; }
    clientDoStore(false, seqSet, mode, flags, options, cb);
  }
  function clientUidStore(seqSet, mode, flags, options, cb) {
    if (typeof options === 'function') { cb = options; options = null; }
    clientDoStore(true, seqSet, mode, flags, options, cb);
  }

  function clientDoStore(byUid, seqSet, mode, flags, options, cb) {
    // mode: 'set' | 'add' | 'remove'
    let op = 'FLAGS';
    if (mode === 'add') op = '+FLAGS';
    else if (mode === 'remove') op = '-FLAGS';
    let flagList = { type: TOK.LIST,
      value: (flags || []).map(function(f) { return { type: TOK.ATOM, value: serializeFlag(f) }; })
    };
    let cmd  = byUid ? 'UID' : 'STORE';

    let args;
    if (byUid) {
      args = [{ type: TOK.ATOM, value: 'STORE' }, { type: TOK.ATOM, value: String(seqSet) }];
    } else {
      args = [{ type: TOK.ATOM, value: String(seqSet) }];
    }

    // RFC 7162: (UNCHANGEDSINCE <modseq>) modifier — goes BEFORE the operation atom
    if (options && options.unchangedSince != null) {
      args.push({
        type: TOK.LIST,
        value: [
          { type: TOK.ATOM, value: 'UNCHANGEDSINCE' },
          { type: TOK.NUMBER, value: options.unchangedSince }
        ]
      });
    }

    args.push({ type: TOK.ATOM, value: op });
    args.push(flagList);

    clientSend(cmd, args, function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('STORE failed: ' + info.text));

      let messages = [];
      for (let i = 0; i < info.untagged.length; i++) {
        let f = parseFetchUntagged(info.untagged[i]);
        if (f) messages.push(f);
      }
      let result = { messages: messages };

      // RFC 7162 §3.2: [MODIFIED <uidlist>] response code lists UIDs rejected
      // by UNCHANGEDSINCE.
      if (info.code) {
        let m = /^MODIFIED\s+(\S+)/i.exec(String(info.code).trim());
        if (m) result.modified = expandSeqSet(m[1]);
      }
      if (cb) cb(null, result);
    });
  }

  function clientCopy(seqSet, dst, options, cb) {
    if (typeof options === 'function') { cb = options; options = null; }
    clientDoCopy(false, seqSet, dst, options, cb);
  }
  function clientUidCopy(seqSet, dst, options, cb) {
    if (typeof options === 'function') { cb = options; options = null; }
    clientDoCopy(true, seqSet, dst, options, cb);
  }

  function clientDoCopy(byUid, seqSet, dst, options, cb) {
    let cmd  = byUid ? 'UID' : 'COPY';
    let args = byUid
      ? [{ type: TOK.ATOM, value: 'COPY' }, { type: TOK.ATOM, value: String(seqSet) }, dst]
      : [{ type: TOK.ATOM, value: String(seqSet) }, dst];
    clientSend(cmd, args, function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('COPY failed: ' + info.text));
      // RFC 4315 COPYUID from tagged OK's response code
      let result = {};
      let cu = parseCopyUidCode(info.code);
      if (cu) { result.dstUidValidity = cu.dstUidValidity; result.mapping = cu.mapping; }
      if (cb) cb(null, result);
    });
  }

  // Parse a "COPYUID <uidValidity> <srcSet> <dstSet>" response code into a structured
  // {dstUidValidity, mapping} object. Returns null if the code isn't COPYUID.
  function parseCopyUidCode(code) {
    if (!code) return null;
    let m = /^COPYUID\s+(\d+)\s+(\S+)\s+(\S+)$/i.exec(String(code).trim());
    if (!m) return null;

    let srcUids = expandSeqSet(m[2]);
    let dstUids = expandSeqSet(m[3]);
    let n = Math.min(srcUids.length, dstUids.length);
    let mapping = [];
    for (let i = 0; i < n; i++) {
      mapping.push({ srcUid: srcUids[i], dstUid: dstUids[i] });
    }
    return { dstUidValidity: parseInt(m[1], 10), mapping: mapping };
  }

  // Expand an IMAP sequence-set string into an array of individual integers,
  // preserving the exact order as written on the wire. Does NOT sort or merge.
  //
  // Used by parseCopyUidCode to recover positional UID mapping, where
  // "503,501:502" must yield [503, 501, 502] — not [501, 502, 503].
  function expandSeqSet(str) {
    if (!str) return [];
    let out = [];
    let parts = String(str).split(',');
    for (let i = 0; i < parts.length; i++) {
      let p = parts[i].trim();
      if (!p) continue;
      let colon = p.indexOf(':');
      if (colon < 0) {
        let n = parseInt(p, 10);
        if (!isNaN(n)) out.push(n);
      } else {
        let a = parseInt(p.slice(0, colon), 10);
        let b = parseInt(p.slice(colon + 1), 10);
        if (isNaN(a) || isNaN(b)) continue;
        // "5:1" is equivalent to "1:5" per RFC 3501 §9, but for COPYUID the
        // server always emits forward ranges, so we iterate in natural order.
        let lo = a < b ? a : b;
        let hi = a < b ? b : a;
        for (let n = lo; n <= hi; n++) out.push(n);
      }
    }
    return out;
  }

  // --- SEARCH / UID SEARCH ---
  function clientSearch(criteria, cb)    { clientDoSearch(false, criteria, cb); }
  function clientUidSearch(criteria, cb) { clientDoSearch(true,  criteria, cb); }

  function clientDoSearch(byUid, criteria, cb) {
    if (!criteria || typeof criteria !== 'object') {
      if (cb) cb(new Error('criteria must be an object (tree or flat)'));
      return;
    }

    let bodyArgs = buildSearchArgs(criteria);
    if (!bodyArgs || bodyArgs.length === 0) {
      if (cb) cb(new Error('No valid criteria'));
      return;
    }

    let cmd  = byUid ? 'UID' : 'SEARCH';
    let args = byUid
      ? [{ type: TOK.ATOM, value: 'SEARCH' }].concat(bodyArgs)
      : bodyArgs;

    clientSend(cmd, args, function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('SEARCH failed: ' + info.text));

      // Collect numbers and optional (MODSEQ N) from "* SEARCH N1 N2 ... (MODSEQ M)"
      let numbers = [];
      let modseq = null;
      for (let i = 0; i < info.untagged.length; i++) {
        let r = info.untagged[i];
        if (!r.data || !r.data[0]) continue;
        if (String(r.data[0].value || '').toUpperCase() !== 'SEARCH') continue;
        for (let j = 1; j < r.data.length; j++) {
          let tok = r.data[j];
          if (tok.type === TOK.NUMBER) {
            numbers.push(tok.value);
          } else if (tok.type === TOK.LIST && tok.value.length >= 2 &&
                     tok.value[0].type === TOK.ATOM &&
                     String(tok.value[0].value).toUpperCase() === 'MODSEQ' &&
                     tok.value[1].type === TOK.NUMBER) {
            modseq = tok.value[1].value;
          }
        }
      }
      let result = { numbers: numbers };
      if (modseq != null) result.modseq = modseq;
      if (cb) cb(null, result);
    });
  }

  // Convert a criteria object (tree or flat) into IMAP argument tokens.
  // Tree form:  { op: 'and', children: [...] } / { op: 'or', ... } / { op: 'not', child } / leaf ops
  // Flat form:  { from: 'boss', subject: 'urgent', seen: true, since: <Date>, ... }  → AND of items
  function buildSearchArgs(obj) {
    if (obj.op) return treeToSearchArgs(obj);
    return flatToSearchArgs(obj);
  }

  function flatToSearchArgs(obj) {
    let args = [];
    let keys = Object.keys(obj);
    for (let i = 0; i < keys.length; i++) {
      let k = keys[i];
      let v = obj[k];
      let node = flatEntryToNode(k, v);
      if (node) args.push.apply(args, treeToSearchArgs(node));
    }
    return args;
  }

  function flatEntryToNode(key, val) {
    let k = key.toLowerCase();
    // Boolean shorthand for flag predicates
    let flagOps = { seen:1, answered:1, flagged:1, deleted:1, draft:1, recent:1, new:1, old:1, all:1 };
    if (flagOps[k]) {
      if (val === true)  return { op: k };
      if (val === false) return { op: 'not', child: { op: k } };
      return null;
    }
    if (val instanceof Date) return { op: k, date: val };
    if (typeof val === 'number') return { op: k, value: val };
    if (typeof val === 'string') return { op: k, value: val };
    return null;
  }

  function treeToSearchArgs(node) {
    if (!node || !node.op) return [];
    let op = node.op;
    let args = [];

    switch (op) {
      case 'and':
        for (let i = 0; i < node.children.length; i++) {
          args.push.apply(args, treeToSearchArgs(node.children[i]));
        }
        return args;

      case 'or':
        args.push({ type: TOK.ATOM, value: 'OR' });
        args.push.apply(args, treeToSearchArgs(node.children[0]));
        args.push.apply(args, treeToSearchArgs(node.children[1]));
        return args;

      case 'not':
        args.push({ type: TOK.ATOM, value: 'NOT' });
        args.push.apply(args, treeToSearchArgs(node.child));
        return args;

      // Zero-arg flag predicates
      case 'all': case 'answered': case 'deleted': case 'draft':
      case 'flagged': case 'new': case 'old': case 'recent': case 'seen':
        args.push({ type: TOK.ATOM, value: op.toUpperCase() });
        return args;

      // String-arg predicates
      case 'bcc': case 'body': case 'cc': case 'from':
      case 'subject': case 'text': case 'to':
        args.push({ type: TOK.ATOM, value: op.toUpperCase() });
        args.push({ type: TOK.QUOTED, value: String(node.value || '') });
        return args;

      case 'header':
        args.push({ type: TOK.ATOM, value: 'HEADER' });
        args.push({ type: TOK.QUOTED, value: String(node.name || '') });
        args.push({ type: TOK.QUOTED, value: String(node.value || '') });
        return args;

      case 'keyword':
        args.push({ type: TOK.ATOM, value: 'KEYWORD' });
        args.push({ type: TOK.ATOM, value: serializeFlag(node.value) });
        return args;

      // Date predicates
      case 'before': case 'on': case 'since':
      case 'sentBefore': case 'sentOn': case 'sentSince':
        args.push({ type: TOK.ATOM, value: op.replace(/([a-z])([A-Z])/g, '$1$2').toUpperCase() });
        args.push({ type: TOK.ATOM, value: formatSearchDate(node.date) });
        return args;

      // Numeric predicates
      case 'larger': case 'smaller':
        args.push({ type: TOK.ATOM, value: op.toUpperCase() });
        args.push({ type: TOK.NUMBER, value: node.value });
        return args;

      // WITHIN extension (RFC 5032) — YOUNGER / OLDER take a seconds value
      case 'younger': case 'older':
        args.push({ type: TOK.ATOM, value: op.toUpperCase() });
        args.push({ type: TOK.NUMBER, value: node.seconds });
        return args;

      // RFC 7162 CONDSTORE
      case 'modseq':
        args.push({ type: TOK.ATOM, value: 'MODSEQ' });
        args.push({ type: TOK.NUMBER, value: node.value });
        return args;

      // Sequence sets
      case 'uid':
        args.push({ type: TOK.ATOM, value: 'UID' });
        args.push({ type: TOK.ATOM, value: formatRanges(node.ranges) });
        return args;
      case 'seq':
        args.push({ type: TOK.ATOM, value: formatRanges(node.ranges) });
        return args;
    }
    return args;
  }

  // --- SORT / UID SORT (RFC 5256) ---
  //
  //   client.sort([{key:'date', reverse:true}, {key:'subject'}], {from:'boss'}, cb)
  //   client.uidSort([...], criteria, cb)
  //
  // sortCriteria: flat array of {key, reverse?}.
  // criteria:     search criteria (tree or flat form, same as search()).
  function clientSort(sortCriteria, criteria, cb)    { clientDoSort(false, sortCriteria, criteria, cb); }
  function clientUidSort(sortCriteria, criteria, cb) { clientDoSort(true,  sortCriteria, criteria, cb); }

  function clientDoSort(byUid, sortCriteria, criteria, cb) {
    if (!Array.isArray(sortCriteria) || sortCriteria.length === 0) {
      if (cb) cb(new Error('sortCriteria must be a non-empty array'));
      return;
    }

    // Build the (REVERSE KEY ...) token list
    let sortToks = [];
    for (let i = 0; i < sortCriteria.length; i++) {
      let c = sortCriteria[i];
      if (c.reverse) sortToks.push({ type: TOK.ATOM, value: 'REVERSE' });
      sortToks.push({ type: TOK.ATOM, value: String(c.key).toUpperCase() });
    }

    // Build search criteria args (reuses SORT's own args builder from clientDoSearch)
    let searchArgs = criteria ? buildSearchArgs(criteria) : [{ type: TOK.ATOM, value: 'ALL' }];
    if (!searchArgs || searchArgs.length === 0) searchArgs = [{ type: TOK.ATOM, value: 'ALL' }];

    let cmd  = byUid ? 'UID' : 'SORT';
    let args = byUid
      ? [{ type: TOK.ATOM, value: 'SORT' },
         { type: TOK.LIST, value: sortToks },
         { type: TOK.ATOM, value: 'UTF-8' }].concat(searchArgs)
      : [{ type: TOK.LIST, value: sortToks },
         { type: TOK.ATOM, value: 'UTF-8' }].concat(searchArgs);

    clientSend(cmd, args, function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('SORT failed: ' + info.text));
      // Collect numbers from "* SORT N1 N2 ..." untagged
      let numbers = [];
      for (let i = 0; i < info.untagged.length; i++) {
        let r = info.untagged[i];
        if (!r.data || !r.data[0]) continue;
        if (String(r.data[0].value || '').toUpperCase() !== 'SORT') continue;
        for (let j = 1; j < r.data.length; j++) {
          if (r.data[j].type === TOK.NUMBER) numbers.push(r.data[j].value);
        }
      }
      if (cb) cb(null, { numbers: numbers });
    });
  }

  // --- THREAD / UID THREAD (RFC 5256) ---
  //
  //   client.thread('references', {all: true}, cb)
  //   client.uidThread('references', criteria, cb)
  //
  // algorithm: 'references' | 'orderedsubject' (or any server-supported)
  // criteria:  search criteria (tree or flat)
  //
  // cb receives a forest: [{msg, children?}, ...]
  //   — msg is uid (byUid) or seq
  //   — children is array of same shape, or omitted
  function clientThread(algorithm, criteria, cb)    { clientDoThread(false, algorithm, criteria, cb); }
  function clientUidThread(algorithm, criteria, cb) { clientDoThread(true,  algorithm, criteria, cb); }

  function clientDoThread(byUid, algorithm, criteria, cb) {
    if (!algorithm) { if (cb) cb(new Error('algorithm required')); return; }

    let searchArgs = criteria ? buildSearchArgs(criteria) : [{ type: TOK.ATOM, value: 'ALL' }];
    if (!searchArgs || searchArgs.length === 0) searchArgs = [{ type: TOK.ATOM, value: 'ALL' }];

    let cmd  = byUid ? 'UID' : 'THREAD';
    let args = byUid
      ? [{ type: TOK.ATOM, value: 'THREAD' },
         { type: TOK.ATOM, value: String(algorithm).toUpperCase() },
         { type: TOK.ATOM, value: 'UTF-8' }].concat(searchArgs)
      : [{ type: TOK.ATOM, value: String(algorithm).toUpperCase() },
         { type: TOK.ATOM, value: 'UTF-8' }].concat(searchArgs);

    clientSend(cmd, args, function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('THREAD failed: ' + info.text));

      let forest = [];
      for (let i = 0; i < info.untagged.length; i++) {
        let r = info.untagged[i];
        if (!r.data || !r.data[0]) continue;
        if (String(r.data[0].value || '').toUpperCase() !== 'THREAD') continue;
        // r.data[1..N] = each top-level thread group (LIST token)
        for (let j = 1; j < r.data.length; j++) {
          let grp = r.data[j];
          if (grp && grp.type === TOK.LIST) {
            let tree = parseThreadTokens(grp.value);
            if (tree) forest.push(tree);
          }
        }
      }
      if (cb) cb(null, { forest: forest });
    });
  }

  // Parse a single thread group (tokens inside one top-level parenthesized thread)
  // into a tree node.
  //
  // Input tokens for "(3 6 (4 23)(44 7 96))" — the OUTER parens have already been
  // stripped, so we receive [3, 6, LIST[4,23], LIST[44,7,LIST[96]]].
  //
  // Grammar:
  //   a linear sequence of numbers = chain of replies (a→b→c)
  //   when we hit a LIST, each remaining LIST is a branch from the last number
  function parseThreadTokens(tokens) {
    if (!tokens || tokens.length === 0) return null;

    // Walk: collect numbers until we hit a LIST. Chain them linearly.
    let chainNums = [];
    let branches = [];
    let i = 0;
    while (i < tokens.length) {
      let t = tokens[i];
      if (t.type === TOK.NUMBER) {
        chainNums.push(t.value);
        i++;
      } else if (t.type === TOK.LIST) {
        // Every remaining LIST is a branch from the tail of the chain
        while (i < tokens.length && tokens[i].type === TOK.LIST) {
          let b = parseThreadTokens(tokens[i].value);
          if (b) branches.push(b);
          i++;
        }
        break;
      } else {
        i++;  // skip unknown
      }
    }

    if (chainNums.length === 0 && branches.length === 0) return null;

    // Build the linear chain top-down
    let root = { msg: chainNums[0] };
    let tail = root;
    for (let k = 1; k < chainNums.length; k++) {
      let node = { msg: chainNums[k] };
      tail.children = [node];
      tail = node;
    }

    // Attach branches to the tail
    if (branches.length > 0) {
      tail.children = branches;
    }
    return root;
  }

  // --- APPEND ---
  // message: Buffer or string  (raw RFC 5322 bytes)
  // options: { flags: ['Seen'], internalDate: Date }  both optional
  function clientAppend(folder, message, options, cb) {
    if (typeof options === 'function') { cb = options; options = {}; }
    options = options || {};

    let buf = Buffer.isBuffer(message) ? message : Buffer.from(message, 'utf-8');

    let args = [{ type: TOK.ATOM, value: String(folder) }];
    if (options.flags && options.flags.length) {
      let flagToks = options.flags.map(function(f) {
        return { type: TOK.ATOM, value: serializeFlag(f) };
      });
      args.push({ type: TOK.LIST, value: flagToks });
    }
    if (options.internalDate) {
      args.push({ type: TOK.QUOTED, value: formatInternalDate(options.internalDate) });
    }
    args.push({ type: TOK.LITERAL, value: buf });

    clientSend('APPEND', args, function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('APPEND failed: ' + info.text));
      // Parse APPENDUID code if present (RFC 4315)
      let result = {};
      if (info.code) {
        let m = /^APPENDUID\s+(\d+)\s+(\d+)/i.exec(info.code);
        if (m) { result.uidValidity = parseInt(m[1], 10); result.uid = parseInt(m[2], 10); }
      }
      if (cb) cb(null, result);
    });
  }

  // --- EXPUNGE / UID EXPUNGE ---
  function clientExpunge(cb) {
    clientSend('EXPUNGE', [], function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('EXPUNGE failed: ' + info.text));
      if (cb) cb(null, { expunged: extractExpungedSeqs(info.untagged) });
    });
  }

  function clientUidExpunge(seqSet, cb) {
    let args = [
      { type: TOK.ATOM, value: 'EXPUNGE' },
      { type: TOK.ATOM, value: String(seqSet) }
    ];
    clientSend('UID', args, function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('UID EXPUNGE failed: ' + info.text));
      if (cb) cb(null, { expunged: extractExpungedSeqs(info.untagged) });
    });
  }

  function extractExpungedSeqs(untagged) {
    let seqs = [];
    for (let i = 0; i < untagged.length; i++) {
      let r = untagged[i];
      // Format: "* <seq> EXPUNGE" — parsed as [number, atom('EXPUNGE')] in r.data
      if (r.data && r.data.length >= 2 &&
          r.data[0].type === TOK.NUMBER &&
          String(r.data[1].value || '').toUpperCase() === 'EXPUNGE') {
        seqs.push(r.data[0].value);
      }
    }
    return seqs;
  }

  // --- MOVE / UID MOVE ---
  function clientMove(seqSet, dst, options, cb) {
    if (typeof options === 'function') { cb = options; options = null; }
    clientDoMove(false, seqSet, dst, options, cb);
  }
  function clientUidMove(seqSet, dst, options, cb) {
    if (typeof options === 'function') { cb = options; options = null; }
    clientDoMove(true, seqSet, dst, options, cb);
  }

  function clientDoMove(byUid, seqSet, dst, options, cb) {
    let cmd = byUid ? 'UID' : 'MOVE';
    let dstTok = { type: TOK.ATOM, value: String(dst) };
    let args = byUid
      ? [{ type: TOK.ATOM, value: 'MOVE' }, { type: TOK.ATOM, value: String(seqSet) }, dstTok]
      : [{ type: TOK.ATOM, value: String(seqSet) }, dstTok];
    clientSend(cmd, args, function(err, info) {
      if (err) return cb && cb(err);
      if (info.status !== 'OK') return cb && cb(new Error('MOVE failed: ' + info.text));

      let result = { expunged: extractExpungedSeqs(info.untagged) };

      // RFC 6851: COPYUID arrives in an untagged "* OK [COPYUID ...]" before EXPUNGEs
      for (let i = 0; i < info.untagged.length; i++) {
        let u = info.untagged[i];
        if (!u.data) continue;
        if (u.data.length >= 2 &&
            u.data[0].type === TOK.ATOM &&
            String(u.data[0].value).toUpperCase() === 'OK' &&
            u.data[1].type === 'respcode') {
          let cu = parseCopyUidCode(u.data[1].value);
          if (cu) {
            result.dstUidValidity = cu.dstUidValidity;
            result.mapping = cu.mapping;
            break;
          }
        }
      }
      if (cb) cb(null, result);
    });
  }

  // --- IDLE / DONE (RFC 2177) ---
  // Starts an IDLE command. The callback fires when the server sends "+ idling"
  // (confirmation that notifications will stream). Until clientDone() is called,
  // any untagged responses arriving from the server fire the 'untagged' event.
  function clientIdle(cb) {
    if (!context.tagGen) context.tagGen = makeTagGenerator('A');
    if (context.idling) { if (cb) cb(new Error('Already idling')); return; }
    let tag = context.tagGen();
    context.idling     = true;
    context.idleTag    = tag;
    context.idleCb     = cb;
    send(buildCommand(tag, 'IDLE', []));
  }

  // Sends "DONE\r\n" to end IDLE. Callback fires on tagged OK.
  function clientDone(cb) {
    if (!context.idling) { if (cb) cb(new Error('Not idling')); return; }
    context.idleDoneCb = cb;
    send(Buffer.from('DONE\r\n', 'utf-8'));
  }


  // ============================================================
  //  Greet (start the session)
  // ============================================================

  function greet() {
    if (context.isServer) {
      context.state = STATE.NOT_AUTHENTICATED;
      let caps = getCapabilities();
      // RFC 3501 §7.1.4: greeting is "* OK [CAPABILITY ...] ..." or "* PREAUTH" / "* BYE"
      sendUntagged('OK [CAPABILITY ' + caps.join(' ') + '] ' + context.hostname + ' IMAP ready');
    } else {
      // Only transition NEW → GREETING. If banner already arrived and processed
      // (state already past GREETING), greet() becomes a no-op.
      if (context.state === STATE.NEW) {
        context.state = STATE.GREETING;
      }
    }
  }


  // ============================================================
  //  TLS upgrade (transport layer calls this after socket.upgrade completes)
  // ============================================================

  function tlsUpgraded() {
    context.isTLS = true;
    context.advertiseTLS = false;
    context.inputBuf = Buffer.alloc(0);

    if (context.isServer) {
      // RFC 3501 §6.2.1: after STARTTLS, client MUST discard cached capabilities
      // and issue CAPABILITY again. We also reset auth per spec (no session reuse).
      context.authenticated = false;
      context.authUsername = null;
      context.state = STATE.NOT_AUTHENTICATED;
      context.authInProgress = null;
    } else {
      // Client: re-query capabilities, then signal 'ready' again
      context.remoteCaps = null;
      clientCapability(function(err) {
        if (err) { ev.emit('error', err); return; }
        ev.emit('ready');
      });
    }
  }


  // ============================================================
  //  Close
  // ============================================================

  function doClose() {
    if (context.state === STATE.CLOSED) return;
    context.state = STATE.CLOSED;
    context.inputBuf = Buffer.alloc(0);
    context.authInProgress = null;
    context.pendingCommand = null;
    context.awaitingLiteral = false;
    ev.emit('close');
    // Defense-in-depth: release all user-registered handlers so they are
    // eligible for GC immediately, without waiting for the session wrapper
    // itself to become unreachable.
    ev.removeAllListeners();
  }


  // ============================================================
  //  Public feed — the single entry point for incoming bytes
  // ============================================================

  function feed(chunk) {
    if (context.state === STATE.CLOSED) return;
    appendInput(toU8(chunk));
    if (context.isServer) feedServer();
    else feedClient();
  }


  // ============================================================
  //  API
  // ============================================================

  let api = {
    context: context,

    on:  function(name, fn) { ev.on(name, fn); },
    off: function(name, fn) { ev.off(name, fn); },

    /** Feed raw bytes from the transport layer. */
    feed: feed,

    /** Start the session — server sends banner, client waits for banner. */
    greet: greet,

    /** Transport notifies us that TLS upgrade completed. */
    tlsUpgraded: tlsUpgraded,

    /** Close the session. */
    close: doClose,

    // ---- Client-mode methods (no-ops in server mode, but harmless) ----
    capability:  clientCapability,
    enable:      clientEnable,
    namespace:   clientNamespace,
    getQuota:     clientGetQuota,
    getQuotaRoot: clientGetQuotaRoot,
    getMetadata:  clientGetMetadata,
    setMetadata:  clientSetMetadata,
    login:       clientLogin,
    xoauth2:     clientXoauth2,
    logout:      clientLogout,
    startTLS:    clientStartTLS,
    compress:    clientCompress,
    list:         clientList,
    listExtended: clientListExtended,
    lsub:        clientLsub,
    select:      clientSelect,
    examine:     clientExamine,
    create:      clientCreate,
    delete:      clientDelete,
    rename:      clientRename,
    subscribe:   clientSubscribe,
    unsubscribe: clientUnsubscribe,
    status:      clientStatus,
    closeFolder: clientClose,
    unselect:    clientUnselect,
    fetch:       clientFetch,
    uidFetch:    clientUidFetch,
    store:       clientStore,
    uidStore:    clientUidStore,
    copy:        clientCopy,
    uidCopy:     clientUidCopy,
    search:      clientSearch,
    uidSearch:   clientUidSearch,
    sort:        clientSort,
    uidSort:     clientUidSort,
    thread:      clientThread,
    uidThread:   clientUidThread,
    append:      clientAppend,
    expunge:     clientExpunge,
    uidExpunge:  clientUidExpunge,
    move:        clientMove,
    uidMove:     clientUidMove,
    idle:        clientIdle,
    done:        clientDone,

    // ---- Server-side push notifications (no-op when not in SELECTED state) ----
    notifyExists:   notifyExists,
    notifyRecent:   notifyRecent,
    notifyExpunge:  notifyExpunge,
    notifyVanished: notifyVanished,   // RFC 7162 §3.2.10
    notifyFlags:    notifyFlags,

    // ---- Getters ----
    get state()          { return context.state; },
    get isServer()       { return context.isServer; },
    get isTLS()          { return context.isTLS; },
    get authenticated()  { return context.authenticated; },
    get username()       { return context.authUsername; },
    get remoteAddress()  { return context.remoteAddress; },
    get capabilities()   { return context.remoteCaps ? Object.keys(context.remoteCaps).sort() : []; },
    get currentFolder()  { return context.currentFolder; },
    get readOnly()       { return context.currentFolderReadOnly; },
    get idling()         { return context.idling; }
  };

  for (let k in api) {
    if (Object.prototype.hasOwnProperty.call(api, k)) {
      let desc = Object.getOwnPropertyDescriptor(api, k);
      if (desc && (desc.get || desc.set)) {
        Object.defineProperty(this, k, desc);
      } else {
        this[k] = api[k];
      }
    }
  }

  return this;
}


export default IMAPSession;
export {
  IMAPSession,
  STATE,
  SPECIAL_USE,
  FLAGS,
  // Pure helpers — exposed for testing and advanced users
  normalizeSpecialUse,
  normalizeFlag,
  serializeFlag,
  serializeFlagList,
  makeWildcardMatcher,
  hasChildren,
  parseSequenceSet,
  rangesContain,
  compressUids,
  formatInternalDate,
  parseInternalDate,
  parseBodySection,
  buildBodyResponseName,
  parseSearchCriteria,
  parseSearchDate,
  formatSearchDate,

  // Message metadata extraction — developer calls once when storing a message,
  // stores the returned JSON in DB, and returns it from `messageEnvelope` /
  // `messageBodyStructure` events later to avoid per-FETCH body parsing.
  extractEnvelope,
  extractBodyStructure,
  extractMessageMetadata
};
