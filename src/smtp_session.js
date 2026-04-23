
import { EventEmitter } from 'node:events';

import {
  parseCommandLine,
  parseEsmtpParams,
  parseBdatHeaderLine,
  parseReplyBlock,
  looksLikeReply,
  buildReply,
  buildEhloReply,
  CONTEXT_CODE,
  SKIP_ENHANCED
} from './smtp_wire.js';

import {
  toU8,
  u8ToStr,
  concatU8,
  indexOfCRLF,
  parseMailHeaders
} from './utils.js';


// ============================================================
//  Constants
// ============================================================

const DEFAULT_HOSTNAME = 'localhost';
const DEFAULT_MAX_SIZE = 25 * 1024 * 1024;
const DEFAULT_MAX_RECIPIENTS = 100;
const DEFAULT_ACCEPT_TIMEOUT = 30000;

const STATE = {
  NEW:       'new',        // connected, banner not sent yet
  GREETING:  'greeting',   // banner sent, waiting for EHLO/HELO
  READY:     'ready',      // EHLO received, ready for transaction
  MAIL:      'mail',       // MAIL FROM received
  RCPT:      'rcpt',       // at least one RCPT TO received
  DATA:      'data',       // receiving DATA body
  BDAT:      'bdat',       // receiving BDAT chunks
  MESSAGE:   'message',    // full message received, waiting for accept/reject
  CLOSING:   'closing',    // QUIT received or closing
  CLOSED:    'closed'      // connection ended
};


// ============================================================
//  SMTPSession
// ============================================================

function SMTPSession(options) {
  if (!(this instanceof SMTPSession)) return new SMTPSession(options);
  options = options || {};

  const ev = new EventEmitter();
  ev.setMaxListeners(50);

  let context = {
    state: STATE.NEW,
    isServer: options.isServer !== false,   // default: true
    isSubmission: !!options.isSubmission,   // port 587 vs 25

    // Server identity
    hostname: options.hostname || DEFAULT_HOSTNAME,
    maxSize: options.maxSize || DEFAULT_MAX_SIZE,
    maxRecipients: options.maxRecipients || DEFAULT_MAX_RECIPIENTS,
    acceptTimeout: options.acceptTimeout || DEFAULT_ACCEPT_TIMEOUT,

    // Connection info
    remoteAddress: options.remoteAddress || null,
    localAddress: options.localAddress || null,
    isTLS: !!options.isTLS,
    tlsOptions: options.tlsOptions || null,

    // Capabilities to advertise (server) / received (client)
    advertiseTLS: !options.isTLS && !!options.tlsOptions,
    advertiseAuth: !!options.isSubmission,
    authMethods: options.authMethods || ['PLAIN', 'LOGIN', 'XOAUTH2'],
    extraCapabilities: options.extraCapabilities || [],

    // Remote capabilities (client mode — parsed from EHLO response)
    remoteCaps: null,

    // Client/server info (from EHLO)
    clientHostname: null,
    ehloReceived: false,

    // Auth state
    authenticated: false,
    authUsername: null,
    authInProgress: false,
    authMechanism: null,
    authData: null,

    // Transaction
    mailFrom: null,
    mailParams: null,
    rcptTo: [],
    rcptParams: [],

    // DATA accumulation (chunk array — concat only at finalize)
    inputBuf: Buffer.alloc(0),
    dataChunks: [],
    dataSize: 0,

    // BDAT accumulation
    bdatExpect: 0,
    bdatAccum: [],
    bdatTotal: 0,
    bdatLast: false,

    // Accept/reject timer
    acceptTimer: null,

    // Message counter (per connection)
    messageCount: 0,

    // Client mode — pending reply callback
    pendingReply: null
  };


  // ============================================================
  //  Input buffer management
  //  Uses Buffer for Node.js-optimized concat (C++ implementation)
  // ============================================================

  function appendInput(chunk) {
    if (context.inputBuf.length === 0) {
      context.inputBuf = Buffer.from(chunk);
    } else {
      context.inputBuf = Buffer.concat([context.inputBuf, chunk]);
    }
  }

  function consumeInput(n) {
    if (n >= context.inputBuf.length) {
      context.inputBuf = Buffer.alloc(0);
    } else {
      context.inputBuf = context.inputBuf.subarray(n); // subarray = no copy, just view
    }
  }


  // ============================================================
  //  Send response to client
  // ============================================================

  function send(data) {
    if (context.state === STATE.CLOSED) return;
    ev.emit('send', data);
  }

  function sendReply(code, message, enhanced) {
    let opts = enhanced ? { enhanced: enhanced } : {};
    send(buildReply(code, message, opts));
  }


  // ============================================================
  //  Build capabilities list
  // ============================================================

  function getCapabilities() {
    let caps = [];

    caps.push('PIPELINING');
    caps.push('SIZE ' + context.maxSize);
    caps.push('8BITMIME');
    caps.push('SMTPUTF8');
    caps.push('DSN');                        // RFC 3461 — delivery status notifications
    caps.push('ENHANCEDSTATUSCODES');

    if (context.advertiseTLS) {
      caps.push('STARTTLS');
    }

    // REQUIRETLS (RFC 8689) — advertise only when TLS is currently active.
    // Per §4.1 the capability must not appear on unsecured connections,
    // because accepting REQUIRETLS on a plaintext channel would be a lie.
    if (context.isTLS) {
      caps.push('REQUIRETLS');
    }

    if (context.advertiseAuth && context.authMethods.length > 0) {
      caps.push('AUTH ' + context.authMethods.join(' '));
    }

    for (let i = 0; i < context.extraCapabilities.length; i++) {
      caps.push(context.extraCapabilities[i]);
    }

    return caps;
  }


  // ============================================================
  //  Transaction management
  // ============================================================

  function resetTransaction() {
    context.mailFrom = null;
    context.mailParams = null;
    context.rcptTo = [];
    context.rcptParams = [];
    context.dataChunks = []; context.dataSize = 0;
    context.bdatExpect = 0;
    context.bdatAccum = [];
    context.bdatTotal = 0;
    context.bdatLast = false;

    if (context.acceptTimer) {
      clearTimeout(context.acceptTimer);
      context.acceptTimer = null;
    }

    if (context.state !== STATE.CLOSING && context.state !== STATE.CLOSED) {
      context.state = STATE.READY;
    }
  }

  function startAcceptTimeout() {
    if (context.acceptTimeout > 0) {
      context.acceptTimer = setTimeout(function() {
        // Auto-reject if no accept/reject called
        sendReply(451, 'Timeout waiting for processing', '4.3.0');
        resetTransaction();
      }, context.acceptTimeout);
    }
  }


  // ============================================================
  //  Finalize message — emit to higher layer
  // ============================================================

  function finalizeMessage(rawU8) {
    context.state = STATE.MESSAGE;
    context.messageCount++;

    // Parse headers from raw message for convenience
    let parsed = parseMailHeaders(rawU8);
    let headers = parsed.map;

    let mailEv = new EventEmitter();
    let mailObject = {
      // Envelope (from SMTP)
      from: context.mailFrom,
      to: context.rcptTo.slice(),
      params: context.mailParams,

      // Parsed headers (available immediately)
      subject: headers.subject || null,
      messageId: headers.messageId || null,
      date: headers.date || null,
      headerFrom: headers.from || null,
      headerTo: headers.to || null,

      // Auth results (filled by server layer before inboundMail fires)
      auth: {
        dkim: null,
        spf: null,
        dmarc: null,
        dmarcPolicy: null,
        rdns: null,
        rdnsHostname: null,
        dkimDomain: null
      },

      // Raw data (internal — exposed via events)
      raw: rawU8,
      size: rawU8.length,

      // Parsed body (populated at 'end' time)
      text: null,
      html: null,
      attachments: null,

      // EventEmitter for body streaming
      on: function(name, fn) { mailEv.on(name, fn); },
      off: function(name, fn) { mailEv.off(name, fn); },

      // Internal: trigger body events
      _emitBody: function() {
        if (mailObject._rejected) return;
        mailObject._bodyEmitted = true;

        // Emit data (the full body as one chunk)
        mailEv.emit('data', rawU8);

        // Parse body for convenience fields
        let parsed = null;
        try {
          // Import parseMessage dynamically to avoid circular deps
          parsed = _parseMessage(rawU8);
        } catch(e) {}

        if (parsed) {
          mailObject.text = parsed.text;
          mailObject.html = parsed.html;
          mailObject.attachments = parsed.attachments;
        }

        // Emit end
        mailEv.emit('end');
      },

      // Response methods
      _accepted: false,
      _rejected: false,
      _bodyEmitted: false,

      accept: function() {
        if (mailObject._accepted || mailObject._rejected) return;
        mailObject._accepted = true;
        if (context.acceptTimer) { clearTimeout(context.acceptTimer); context.acceptTimer = null; }
        sendReply(250, 'Ok queued', '2.0.0');
        resetTransaction();
      },

      reject: function(code, message) {
        if (mailObject._accepted || mailObject._rejected) return;
        mailObject._rejected = true;
        if (context.acceptTimer) { clearTimeout(context.acceptTimer); context.acceptTimer = null; }
        code = code || 550;
        message = message || 'Rejected';
        let enhanced = (Math.floor(code / 100) === 5) ? '5.7.1' : '4.7.1';
        sendReply(code, message, enhanced);
        resetTransaction();
      }
    };

    startAcceptTimeout();
    ev.emit('message', mailObject);
  }

  // Pluggable parseMessage — set by server layer to avoid circular deps
  let _parseMessage = function(raw) { return null; };
  function setParseMessage(fn) { _parseMessage = fn; }


  // ============================================================
  //  Un-dot-stuff DATA body
  // ============================================================

  function undotStuff(body) {
    // Step 1: Normalize bare LF to CRLF (SMTP smuggling protection)
    // A bare \n (not preceded by \r) is a smuggling vector
    body = normalizeCRLF(body);

    // Step 2: Remove dot-stuffing (\r\n.. → \r\n.)
    let out = new Uint8Array(body.length);
    let w = 0;
    for (let i = 0; i < body.length; i++) {
      if (i >= 2 && body[i - 2] === 13 && body[i - 1] === 10 && body[i] === 46 && i + 1 < body.length && body[i + 1] === 46) {
        out[w++] = 46;
        i++;
        continue;
      }
      out[w++] = body[i];
    }
    return out.slice(0, w);
  }

  // Normalize line endings: bare \n → \r\n, bare \r → \r\n
  function normalizeCRLF(data) {
    // Count how many bare LF/CR exist (to pre-allocate)
    let extra = 0;
    for (let i = 0; i < data.length; i++) {
      if (data[i] === 10 && (i === 0 || data[i - 1] !== 13)) extra++; // bare LF
      else if (data[i] === 13 && (i + 1 >= data.length || data[i + 1] !== 10)) extra++; // bare CR
    }
    if (extra === 0) return data;

    let out = new Uint8Array(data.length + extra);
    let w = 0;
    for (let i = 0; i < data.length; i++) {
      if (data[i] === 13) {
        out[w++] = 13;
        if (i + 1 < data.length && data[i + 1] === 10) {
          out[w++] = 10;
          i++; // skip the LF — already written
        } else {
          out[w++] = 10; // bare CR → CRLF
        }
      } else if (data[i] === 10) {
        // bare LF (not preceded by CR — already checked above)
        if (i > 0 && data[i - 1] === 13) {
          // Part of CRLF — already handled
          out[w++] = 10;
        } else {
          out[w++] = 13; // insert CR
          out[w++] = 10;
        }
      } else {
        out[w++] = data[i];
      }
    }
    return out.slice(0, w);
  }


  // ============================================================
  //  Command processing
  // ============================================================

  function processCommand(lineU8) {
    let cmd = parseCommandLine(lineU8);

    // Emit raw command for hooks
    ev.emit('command', cmd);

    switch (cmd.type) {

      case 'EHLO':
        context.clientHostname = cmd.host;
        context.ehloReceived = true;
        resetTransaction();
        context.state = STATE.READY;
        send(buildEhloReply(context.hostname, getCapabilities()));
        ev.emit('ehlo', cmd.host);
        break;

      case 'HELO':
        context.clientHostname = cmd.host;
        context.ehloReceived = true;
        resetTransaction();
        context.state = STATE.READY;
        sendReply(250, context.hostname);
        break;

      case 'MAIL':
        if (cmd.error) { sendReply(501, 'Syntax error', '5.5.2'); break; }
        if (context.state !== STATE.READY) { sendReply(503, 'Bad sequence', '5.5.1'); break; }
        if (context.isSubmission && !context.authenticated) { sendReply(530, 'Authentication required', '5.7.0'); break; }
        if (context.mailFrom !== null) { sendReply(503, 'Nested MAIL', '5.5.1'); break; }

        // Check SIZE param
        if (cmd.params && cmd.params.size && cmd.params.size > context.maxSize) {
          sendReply(552, 'Message size exceeds limit', '5.3.4');
          break;
        }

        // REQUIRETLS (RFC 8689 §4.2): the sender is asserting this message
        // must travel only over TLS-protected hops. If the current session
        // is plaintext we must reject — accepting on the clear would break
        // the chain of custody the sender relies on.
        if (cmd.params && cmd.params.requiretls && !context.isTLS) {
          sendReply(550, 'REQUIRETLS requires active TLS', '5.7.10');
          break;
        }

        context.mailFrom = cmd.from;
        context.mailParams = cmd.params || {};
        context.state = STATE.MAIL;
        sendReply(250, 'Ok', CONTEXT_CODE.MAIL_FROM_OK);
        ev.emit('mail', cmd.from, cmd.params);
        break;

      case 'RCPT':
        if (cmd.error) { sendReply(501, 'Syntax error', '5.5.2'); break; }
        if (context.state !== STATE.MAIL && context.state !== STATE.RCPT) {
          sendReply(503, 'Bad sequence', '5.5.1');
          break;
        }
        if (context.rcptTo.length >= context.maxRecipients) {
          sendReply(452, 'Too many recipients', '4.5.3');
          break;
        }

        // Emit rcpt event — allow server to reject specific recipients
        let rcptAddress = cmd.to;
        let rcptParams = cmd.params || {};
        let rcptAccepted = true;
        let rcptRejectCode = 550;
        let rcptRejectMsg = 'User not found';

        // Synchronous check via event
        ev.emit('rcpt', rcptAddress, rcptParams, {
          reject: function(code, msg) {
            rcptAccepted = false;
            rcptRejectCode = code || 550;
            rcptRejectMsg = msg || 'User not found';
          }
        });

        if (!rcptAccepted) {
          sendReply(rcptRejectCode, rcptRejectMsg, '5.1.1');
          break;
        }

        context.rcptTo.push(rcptAddress);
        context.rcptParams.push(rcptParams);
        context.state = STATE.RCPT;
        sendReply(250, 'Ok', CONTEXT_CODE.RCPT_TO_OK);
        break;

      case 'DATA_START':
        if (context.state !== STATE.RCPT) {
          sendReply(503, 'Bad sequence', '5.5.1');
          break;
        }
        context.state = STATE.DATA;
        context.dataChunks = []; context.dataSize = 0;
        sendReply(354, 'End data with <CRLF>.<CRLF>');
        break;

      case 'BDAT_HEADER_ONLY': {
        if (context.state !== STATE.RCPT && context.state !== STATE.BDAT) {
          sendReply(503, 'Bad sequence', '5.5.1');
          break;
        }
        let bh = parseBdatHeaderLine(cmd.raw || u8ToStr(lineU8));
        if (!bh) { sendReply(501, 'Syntax error', '5.5.2'); break; }
        context.state = STATE.BDAT;
        context.bdatExpect = bh.size;
        context.bdatLast = bh.last;
        break;
      }

      case 'AUTH': {
        if (context.authenticated) { sendReply(503, 'Already authenticated', '5.5.1'); break; }
        if (!context.advertiseAuth) { sendReply(502, 'Not implemented', '5.5.1'); break; }
        if (cmd.error) { sendReply(501, 'Syntax error', '5.5.4'); break; }

        let mech = cmd.mechanism;
        if (context.authMethods.indexOf(mech) < 0) {
          sendReply(504, 'Unsupported mechanism', '5.5.4');
          break;
        }

        if (mech === 'PLAIN') {
          if (cmd.initial) {
            handleAuthPlain(cmd.initial);
          } else {
            context.authInProgress = true;
            context.authMechanism = 'PLAIN';
            sendReply(334, '');
          }
        } else if (mech === 'LOGIN') {
          context.authInProgress = true;
          context.authMechanism = 'LOGIN';
          context.authData = {};
          sendReply(334, Buffer.from('Username:').toString('base64'));
        } else if (mech === 'XOAUTH2') {
          // Bearer-token auth (RFC 7628 / Google / Microsoft). Payload may
          // be provided inline (SASL-IR) or requested via continuation.
          if (cmd.initial) {
            handleAuthXoauth2(cmd.initial);
          } else {
            context.authInProgress = true;
            context.authMechanism = 'XOAUTH2';
            sendReply(334, '');
          }
        } else {
          sendReply(504, 'Mechanism not supported yet', '5.5.4');
        }
        break;
      }

      case 'STARTTLS':
        if (context.isTLS) { sendReply(503, 'Already TLS', '5.5.1'); break; }
        if (!context.tlsOptions) { sendReply(502, 'Not available', '5.5.1'); break; }
        sendReply(220, 'Ready to start TLS');
        ev.emit('starttls');
        break;

      case 'RSET':
        resetTransaction();
        sendReply(250, 'Ok', '2.0.0');
        break;

      case 'NOOP':
        sendReply(250, 'Ok', '2.0.0');
        break;

      case 'QUIT':
        context.state = STATE.CLOSING;
        sendReply(221, 'Bye', '2.0.0');
        ev.emit('close');
        break;

      case 'VRFY':
        sendReply(252, 'Cannot VRFY user', '2.1.5');
        break;

      default:
        sendReply(502, 'Command not implemented', '5.5.1');
        break;
    }
  }


  // ============================================================
  //  AUTH handlers
  // ============================================================

  function handleAuthPlain(data) {
    let decoded;
    try {
      decoded = Buffer.from(data, 'base64').toString('utf-8');
    } catch(e) {
      sendReply(535, 'Invalid encoding', '5.7.8');
      context.authInProgress = false;
      return;
    }

    let parts = decoded.split('\0');
    if (parts.length < 3) {
      sendReply(535, 'Invalid credentials', '5.7.8');
      context.authInProgress = false;
      return;
    }

    let username = parts[1] || parts[0];
    let password = parts[2];

    context.authInProgress = false;
    context.authMechanism = null;

    ev.emit('auth', username, password, {
      accept: function() {
        context.authenticated = true;
        context.authUsername = username;
        sendReply(235, 'Authentication successful', '2.7.0');
      },
      reject: function() {
        sendReply(535, 'Authentication failed', '5.7.8');
      }
    }, 'plain');
  }

  function handleAuthLogin(data) {
    if (!context.authData.username) {
      // First response: username
      try {
        context.authData.username = Buffer.from(data, 'base64').toString('utf-8');
      } catch(e) {
        sendReply(535, 'Invalid encoding', '5.7.8');
        context.authInProgress = false;
        context.authData = null;
        return;
      }
      sendReply(334, Buffer.from('Password:').toString('base64'));
    } else {
      // Second response: password
      let password;
      try {
        password = Buffer.from(data, 'base64').toString('utf-8');
      } catch(e) {
        sendReply(535, 'Invalid encoding', '5.7.8');
        context.authInProgress = false;
        context.authData = null;
        return;
      }

      let username = context.authData.username;
      context.authInProgress = false;
      context.authMechanism = null;
      context.authData = null;

      ev.emit('auth', username, password, {
        accept: function() {
          context.authenticated = true;
          context.authUsername = username;
          sendReply(235, 'Authentication successful', '2.7.0');
        },
        reject: function() {
          sendReply(535, 'Authentication failed', '5.7.8');
        }
      }, 'login');
    }
  }

  // SASL XOAUTH2 (RFC 7628 / Google / Microsoft) — decode the base64 payload
  //   "user=" <email> \x01 "auth=Bearer " <access-token> \x01 \x01
  // and emit auth with the bearer token in the password position and
  // authMethod='xoauth2' so the developer knows to validate it as a token
  // against an IdP rather than as a plaintext password.
  function handleAuthXoauth2(data) {
    let decoded;
    try {
      decoded = Buffer.from(data, 'base64').toString('utf-8');
    } catch(e) {
      sendReply(535, 'Invalid encoding', '5.7.8');
      context.authInProgress = false;
      context.authMechanism = null;
      return;
    }

    let parts = decoded.split('\x01');
    let username = null, token = null;
    for (let i = 0; i < parts.length; i++) {
      let p = parts[i];
      if      (p.indexOf('user=') === 0)         username = p.substring(5);
      else if (p.indexOf('auth=Bearer ') === 0)  token    = p.substring(12);
    }
    if (!username || !token) {
      sendReply(535, 'Invalid XOAUTH2 payload', '5.7.8');
      context.authInProgress = false;
      context.authMechanism = null;
      return;
    }

    context.authInProgress = false;
    context.authMechanism = null;

    ev.emit('auth', username, token, {
      accept: function() {
        context.authenticated = true;
        context.authUsername = username;
        sendReply(235, 'Authentication successful', '2.7.0');
      },
      reject: function() {
        sendReply(535, 'Authentication failed', '5.7.8');
      }
    }, 'xoauth2');
  }


  // ============================================================
  //  Data pump — feed raw TCP data
  // ============================================================

  function feed(chunk) {
    if (context.state === STATE.CLOSED) return;
    appendInput(toU8(chunk));

    // Client mode — parse server responses
    if (!context.isServer) {
      feedClient();
      return;
    }

    while (true) {

      // --- COMMAND mode ---
      if (context.state !== STATE.DATA && context.state !== STATE.BDAT) {

        // Handle AUTH continuation (waiting for auth data, not a command)
        if (context.authInProgress) {
          let cr = indexOfCRLF(context.inputBuf, 0);
          if (cr < 0) break;
          let line = u8ToStr(context.inputBuf.slice(0, cr)).trim();
          consumeInput(cr + 2);

          if (line === '*') {
            // Client cancels auth
            context.authInProgress = false;
            context.authMechanism = null;
            context.authData = null;
            sendReply(501, 'Authentication cancelled', '5.7.0');
          } else if (context.authMechanism === 'PLAIN') {
            handleAuthPlain(line);
          } else if (context.authMechanism === 'LOGIN') {
            handleAuthLogin(line);
          } else if (context.authMechanism === 'XOAUTH2') {
            handleAuthXoauth2(line);
          }
          continue;
        }

        // Regular command
        let cr = indexOfCRLF(context.inputBuf, 0);
        if (cr < 0) break;
        let lineU8 = context.inputBuf.slice(0, cr);
        consumeInput(cr + 2);

        if (lineU8.length === 0) continue; // empty line

        processCommand(lineU8);
        continue;
      }

      // --- DATA mode ---
      if (context.state === STATE.DATA) {
        // Look for \r\n.\r\n terminator
        let termAt = -1;
        let buf = context.inputBuf;
        for (let i = 2; i + 2 < buf.length; i++) {
          if (buf[i - 2] === 13 && buf[i - 1] === 10 && buf[i] === 46 && buf[i + 1] === 13 && buf[i + 2] === 10) {
            termAt = i - 2;
            break;
          }
        }

        if (termAt < 0) {
          // No terminator yet — accumulate chunk (O(1) push, not O(n) copy)
          context.dataChunks.push(Buffer.from(context.inputBuf));
          context.dataSize += context.inputBuf.length;
          context.inputBuf = Buffer.alloc(0);

          // Check size limit
          if (context.dataSize > context.maxSize) {
            sendReply(552, 'Message size exceeds limit', '5.3.4');
            resetTransaction();
          }
          break;
        }

        // Found terminator — push remaining body, concat once
        let bodyPart = context.inputBuf.slice(0, termAt);
        context.dataChunks.push(Buffer.from(bodyPart));
        context.dataSize += bodyPart.length;
        consumeInput(termAt + 5); // skip past \r\n.\r\n

        let body = undotStuff(Buffer.concat(context.dataChunks, context.dataSize));
        context.dataChunks = []; context.dataSize = 0;
        finalizeMessage(body);
        continue;
      }

      // --- BDAT mode ---
      if (context.state === STATE.BDAT) {
        if (context.bdatExpect > 0) {
          if (context.inputBuf.length === 0) break;
          let take = Math.min(context.bdatExpect, context.inputBuf.length);
          let piece = context.inputBuf.slice(0, take);
          context.bdatAccum.push(piece);
          context.bdatTotal += piece.length;
          context.bdatExpect -= take;
          consumeInput(take);

          if (context.bdatExpect > 0) break; // waiting for more

          // Chunk complete
          sendReply(250, 'Ok chunk', '2.0.0');

          if (context.bdatLast) {
            // Assemble full message
            let raw = new Uint8Array(context.bdatTotal);
            let off = 0;
            for (let i = 0; i < context.bdatAccum.length; i++) {
              raw.set(context.bdatAccum[i], off);
              off += context.bdatAccum[i].length;
            }
            context.bdatAccum = [];
            context.bdatTotal = 0;
            context.bdatLast = false;
            context.state = STATE.READY;
            finalizeMessage(raw);
          } else {
            // Wait for next BDAT command
            context.state = STATE.RCPT;
          }
        } else {
          context.state = STATE.RCPT;
        }
        continue;
      }

      break;
    }
  }


  // ============================================================
  //  Client mode — reply parsing
  // ============================================================

  function feedClient() {
    if (!context.pendingReply) return;

    // Search for complete reply directly in buffer (avoid string conversion)
    // A reply is complete when we find: \r\n DDD SP (or DDD SP at start)
    let buf = context.inputBuf;
    let endIdx = -1;

    // Scan for final reply line: 3 digits + space
    let lineStart = 0;
    for (let i = 0; i + 1 < buf.length; i++) {
      if (buf[i] === 13 && buf[i + 1] === 10) { // \r\n
        let nextLineStart = i + 2;
        // Check if next line starts with DDD SP (final reply line)
        if (nextLineStart + 3 < buf.length &&
            buf[nextLineStart] >= 48 && buf[nextLineStart] <= 57 &&
            buf[nextLineStart + 1] >= 48 && buf[nextLineStart + 1] <= 57 &&
            buf[nextLineStart + 2] >= 48 && buf[nextLineStart + 2] <= 57 &&
            buf[nextLineStart + 3] === 32) {
          // Find end of this final line
          for (let k = nextLineStart + 4; k + 1 < buf.length; k++) {
            if (buf[k] === 13 && buf[k + 1] === 10) {
              endIdx = k + 2;
              break;
            }
          }
          if (endIdx >= 0) break;
        }
        lineStart = nextLineStart;
      }
    }

    // Also check if first line itself is a final reply (single-line reply)
    if (endIdx < 0 && buf.length >= 5 &&
        buf[0] >= 48 && buf[0] <= 57 &&
        buf[1] >= 48 && buf[1] <= 57 &&
        buf[2] >= 48 && buf[2] <= 57 &&
        buf[3] === 32) {
      for (let k = 4; k + 1 < buf.length; k++) {
        if (buf[k] === 13 && buf[k + 1] === 10) {
          endIdx = k + 2;
          break;
        }
      }
    }

    if (endIdx < 0) return;

    let replyData = context.inputBuf.slice(0, endIdx);
    consumeInput(endIdx);
    let parsed = parseReplyBlock(replyData);
    let fn = context.pendingReply;
    context.pendingReply = null;
    fn(parsed);
  }

  function clientReadReply(onReply) {
    context.pendingReply = onReply;
    feedClient(); // check if data already buffered
  }

  function clientSendLine(line) {
    send(line + '\r\n');
  }


  // ============================================================
  //  Client mode — EHLO negotiation
  // ============================================================

  function clientEhlo(cb) {
    clientSendLine('EHLO ' + context.hostname);
    clientReadReply(function(reply) {
      if (reply.code !== 250) {
        // Fallback to HELO
        clientSendLine('HELO ' + context.hostname);
        clientReadReply(function(helo) {
          if (helo.code !== 250) return cb(new Error('HELO rejected: ' + helo.code));
          context.remoteCaps = {};
          context.state = STATE.READY;
          cb(null);
        });
        return;
      }
      context.remoteCaps = reply.capabilities || {};
      context.state = STATE.READY;
      cb(null);
    });
  }


  // ============================================================
  //  Client mode — STARTTLS
  // ============================================================

  function clientStartTLS(cb) {
    clientSendLine('STARTTLS');
    clientReadReply(function(reply) {
      if (reply.code !== 220) return cb(new Error('STARTTLS rejected: ' + reply.code));
      // Emit starttls — transport layer handles socket upgrade
      // After upgrade, caller should call tlsUpgraded() then clientEhlo()
      ev.emit('starttls');
      cb(null);
    });
  }


  // ============================================================
  //  Client mode — AUTH
  // ============================================================

  function clientAuthPlain(user, pass, cb) {
    let creds = Buffer.from('\0' + user + '\0' + pass).toString('base64');
    clientSendLine('AUTH PLAIN ' + creds);
    clientReadReply(function(reply) {
      if (reply.code === 235) {
        context.authenticated = true;
        context.authUsername = user;
        cb(null);
      } else {
        cb(new Error('Auth failed: ' + reply.code));
      }
    });
  }


  // ============================================================
  //  Client mode — mail transaction
  // ============================================================

  function clientMailFrom(address, params, cb) {
    let line = 'MAIL FROM:<' + address + '>';
    if (params && params.size)       line += ' SIZE=' + params.size;
    if (params && params.body)       line += ' BODY=' + params.body;
    // RFC 6531 — advertise SMTPUTF8 use for this envelope. Required when
    // the local-part is non-ASCII; optional but recommended when only the
    // domain is non-ASCII (an SMTPUTF8-aware peer will accept the UTF-8
    // domain without Punycoding).
    if (params && params.smtputf8)   line += ' SMTPUTF8';
    // RFC 8689 — require TLS for the entire delivery chain. Senders use this
    // for sensitive mail that must not fall back to plaintext. Pointless
    // unless the peer advertises REQUIRETLS; we emit anyway since the peer
    // will reject if unsupported, giving the caller a clear failure.
    if (params && params.requiretls) line += ' REQUIRETLS';
    clientSendLine(line);
    clientReadReply(function(reply) {
      if (reply.code === 250) {
        context.mailFrom = address;
        context.mailParams = params || {};
        context.state = STATE.MAIL;
        cb(null);
      } else {
        cb(new Error('MAIL FROM rejected: ' + reply.code + ' ' + (reply.replyLines[0] || '')));
      }
    });
  }

  function clientRcptTo(address, cb) {
    clientSendLine('RCPT TO:<' + address + '>');
    clientReadReply(function(reply) {
      if (reply.code === 250 || reply.code === 251) {
        context.rcptTo.push(address);
        context.state = STATE.RCPT;
        cb(null);
      } else {
        cb(new Error('RCPT TO rejected: ' + reply.code + ' ' + (reply.replyLines[0] || '')));
      }
    });
  }

  function clientData(rawMessage, cb) {
    clientSendLine('DATA');
    clientReadReply(function(reply) {
      if (reply.code !== 354) return cb(new Error('DATA rejected: ' + reply.code));

      // Dot-stuff and send body
      let str = (rawMessage instanceof Uint8Array) ? u8ToStr(rawMessage) :
                (Buffer.isBuffer(rawMessage)) ? rawMessage.toString('utf-8') : String(rawMessage);
      let stuffed = str.replace(/\r\n\./g, '\r\n..');
      send(stuffed + '\r\n.\r\n');

      clientReadReply(function(reply2) {
        if (reply2.code === 250) {
          context.messageCount++;
          resetTransaction();
          cb(null, reply2);
        } else {
          cb(new Error('Message rejected: ' + reply2.code + ' ' + (reply2.replyLines[0] || '')));
        }
      });
    });
  }

  function clientQuit() {
    clientSendLine('QUIT');
    context.state = STATE.CLOSING;
  }


  // ============================================================
  //  Greeting (both modes)
  // ============================================================

  function greet() {
    if (context.isServer) {
      // Server: send banner
      context.state = STATE.GREETING;
      sendReply(220, context.hostname + ' ESMTP ready');
    } else {
      // Client: wait for server banner, then EHLO
      context.state = STATE.GREETING;
      clientReadReply(function(banner) {
        if (banner.code !== 220) {
          ev.emit('error', new Error('Bad banner: ' + banner.code));
          return;
        }
        if (banner.bannerDomain) context.clientHostname = banner.bannerDomain;

        clientEhlo(function(err) {
          if (err) { ev.emit('error', err); return; }

          // STARTTLS if available and not already TLS
          if (context.remoteCaps && context.remoteCaps.starttls && !context.isTLS) {
            clientStartTLS(function(err) {
              if (err) {
                // STARTTLS failed, continue without
                ev.emit('ready');
                return;
              }
              // TLS upgrade happens externally via 'starttls' event
              // After tlsUpgraded() is called, we re-EHLO
            });
          } else {
            ev.emit('ready');
          }
        });
      });
    }
  }


  // ============================================================
  //  Close
  // ============================================================

  function close() {
    if (context.state === STATE.CLOSED) return;

    // Clean up timers
    if (context.acceptTimer) {
      clearTimeout(context.acceptTimer);
      context.acceptTimer = null;
    }

    // Clean up client mode pending reply
    context.pendingReply = null;

    // Clean up buffers
    context.inputBuf = Buffer.alloc(0);
    context.dataChunks = []; context.dataSize = 0;
    context.bdatAccum = [];

    context.state = STATE.CLOSED;
    ev.emit('close');
    // Release listener references for GC.
    ev.removeAllListeners();
  }


  // ============================================================
  //  TLS upgrade complete
  // ============================================================

  function tlsUpgraded() {
    context.isTLS = true;
    context.advertiseTLS = false;
    context.inputBuf = Buffer.alloc(0);

    if (context.isServer) {
      // Server: client must re-EHLO
      context.ehloReceived = false;
      context.clientHostname = null;
      context.authenticated = false;
      context.authUsername = null;
      resetTransaction();
      context.state = STATE.GREETING;
    } else {
      // Client: re-EHLO after TLS upgrade, then emit ready
      clientEhlo(function(err) {
        if (err) { ev.emit('error', err); return; }
        ev.emit('ready');
      });
    }
  }


  // ============================================================
  //  API
  // ============================================================

  let api = {
    context: context,

    on:  function(name, fn) { ev.on(name, fn); },
    off: function(name, fn) { ev.off(name, fn); },

    /** Feed raw TCP data into the session. */
    feed: feed,

    /** Start the session — server sends banner, client waits for banner + EHLO. */
    greet: greet,

    /** Notify that TLS upgrade completed. */
    tlsUpgraded: tlsUpgraded,

    /** Close the session. */
    close: close,

    /** Set the parseMessage function (injected by server layer). */
    setParseMessage: setParseMessage,

    // ---- Client mode methods ----

    /** Client: send MAIL FROM. */
    mailFrom: clientMailFrom,

    /** Client: send RCPT TO. */
    rcptTo: clientRcptTo,

    /** Client: send DATA + message body. */
    data: clientData,

    /** Client: send AUTH PLAIN. */
    authPlain: clientAuthPlain,

    /** Client: send STARTTLS. */
    startTLS: clientStartTLS,

    /** Client: send QUIT. */
    quit: clientQuit,

    /** Client: raw send line + read reply. */
    sendLine: clientSendLine,
    readReply: clientReadReply,

    // ---- Getters ----

    get isServer() { return context.isServer; },
    get state() { return context.state; },
    get authenticated() { return context.authenticated; },
    get username() { return context.authUsername; },
    get clientHostname() { return context.clientHostname; },
    get remoteAddress() { return context.remoteAddress; },
    get isTLS() { return context.isTLS; },
    get messageCount() { return context.messageCount; },
    get capabilities() { return context.remoteCaps; }
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


export default SMTPSession;
export { SMTPSession, STATE };
