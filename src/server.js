
import net from 'node:net';
import tls from 'node:tls';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

import { SMTPSession } from './smtp_session.js';
import { IMAPSession } from './imap_session.js';
import { POP3Session } from './pop3_session.js';
import { sendMail } from './smtp_client.js';
import { OutboundPool } from './pool.js';
import { createRateLimiter } from './rate_limit.js';
import { buildDsn } from './dsn.js';
import { composeMessage, parseMessage as parseMessageFn } from './message.js';
import { sign as dkimSign, verify as dkimVerify } from './dkim.js';
import { checkSPF } from './spf.js';
import { checkDMARC } from './dmarc.js';
import { checkFCrDNS } from './rdns.js';
import { extractAddress, extractAddressList } from './utils.js';


// ============================================================
//  Server
// ============================================================

function Server(options) {
  if (!(this instanceof Server)) return new Server(options);
  options = options || {};

  const ev = new EventEmitter();
  const self = this;

  let context = {
    hostname: options.hostname || 'localhost',
    ports: options.ports || { inbound: 25 },
    maxSize: options.maxSize || 25 * 1024 * 1024,
    maxRecipients: options.maxRecipients || 100,
    acceptTimeout: options.acceptTimeout || 30000,
    rateLimit: options.rateLimit || null,
    closeTimeout: options.closeTimeout || 30000,

    // PROXY protocol (HAProxy)
    useProxy: options.useProxy || false,

    // Relay / smarthost
    relay: options.relay || null,

    // Dynamic callbacks
    SNICallback: options.SNICallback || null,
    dkimCallback: options.dkimCallback || null,
    onSecure: options.onSecure || null,

    // Domain registry
    domains: {},

    // TLS context cache
    secureContexts: new Map(),

    // TCP servers
    servers: [],

    // Active connections (socket → { id, session })
    connections: new Map(),

    // Connection counter for IDs
    connectionCounter: 0,

    // Running state
    listening: false,

    // Outbound pool
    pool: null,

    // Per-IP rate limiter (opt-in via options.rateLimit).
    // When `rateLimit` is null, `limiter` is null and all checks are skipped.
    limiter: null
  };

  // Create the rate limiter if configured
  if (options.rateLimit) context.limiter = createRateLimiter(options.rateLimit);

  // Create outbound pool
  let poolOpts = options.pool || {};
  poolOpts.localHostname = context.hostname;
  context.pool = new OutboundPool(poolOpts);

  // Forward pool events to server
  context.pool.on('sent', function(info) { ev.emit('sent', info); });
  context.pool.on('bounce', function(info) { ev.emit('bounce', info); });
  context.pool.on('retry', function(info) { ev.emit('retry', info); });


  // ============================================================
  //  Domain management
  // ============================================================

  function addDomain(mat) {
    if (!mat || !mat.domain) throw new Error('Invalid domain material');
    context.domains[mat.domain] = mat;
    ev.emit('domainAdded', mat.domain);

    // Check DNS in background
    if (mat.verifyDNS) {
      mat.verifyDNS(function(err, results) {
        if (err) return;
        let warnings = [];
        if (!results.dkim) warnings.push('DKIM record missing for ' + mat.domain);
        if (!results.spf) warnings.push('SPF record missing for ' + mat.domain);
        if (!results.dmarc) warnings.push('DMARC record missing for ' + mat.domain);
        if (!results.mx) warnings.push('MX record missing for ' + mat.domain);
        for (let i = 0; i < warnings.length; i++) {
          ev.emit('dnsWarning', { domain: mat.domain, message: warnings[i] });
        }
      });
    }
  }

  function removeDomain(domain) {
    if (domain in context.domains) {
      delete context.domains[domain];
      return true;
    }
    return false;
  }

  function getDomainMaterial(domain) {
    return context.domains[domain] || null;
  }

  function isDomainRegistered(domain) {
    return domain in context.domains;
  }


  // ============================================================
  //  TLS context resolution
  // ============================================================

  function resolveTlsContext(servername, cb) {
    // Normalize — TLS SNI is case-insensitive; use lowercase as cache key.
    let key = (servername || '').toLowerCase();

    // Cached already? createSecureContext is expensive (parses PEM, derives
    // OCSP if stapling, etc). We cache per servername for the life of the
    // server. Call server.clearTlsCache() after a cert rotation.
    let cached = context.secureContexts.get(key);
    if (cached) return cb(null, cached);

    // Check registered domains first
    let mat = getDomainMaterial(servername);
    if (mat && mat.tls && mat.tls.key && mat.tls.cert) {
      try {
        let ctx = tls.createSecureContext({
          key: mat.tls.key,
          cert: mat.tls.cert,
          ca: mat.tls.ca || undefined
        });
        context.secureContexts.set(key, ctx);
        return cb(null, ctx);
      } catch(e) {
        return cb(e);
      }
    }

    // Fallback to developer-provided SNICallback. We don't cache results from
    // SNICallback because the developer may want to rotate certs dynamically
    // — caching their result would defeat that. Developer can implement
    // their own caching if desired.
    if (context.SNICallback) {
      return context.SNICallback(servername, cb);
    }

    cb(null, null);
  }


  // ============================================================
  //  DKIM material resolution
  // ============================================================

  function resolveDkim(domain, cb) {
    let mat = getDomainMaterial(domain);
    if (mat && mat.dkim && mat.dkim.privateKey) {
      return cb(null, {
        selector: mat.dkim.selector,
        algo: mat.dkim.algo,
        privateKey: mat.dkim.privateKey
      });
    }

    if (context.dkimCallback) {
      return context.dkimCallback(domain, cb);
    }

    cb(null, null);
  }


  // ============================================================
  //  Session factory
  // ============================================================

  function createSession(socket, isSubmission, remoteAddress, connId) {

    // Determine if we have TLS options available
    let hasTls = Object.keys(context.domains).some(function(d) {
      return context.domains[d].tls && context.domains[d].tls.key;
    }) || !!context.SNICallback;

    let session = new SMTPSession({
      hostname: context.hostname,
      isSubmission: isSubmission,
      maxSize: context.maxSize,
      maxRecipients: context.maxRecipients,
      acceptTimeout: context.acceptTimeout,
      remoteAddress: remoteAddress,
      localAddress: socket.localAddress || null,
      isTLS: socket.encrypted || false,
      tlsOptions: hasTls ? {} : null,
      authMethods: ['PLAIN', 'LOGIN', 'XOAUTH2']
    });

    // Inject parseMessage for body parsing at 'end' time
    session.setParseMessage(function(raw) {
      return parseMessageFn(raw);
    });

    // Build the session facade — mirrors the IMAP/POP3 mailboxSession pattern.
    // Developer registers per-session handlers (currently just 'mail' and 'close')
    // and accesses auth / transport info through closure.
    let sessionFacade = new EventEmitter();
    sessionFacade.protocol      = 'smtp';
    sessionFacade.isSubmission  = isSubmission;
    sessionFacade.username      = null;                        // set on auth.accept()
    sessionFacade.remoteAddress = remoteAddress;
    sessionFacade.isTLS         = session.isTLS;

    // Wire session output to socket with backpressure
    session.on('send', function(data) {
      if (!socket.destroyed) {
        try {
          let ok = socket.write(data);
          if (!ok) {
            // Buffer full — pause reading until drained
            socket.pause();
          }
        } catch(e) {}
      }
    });

    socket.on('drain', function() {
      // Buffer drained — resume reading
      if (!socket.destroyed) socket.resume();
    });

    // EHLO event
    session.on('ehlo', function(host) {
      // Informational — server layer can listen
    });

    // Auth event — forward via unified `auth` event.
    //
    // On accept(), emit the smtpSession facade SYNCHRONOUSLY BEFORE calling
    // the underlying cb.accept() — this way the developer's 'mail' handler is
    // registered before the 235 OK is sent to the client. No race even in
    // fully-synchronous test pipes.
    session.on('auth', function(username, password, cb, authMethod) {
      let authInfo = {
        protocol:      'smtp',
        username:      username,
        password:      password,
        authMethod:    authMethod || 'plain',
        remoteAddress: remoteAddress,
        isTLS:         session.isTLS,
        accept: function() {
          if (context.limiter) context.limiter.recordAuthSuccess(remoteAddress);
          sessionFacade.username = username;
          ev.emit('smtpSession', sessionFacade);   // sync — developer registers handlers
          cb.accept();                              // sync — sends 235
        },
        reject: function() {
          if (context.limiter) {
            let r = context.limiter.recordAuthFailure(remoteAddress);
            if (r.banned) ev.emit('rateLimit', { protocol: 'smtp', remoteAddress: remoteAddress, reason: 'banned', bannedUntil: r.bannedUntil });
          }
          cb.reject();
        }
      };
      ev.emit('auth', authInfo);
    });

    // Message event — fire 'mail' on the session facade after any required
    // auth checks (SPF/DKIM/DMARC/rDNS for port 25).
    session.on('message', function(mail) {
      if (isSubmission) {
        sessionFacade.emit('mail', mail);
        // After developer registers mail.on('data') / mail.on('end'), trigger body events
        setImmediate(function() { mail._emitBody(); });
      } else {
        // Run all auth checks in parallel, then fire 'mail' event on session
        let dkimDone = false, spfDone = false, rdnsDone = false;

        function afterAllAuth() {
          if (!dkimDone || !spfDone || !rdnsDone) return;

          // Extract From domain for DMARC
          let fromDomain = '';
          if (mail.headerFrom) {
            let m = /@([^>,\s]+)/.exec(mail.headerFrom);
            if (m) fromDomain = m[1].trim();
          }

          let spfDomain = '';
          if (mail.from) {
            let parts = mail.from.split('@');
            if (parts[1]) spfDomain = parts[1];
          }

          checkDMARC({
            fromDomain:  fromDomain,
            dkimResult:  mail.auth.dkim,
            dkimDomain:  mail.auth.dkimDomain || null,
            spfResult:   mail.auth.spf,
            spfDomain:   spfDomain
          }, function(err, dmarcResult) {
            if (err || !dmarcResult) {
              mail.auth.dmarc = 'none';
            } else {
              mail.auth.dmarc = dmarcResult.result;
              mail.auth.dmarcPolicy = dmarcResult.policy || null;
            }

            // Fire 'mail' on session facade — developer has all auth + headers
            sessionFacade.emit('mail', mail);

            // After developer sets up listeners, trigger body events
            setImmediate(function() {
              mail._emitBody();
            });
          });
        }

        // DKIM verify
        dkimVerify(mail.raw, function(err, result) {
          if (err || !result) {
            mail.auth.dkim = 'none';
          } else {
            mail.auth.dkim = result.result;
            mail.auth.dkimDomain = result.domain || null;
          }
          dkimDone = true;
          afterAllAuth();
        });

        // SPF check
        let envelopeDomain = '';
        if (mail.from) {
          let parts = mail.from.split('@');
          if (parts[1]) envelopeDomain = parts[1];
        }

        checkSPF(remoteAddress, envelopeDomain, function(err, result) {
          if (err || !result) {
            mail.auth.spf = 'none';
          } else {
            mail.auth.spf = result.result;
          }
          spfDone = true;
          afterAllAuth();
        });

        // Reverse DNS
        checkFCrDNS(remoteAddress, function(err, result) {
          if (err || !result) {
            mail.auth.rdns = 'none';
          } else {
            mail.auth.rdns = result.result;
            mail.auth.rdnsHostname = result.hostname || null;
          }
          rdnsDone = true;
          afterAllAuth();
        });
      }
    });

    // STARTTLS event
    session.on('starttls', function() {
      let tlsOpts = {
        isServer: true,
        SNICallback: function(servername, cb) {
          resolveTlsContext(servername, cb);
        }
      };

      let tlsSocket = new tls.TLSSocket(socket, tlsOpts);

      tlsSocket.on('secure', function() {
        session.tlsUpgraded();
        sessionFacade.isTLS = true;

        // Replace data handler
        tlsSocket.on('data', function(chunk) {
          session.feed(chunk);
        });
      });

      tlsSocket.on('error', function() {
        ev.emit('tlsError', new Error('TLS handshake failed'));
        try { socket.destroy(); } catch(e) {}
      });
    });

    // Close event — propagate to session facade for developer cleanup
    session.on('close', function() {
      try { socket.end(); } catch(e) {}
      sessionFacade.emit('close');
    });

    // For INBOUND (port 25 — no auth): emit smtpSession immediately, synchronously.
    // Developer registers 'mail' handler BEFORE any data reaches the protocol layer.
    // For SUBMISSION (ports 587/465), smtpSession is emitted on auth.accept() above.
    if (!isSubmission) {
      ev.emit('smtpSession', sessionFacade);
    }

    return session;
  }


  // ============================================================
  //  Connection handler
  // ============================================================

  function handleConnection(socket, isSubmission) {
    // Generate connection ID
    let connId = (++context.connectionCounter).toString(36) + '-' +
      crypto.randomBytes(4).toString('hex');

    let remoteAddress = socket.remoteAddress || null;

    function startSession(finalRemoteAddress) {
      // Rate-limit check: is this IP allowed to open a new connection?
      if (context.limiter) {
        let check = context.limiter.canConnect(finalRemoteAddress);
        if (!check.ok) {
          // Reject with a terse, standards-aware greeting then close.
          try { socket.write('421 4.7.0 Too many connections or banned\r\n'); } catch(e) {}
          try { socket.destroy(); } catch(e) {}
          ev.emit('rateLimit', { protocol: 'smtp', remoteAddress: finalRemoteAddress, reason: check.reason });
          return;
        }
        context.limiter.recordConnection(finalRemoteAddress);
      }

      // Track connection
      context.connections.set(socket, { id: connId, remoteAddress: finalRemoteAddress });

      // Emit connection event — allow rejecting IPs
      let connInfo = {
        id: connId,
        remoteAddress: finalRemoteAddress,
        _rejected: false,
        reject: function() { connInfo._rejected = true; }
      };

      ev.emit('connection', connInfo);
      if (connInfo._rejected) {
        socket.destroy();
        context.connections.delete(socket);
        if (context.limiter) context.limiter.releaseConnection(finalRemoteAddress);
        return;
      }

      let session = createSession(socket, isSubmission, finalRemoteAddress, connId);

      socket.on('data', function(chunk) {
        session.feed(chunk);
      });

      socket.on('error', function() {
        session.close();
      });

      socket.on('close', function() {
        session.close();
        context.connections.delete(socket);
        if (context.limiter) context.limiter.releaseConnection(finalRemoteAddress);
      });

      socket.setTimeout(300000);
      socket.on('timeout', function() {
        try { socket.destroy(); } catch(e) {}
      });

      session.greet();
    }

    // PROXY protocol support
    if (context.useProxy) {
      parseProxyHeader(socket, function(err, proxyAddress) {
        if (err) {
          socket.destroy();
          return;
        }
        startSession(proxyAddress || remoteAddress);
      });
    } else {
      startSession(remoteAddress);
    }
  }

  // Parse PROXY protocol header (HAProxy v1)
  function parseProxyHeader(socket, cb) {
    let buf = Buffer.alloc(0);
    let done = false;

    function onData(chunk) {
      if (done) return;
      buf = Buffer.concat([buf, chunk]);

      let nlIdx = buf.indexOf(0x0A); // \n
      if (nlIdx >= 0) {
        done = true;
        socket.removeListener('data', onData);

        let header = buf.slice(0, nlIdx).toString().trim();
        let remainder = buf.slice(nlIdx + 1);
        if (remainder.length > 0) socket.unshift(remainder);

        let parts = header.split(' ');
        if (parts[0] !== 'PROXY') {
          return cb(new Error('Invalid PROXY header'));
        }

        // PROXY TCP4 sourceIP destIP sourcePort destPort
        let sourceIP = parts[1] || null;
        cb(null, sourceIP);
      }

      // Guard against oversized header
      if (buf.length > 256) {
        done = true;
        socket.removeListener('data', onData);
        cb(new Error('PROXY header too long'));
      }
    }

    socket.on('data', onData);
  }


  // ============================================================
  //  IMAP connection handler
  // ============================================================
  //
  // Developer-facing flow:
  //
  //   1. TCP connects → server emits 'connection' (as today; dev may reject by IP)
  //   2. Client runs LOGIN / AUTHENTICATE:
  //        server emits 'auth'  with { protocol: 'imap', username, password,
  //                                    remoteAddress, isTLS, accept(), reject(msg) }
  //   3. On accept():
  //        server emits 'mailboxSession' with a session facade. The developer
  //        registers per-session handlers (folders, messageMeta, messageBody, ...).
  //
  // Why 'mailboxSession' and not 'imapSession':
  //   The same event will be emitted for POP3 connections (future). POP3 and
  //   IMAP both expose the same underlying model — a user's mailbox — and map
  //   to the same storage handlers. `session.protocol` tells them apart when
  //   the developer cares (rarely).
  //
  // All handlers share the facade's closure — `session.username` identifies the
  // authenticated user without needing an artificial `user` argument on each event.
  function handleImapConnection(socket, remoteAddress, connId) {
    // Rate-limit check before anything else
    if (context.limiter) {
      let check = context.limiter.canConnect(remoteAddress);
      if (!check.ok) {
        try { socket.write('* BYE Too many connections or banned\r\n'); } catch(e) {}
        try { socket.destroy(); } catch(e) {}
        ev.emit('rateLimit', { protocol: 'imap', remoteAddress: remoteAddress, reason: check.reason });
        return;
      }
      context.limiter.recordConnection(remoteAddress);
    }

    // Emit 'connection' event — lets the developer reject by IP / rate limit
    let connInfo = {
      id: connId,
      protocol: 'imap',
      remoteAddress: remoteAddress,
      _rejected: false,
      reject: function() { connInfo._rejected = true; }
    };
    ev.emit('connection', connInfo);
    if (connInfo._rejected) {
      try { socket.destroy(); } catch(e) {}
      if (context.limiter) context.limiter.releaseConnection(remoteAddress);
      return;
    }
    context.connections.set(socket, { id: connId, protocol: 'imap', remoteAddress: remoteAddress });

    let hasTls = Object.keys(context.domains).some(function(d) {
      return context.domains[d].tls && context.domains[d].tls.key;
    }) || !!context.SNICallback;

    let imapSession = new IMAPSession({
      hostname:      context.hostname,
      remoteAddress: remoteAddress,
      localAddress:  socket.localAddress || null,
      isTLS:         socket.encrypted || false,
      tlsOptions:    hasTls ? {} : null,
      authTimeout:   context.acceptTimeout
    });

    // Wire session output → socket (with backpressure). The sendFn indirection
    // lets us hot-swap the write path later (for COMPRESS=DEFLATE — after
    // activation the bytes are run through a zlib deflate stream first).
    let sendFn = function(data) {
      if (!socket.destroyed) {
        try {
          let ok = socket.write(data);
          if (!ok) socket.pause();
        } catch(e) {}
      }
    };
    imapSession.on('send', function(data) { sendFn(data); });
    socket.on('drain', function() {
      if (!socket.destroyed) socket.resume();
    });

    // --- AUTH ---
    imapSession.on('imapAuth', function(authCtx) {
      // Build the unified server-level auth info object.
      // `protocol: 'imap'` distinguishes from the SMTP auth event on the same
      // server (next refactor will make SMTP emit the same event with
      // `protocol: 'smtp'`).
      let authInfo = {
        protocol:      'imap',
        username:      authCtx.username,
        password:      authCtx.password,
        authMethod:    authCtx.authMethod,
        remoteAddress: remoteAddress,
        isTLS:         imapSession.isTLS,

        accept: function() {
          if (context.limiter) context.limiter.recordAuthSuccess(remoteAddress);
          authCtx.accept();
          // Build the session facade and release it to the developer.
          // Event registrations on the facade forward to the underlying session.
          //
          // `mailboxSession` is the unified event for mailbox-access protocols
          // (IMAP now; POP3 planned). The developer registers the same storage
          // handlers regardless of protocol — the session layer handles the
          // command mapping. `session.protocol` lets the developer tell them
          // apart if needed (rarely is).
          //
          // The facade also exposes:
          //   • notify* methods — forward to the underlying session so the
          //     developer can push untagged IMAP responses (EXISTS, FETCH,
          //     EXPUNGE, VANISHED) to the connected client. Essential for
          //     IDLE clients that need to learn about new messages.
          //   • currentFolder / idling getters — let the developer filter
          //     "which sessions should receive this notification". The
          //     library does NOT maintain a user → sessions registry —
          //     user/tenant management is the developer's domain. If the
          //     developer needs one, they register it themselves on the
          //     'mailboxSession' event and clean up on the session's 'close'.
          let sessionFacade = {
            protocol:      'imap',
            username:      authCtx.username,
            remoteAddress: remoteAddress,
            isTLS:         imapSession.isTLS,
            on:   function(name, fn) { authCtx.on(name, fn);   return sessionFacade; },
            off:  function(name, fn) { authCtx.off(name, fn);  return sessionFacade; },
            once: function(name, fn) { authCtx.once(name, fn); return sessionFacade; },

            // Push untagged responses to the client (for IDLE-style push).
            // All are no-ops unless the session is in SELECTED state.
            notifyExists:   function(total)          { imapSession.notifyExists(total); },
            notifyRecent:   function(count)          { imapSession.notifyRecent(count); },
            notifyExpunge:  function(seq, uid)       { imapSession.notifyExpunge(seq, uid); },
            notifyVanished: function(arg)            { imapSession.notifyVanished(arg); },
            notifyFlags:    function(seq, uid, flags){ imapSession.notifyFlags(seq, uid, flags); },

            // State getters — developer can check before calling notify*.
            get currentFolder() { return imapSession.currentFolder; },
            get idling()        { return imapSession.idling; }
          };

          ev.emit('mailboxSession', sessionFacade);
        },

        reject: function(msg) {
          if (context.limiter) {
            let r = context.limiter.recordAuthFailure(remoteAddress);
            if (r.banned) ev.emit('rateLimit', { protocol: 'imap', remoteAddress: remoteAddress, reason: 'banned', bannedUntil: r.bannedUntil });
          }
          authCtx.reject(msg);
        }
      };

      ev.emit('auth', authInfo);
    });

    // --- STARTTLS ---
    imapSession.on('starttls', function() {
      let tlsOpts = {
        isServer: true,
        SNICallback: function(servername, cb) {
          resolveTlsContext(servername, cb);
        }
      };
      let tlsSocket = new tls.TLSSocket(socket, tlsOpts);
      tlsSocket.on('secure', function() {
        imapSession.tlsUpgraded && imapSession.tlsUpgraded();
        tlsSocket.on('data', function(chunk) { imapSession.feed(chunk); });
      });
      tlsSocket.on('error', function() {
        ev.emit('tlsError', new Error('TLS handshake failed'));
        try { socket.destroy(); } catch(e) {}
      });
    });

    // --- close ---
    imapSession.on('close', function() {
      try { socket.end(); } catch(e) {}
    });

    // Feed socket data into session. The feedFn indirection lets us slip a
    // zlib inflate stream in place after COMPRESS=DEFLATE is activated.
    let feedFn = function(chunk) { imapSession.feed(chunk); };
    socket.on('data', function(chunk) { feedFn(chunk); });

    // --- COMPRESS=DEFLATE (RFC 4978) ---
    // Session emits this after sending tagged OK for the COMPRESS command.
    // From this point on, all bytes on the wire are raw-deflate encoded.
    // We replace both pipelines so further socket data flows through
    // inflate → session, and session output flows through deflate → socket.
    imapSession.on('compress', function() {
      let inflate = zlib.createInflateRaw();
      let deflate = zlib.createDeflateRaw({ flush: zlib.constants.Z_SYNC_FLUSH });

      inflate.on('data',  function(chunk) { imapSession.feed(chunk); });
      inflate.on('error', function() { try { socket.destroy(); } catch(e) {} });
      deflate.on('data',  function(chunk) {
        if (socket.destroyed) return;
        try { socket.write(chunk); } catch(e) {}
      });
      deflate.on('error', function() { try { socket.destroy(); } catch(e) {} });

      // Hot-swap the pipelines. Any in-flight bytes already flushed through
      // sendFn (the tagged OK for COMPRESS) have been sent in plaintext —
      // that's correct per RFC 4978 §2, which says the server OK is the
      // last uncompressed response.
      feedFn = function(chunk) { inflate.write(chunk); };
      sendFn = function(data) {
        try {
          deflate.write(data);
          // Sync-flush every write so the client sees packets in real time.
          // Z_PARTIAL_FLUSH is cheaper than FULL_FLUSH and still interactive.
          deflate.flush(zlib.constants.Z_SYNC_FLUSH);
        } catch(e) {}
      };
    });

    socket.on('error', function() { imapSession.close && imapSession.close(); });
    socket.on('close', function() {
      imapSession.close && imapSession.close();
      context.connections.delete(socket);
      if (context.limiter) context.limiter.releaseConnection(remoteAddress);
    });

    // IMAP idle connections can be long — use a generous timeout (30 min).
    // Normal IMAP clients send NOOP/IDLE periodically, keeping the socket alive.
    socket.setTimeout(30 * 60 * 1000);
    socket.on('timeout', function() { try { socket.destroy(); } catch(e) {} });

    imapSession.greet();
  }


  // ============================================================
  //  POP3 connection handler — RFC 1939 (+ RFC 2595 STLS, RFC 5034 SASL)
  //
  //  Structure mirrors handleImapConnection. The POP3Session emits a
  //  `pop3Auth` event on USER+PASS or AUTH PLAIN; we map it onto the unified
  //  `auth` event and, on accept, into a `mailboxSession` facade just like
  //  IMAP. The same storage handlers (openFolder / resolveMessages /
  //  messageMeta / messageBody / setFlags / expunge) handle both protocols.
  // ============================================================

  function handlePop3Connection(socket, remoteAddress, connId) {
    let connInfo = {
      id: connId,
      protocol: 'pop3',
      remoteAddress: remoteAddress,
      _rejected: false,
      reject: function() { connInfo._rejected = true; }
    };
    ev.emit('connection', connInfo);
    if (connInfo._rejected) {
      try { socket.destroy(); } catch(e) {}
      return;
    }
    context.connections.set(socket, { id: connId, protocol: 'pop3', remoteAddress: remoteAddress });

    let hasTls = Object.keys(context.domains).some(function(d) {
      return context.domains[d].tls && context.domains[d].tls.key;
    }) || !!context.SNICallback;

    let pop3Session = new POP3Session({
      hostname:      context.hostname,
      remoteAddress: remoteAddress,
      isTLS:         socket.encrypted || false,
      tlsOptions:    hasTls ? {} : null
    });

    // Wire session output → socket (with backpressure)
    pop3Session.on('send', function(data) {
      if (!socket.destroyed) {
        try {
          let ok = socket.write(data);
          if (!ok) socket.pause();
        } catch(e) {}
      }
    });
    socket.on('drain', function() {
      if (!socket.destroyed) socket.resume();
    });

    // --- AUTH ---
    pop3Session.on('pop3Auth', function(authCtx) {
      let authInfo = {
        protocol:      'pop3',
        username:      authCtx.username,
        password:      authCtx.password,
        authMethod:    authCtx.authMethod,
        remoteAddress: remoteAddress,
        isTLS:         pop3Session.isTLS,

        accept: function() {
          // Build the mailboxSession facade — same shape as IMAP so the
          // developer's storage handlers are shared across protocols.
          //
          // IMPORTANT: we emit mailboxSession BEFORE calling authCtx.accept()
          // so the developer's handlers (openFolder, messageMeta, etc.) are
          // registered on the session's EventEmitter before the POP3 session's
          // loadInbox logic fires inside accept().
          let sessionFacade = {
            protocol:      'pop3',
            username:      authCtx.username,
            remoteAddress: remoteAddress,
            isTLS:         pop3Session.isTLS,
            on:   function(name, fn) { authCtx.on(name, fn);   return sessionFacade; },
            off:  function(name, fn) { authCtx.off(name, fn);  return sessionFacade; },
            once: function(name, fn) { authCtx.once(name, fn); return sessionFacade; },

            // POP3 has no push notifications (no IDLE equivalent), so the
            // notify* methods are no-ops here for API consistency with IMAP.
            notifyExists:   function() {},
            notifyRecent:   function() {},
            notifyExpunge:  function() {},
            notifyVanished: function() {},
            notifyFlags:    function() {},

            // POP3 is single-folder; currentFolder is always 'INBOX' after auth
            get currentFolder() { return pop3Session.authenticated ? 'INBOX' : null; },
            get idling()        { return false; }   // POP3 has no IDLE
          };
          ev.emit('mailboxSession', sessionFacade);
          authCtx.accept();
        },
        reject: function(msg) { authCtx.reject(msg); }
      };
      ev.emit('auth', authInfo);
    });

    // --- STARTTLS ---
    pop3Session.on('starttls', function() {
      let tlsOpts = {
        isServer: true,
        SNICallback: function(servername, cb) {
          resolveTlsContext(servername, cb);
        }
      };
      let tlsSocket = new tls.TLSSocket(socket, tlsOpts);
      tlsSocket.on('secure', function() {
        pop3Session.onTlsUpgraded && pop3Session.onTlsUpgraded();
        tlsSocket.on('data', function(chunk) { pop3Session.feed(chunk); });
      });
      tlsSocket.on('error', function() {
        ev.emit('tlsError', new Error('TLS handshake failed'));
        try { socket.destroy(); } catch(e) {}
      });
    });

    // --- close ---
    pop3Session.on('close', function() {
      try { socket.end(); } catch(e) {}
    });

    // Feed socket data into session
    socket.on('data', function(chunk) { pop3Session.feed(chunk); });
    socket.on('error', function() { pop3Session.close && pop3Session.close(); });
    socket.on('close', function() {
      pop3Session.close && pop3Session.close();
      context.connections.delete(socket);
    });

    // POP3 sessions are short — 10 minutes is generous
    socket.setTimeout(10 * 60 * 1000);
    socket.on('timeout', function() { try { socket.destroy(); } catch(e) {} });

    pop3Session.greet();
  }


  // ============================================================
  //  Listen
  // ============================================================

  function listen(cb) {
    let ports = context.ports;
    let pending = 0;
    let errors = [];

    function onReady() {
      pending--;
      if (pending === 0) {
        context.listening = true;
        ev.emit('ready');
        if (cb) cb(errors.length > 0 ? errors[0] : null);
      }
    }

    function startTcpServer(port, onConnection) {
      pending++;
      let tcpServer = net.createServer(function(socket) {
        onConnection(socket);
      });
      tcpServer.on('error', function(err) { errors.push(err); ev.emit('error', err); onReady(); });
      tcpServer.listen(port, function() { context.servers.push(tcpServer); onReady(); });
    }

    function startTlsServer(port, onConnection) {
      pending++;
      let tlsOpts = {
        SNICallback: function(servername, cb2) {
          resolveTlsContext(servername, cb2);
        }
      };

      // Find a default cert from registered domains
      let domainNames = Object.keys(context.domains);
      for (let i = 0; i < domainNames.length; i++) {
        let mat = context.domains[domainNames[i]];
        if (mat.tls && mat.tls.key && mat.tls.cert) {
          tlsOpts.key = mat.tls.key;
          tlsOpts.cert = mat.tls.cert;
          if (mat.tls.ca) tlsOpts.ca = mat.tls.ca;
          break;
        }
      }

      let tlsServer = tls.createServer(tlsOpts, function(socket) {
        onConnection(socket);
      });
      tlsServer.on('error', function(err) { errors.push(err); ev.emit('error', err); onReady(); });
      tlsServer.on('tlsClientError', function(err) { ev.emit('tlsError', err); });
      tlsServer.listen(port, function() { context.servers.push(tlsServer); onReady(); });
    }

    // --- SMTP ports ---
    // Inbound (port 25) — plain TCP, supports STARTTLS
    if (ports.inbound != null) {
      startTcpServer(ports.inbound, function(s) { handleConnection(s, false); });
    }

    // Submission (port 587) — plain TCP, AUTH required, supports STARTTLS
    if (ports.submission != null) {
      startTcpServer(ports.submission, function(s) { handleConnection(s, true); });
    }

    // Secure (port 465) — implicit TLS from start
    if (ports.secure != null) {
      startTlsServer(ports.secure, function(s) { handleConnection(s, true); });
    }

    // --- IMAP ports ---
    function imapConn(s) {
      let connId = (++context.connectionCounter).toString(36) + '-' +
                   crypto.randomBytes(4).toString('hex');
      handleImapConnection(s, s.remoteAddress || null, connId);
    }
    // IMAP (port 143) — plain TCP, supports STARTTLS
    if (ports.imap != null)  startTcpServer(ports.imap, imapConn);
    // IMAPS (port 993) — implicit TLS from start
    if (ports.imaps != null) startTlsServer(ports.imaps, imapConn);

    // --- POP3 ports ---
    function pop3Conn(s) {
      let connId = (++context.connectionCounter).toString(36) + '-' +
                   crypto.randomBytes(4).toString('hex');
      handlePop3Connection(s, s.remoteAddress || null, connId);
    }
    // POP3 (port 110) — plain TCP, supports STLS
    if (ports.pop3 != null)  startTcpServer(ports.pop3, pop3Conn);
    // POP3S (port 995) — implicit TLS from start
    if (ports.pop3s != null) startTlsServer(ports.pop3s, pop3Conn);

    if (pending === 0) {
      if (cb) cb(new Error('No ports configured'));
    }
  }


  // ============================================================
  //  Close
  // ============================================================

  function close(cb) {
    // Close outbound pool
    context.pool.closeAll();

    let pending = context.servers.length;

    if (pending === 0 && context.connections.size === 0) {
      context.listening = false;
      if (cb) cb();
      return;
    }

    // Stop accepting new connections
    for (let i = 0; i < context.servers.length; i++) {
      context.servers[i].close(function() {
        pending--;
        if (pending === 0 && context.connections.size === 0) {
          context.servers = [];
          context.listening = false;
          if (cb) { let fn = cb; cb = null; fn(); }
        }
      });
    }

    // Send 421 to all active connections
    context.connections.forEach(function(info, socket) {
      try {
        socket.write('421 ' + context.hostname + ' Server shutting down\r\n');
      } catch(e) {}
    });

    // Force close after timeout
    let closeTimer = setTimeout(function() {
      context.connections.forEach(function(info, socket) {
        try { socket.destroy(); } catch(e) {}
      });
      context.connections.clear();
      context.servers = [];
      context.listening = false;
      if (cb) { let fn = cb; cb = null; fn(); }
    }, context.closeTimeout);

    if (closeTimer.unref) closeTimer.unref();
  }


  // ============================================================
  //  Send (placeholder — needs SMTP client, built in step 5)
  // ============================================================

  function send(options, cb) {
    ev.emit('sending', options);

    let useRelay = options.relay || context.relay;

    if (useRelay) {
      // Relay mode
      let sendOptions = Object.assign({}, options);
      sendOptions.relay = useRelay;
      sendOptions.localHostname = context.hostname;

      // Compose + sign
      composeAndSign(options, function(err, raw, messageId) {
        if (err) { ev.emit('sendError', err, options); if (cb) cb(err); return; }
        sendOptions.raw = raw;
        sendOptions.messageId = messageId;
        sendMail(sendOptions, function(err, info) {
          if (err) { ev.emit('sendError', err, options); if (cb) cb(err); }
          else { ev.emit('sent', info); if (cb) cb(null, info); }
        });
      });
    } else {
      // Direct delivery via pool
      composeAndSign(options, function(err, raw, messageId) {
        if (err) { ev.emit('sendError', err, options); if (cb) cb(err); return; }

        let envFrom = extractAddress(options.from);
        let envTo = extractAddressList([].concat(options.to || []).concat(options.cc || []).concat(options.bcc || []));

        if (!envFrom || envTo.length === 0) {
          let e = new Error('Missing from or to');
          ev.emit('sendError', e, options);
          if (cb) cb(e);
          return;
        }

        let byDomain = {};
        for (let i = 0; i < envTo.length; i++) {
          let domain = envTo[i].split('@')[1] || '';
          if (!byDomain[domain]) byDomain[domain] = [];
          byDomain[domain].push(envTo[i]);
        }

        let domains = Object.keys(byDomain);
        for (let i = 0; i < domains.length; i++) {
          context.pool.enqueue({
            envFrom: envFrom,
            envTo: byDomain[domains[i]],
            raw: raw,
            messageId: messageId,
            cb: (i === domains.length - 1) ? cb : null
          });
        }
      });
    }
  }

  function composeAndSign(options, cb) {
    let composed = composeMessage({
      from: options.from, to: options.to, cc: options.cc, bcc: options.bcc,
      subject: options.subject, text: options.text, html: options.html,
      attachments: options.attachments, headers: options.headers,
      messageId: options.messageId, replyTo: options.replyTo, priority: options.priority
    });

    let fromDomain = '';
    let fromAddr = extractAddress(options.from);
    if (fromAddr) fromDomain = fromAddr.split('@')[1] || '';

    if (!fromDomain) {
      return cb(null, composed.raw, composed.messageId);
    }

    // Resolve DKIM material: addDomain → dkimCallback → skip
    resolveDkim(fromDomain, function(err, dkim) {
      if (err || !dkim || !dkim.privateKey) {
        // No DKIM available — send unsigned
        return cb(null, composed.raw, composed.messageId);
      }

      try {
        let signed = dkimSign(composed.raw, {
          domain: fromDomain,
          selector: dkim.selector,
          privateKey: dkim.privateKey,
          algo: dkim.algo || 'rsa-sha256'
        });
        cb(null, signed.message, composed.messageId);
      } catch(e) {
        // DKIM sign failed — send unsigned
        cb(null, composed.raw, composed.messageId);
      }
    });
  }

  // ============================================================
  //  API
  // ============================================================

  let api = {
    context: context,

    on:  function(name, fn) { ev.on(name, fn); },
    off: function(name, fn) { ev.off(name, fn); },

    addDomain: addDomain,
    removeDomain: removeDomain,

    // Generate a DSN (delivery status notification) and dispatch it via the
    // outbound SMTP client. Expects the same `options` shape as buildDsn;
    // `options.to` is the original envelope sender (who receives the DSN),
    // `options.originalMessage` is the message that couldn't be delivered.
    // The MAIL FROM on the DSN is empty per RFC 3461 §6 (prevents loops).
    //
    // Callback: cb(err, info) with the same shape as sendMail().
    sendDsn: function(options, cb) {
      let raw = buildDsn(Object.assign({ reportingMta: context.hostname }, options));
      sendMail({
        raw: raw,
        from: '',                                 // null return-path — RFC 3461 §6
        to: options.to,
        pool: context.pool,
        localHostname: context.hostname
      }, cb || function(){});
    },
    buildDsn: buildDsn,

    // Drop all cached TLS contexts. Call after rotating a cert (e.g. a fresh
    // Let's Encrypt certificate) so the next connection picks up the new one.
    // Takes an optional servername to clear only that entry.
    clearTlsCache: function(servername) {
      if (servername) context.secureContexts.delete(String(servername).toLowerCase());
      else            context.secureContexts.clear();
    },

    listen: listen,
    close: close,
    send: send,

    // Internal — exposed for advanced use
    resolveDkim: resolveDkim,
    resolveTlsContext: resolveTlsContext,

    get listening() { return context.listening; },
    get domains() { return Object.keys(context.domains); }
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


// ============================================================
//  createServer convenience
// ============================================================

function createServer(options) {
  return new Server(options);
}


export { Server, createServer };
