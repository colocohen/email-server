
import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

import { SMTPSession } from './session.js';
import { sendMail } from './client.js';
import { OutboundPool } from './pool.js';
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
    pool: null
  };

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
    // Check registered domains first
    let mat = getDomainMaterial(servername);
    if (mat && mat.tls && mat.tls.key && mat.tls.cert) {
      try {
        let ctx = tls.createSecureContext({
          key: mat.tls.key,
          cert: mat.tls.cert,
          ca: mat.tls.ca || undefined
        });
        return cb(null, ctx);
      } catch(e) {
        return cb(e);
      }
    }

    // Fallback to SNICallback
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
      authMethods: ['PLAIN', 'LOGIN']
    });

    // Inject parseMessage for body parsing at 'end' time
    session.setParseMessage(function(raw) {
      return parseMessageFn(raw);
    });

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

    // Auth event → forward to server
    session.on('auth', function(username, password, cb) {
      let sessionInfo = {
        username: username,
        password: password,
        remoteAddress: remoteAddress,
        isTLS: session.isTLS,
        accept: function() { cb.accept(); },
        reject: function() { cb.reject(); }
      };
      ev.emit('auth', sessionInfo);
    });

    // Message event → forward as inboundMail or submissionMail
    session.on('message', function(mail) {
      if (isSubmission) {
        let sessionInfo = {
          username: session.username,
          remoteAddress: remoteAddress,
          isTLS: session.isTLS,
          authenticated: session.authenticated
        };
        ev.emit('submissionMail', mail, sessionInfo);
      } else {
        // Run all auth checks in parallel, then fire inboundMail
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
            fromDomain: fromDomain,
            dkimResult: mail.auth.dkim,
            dkimDomain: mail.auth.dkimDomain || null,
            spfResult: mail.auth.spf,
            spfDomain: spfDomain
          }, function(err, dmarcResult) {
            if (err || !dmarcResult) {
              mail.auth.dmarc = 'none';
            } else {
              mail.auth.dmarc = dmarcResult.result;
              mail.auth.dmarcPolicy = dmarcResult.policy || null;
            }

            // Fire inboundMail — developer has all auth + headers
            ev.emit('inboundMail', mail);

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

    // Close event
    session.on('close', function() {
      try { socket.end(); } catch(e) {}
    });

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

    function startTcpServer(port, isSubmission) {
      pending++;
      let tcpServer = net.createServer(function(socket) {
        handleConnection(socket, isSubmission);
      });
      tcpServer.on('error', function(err) { errors.push(err); ev.emit('error', err); onReady(); });
      tcpServer.listen(port, function() { context.servers.push(tcpServer); onReady(); });
    }

    function startTlsServer(port, isSubmission) {
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
        handleConnection(socket, isSubmission);
      });
      tlsServer.on('error', function(err) { errors.push(err); ev.emit('error', err); onReady(); });
      tlsServer.on('tlsClientError', function(err) { ev.emit('tlsError', err); });
      tlsServer.listen(port, function() { context.servers.push(tlsServer); onReady(); });
    }

    // Inbound (port 25) — plain TCP, supports STARTTLS
    if (ports.inbound) {
      startTcpServer(ports.inbound, false);
    }

    // Submission (port 587) — plain TCP, AUTH required, supports STARTTLS
    if (ports.submission) {
      startTcpServer(ports.submission, true);
    }

    // Secure (port 465) — implicit TLS from start
    if (ports.secure) {
      startTlsServer(ports.secure, true);
    }

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
