
import net from 'node:net';
import tls from 'node:tls';

import { SMTPSession } from './smtp_session.js';
import { composeMessage } from './message.js';
import { toU8, u8ToStr, extractAddress, extractAddressList,
         domainToAscii, addressNeedsSmtputf8, addressForAsciiOnlyPeer } from './utils.js';
import * as dnsCache from './dns_cache.js';


// ============================================================
//  MX lookup (uses shared dns_cache)
// ============================================================

function resolveMX(domain, cb) {
  dnsCache.mx(domain, function(err, records) {
    if (err || !records || records.length === 0) {
      return cb(null, [{ exchange: domain, priority: 10 }]);
    }
    records.sort(function(a, b) { return a.priority - b.priority; });
    cb(null, records);
  });
}


// ============================================================
//  SMTPConnection — TCP socket + SMTPSession(isServer:false)
// ============================================================

function SMTPConnection(options, cb) {
  options = options || {};

  let host = options.host;
  let port = options.port || 25;
  let localHostname = options.localHostname || 'localhost';
  let timeout = options.timeout || 30000;

  let socket = null;
  let session = null;
  let done = false;

  function finish(err, result) {
    if (done) return;
    done = true;
    if (err && socket && !socket.destroyed) {
      try { socket.destroy(); } catch(e) {}
    }
    cb(err, result);
  }

  // Create session in client mode
  session = new SMTPSession({
    isServer: false,
    hostname: localHostname
  });

  // Wire session output to socket with backpressure
  session.on('send', function(data) {
    if (socket && !socket.destroyed) {
      try {
        let ok = socket.write(data);
        if (!ok) socket.pause();
      } catch(e) {}
    }
  });

  // Handle backpressure drain
  function setupDrain(sock) {
    sock.on('drain', function() {
      if (!sock.destroyed) sock.resume();
    });
  }

  session.on('error', function(err) {
    finish(err);
  });

  // STARTTLS event — upgrade socket to TLS
  session.on('starttls', function() {
    let tlsSocket = tls.connect({
      socket: socket,
      servername: host,
      rejectUnauthorized: false
    });

    tlsSocket.on('error', function(err) {
      finish(err);
    });

    tlsSocket.once('secureConnect', function() {
      // Replace socket and data handler
      socket = tlsSocket;
      tlsSocket.on('data', function(chunk) {
        session.feed(chunk);
      });
      setupDrain(tlsSocket);
      session.tlsUpgraded();
    });
  });

  // Ready event — EHLO done, connection ready
  session.on('ready', function() {
    let conn = {
      session: session,
      capabilities: session.capabilities,
      isTLS: session.isTLS,

      mailFrom: function(from, params, cb2) {
        session.mailFrom(from, params, cb2);
      },

      rcptTo: function(to, cb2) {
        session.rcptTo(to, cb2);
      },

      data: function(rawMessage, cb2) {
        session.data(rawMessage, cb2);
      },

      authPlain: function(user, pass, cb2) {
        session.authPlain(user, pass, cb2);
      },

      quit: function() {
        session.quit();
        setTimeout(function() {
          if (socket && !socket.destroyed) try { socket.end(); } catch(e) {}
        }, 300);
      },

      destroy: function() {
        if (socket && !socket.destroyed) try { socket.destroy(); } catch(e) {}
      },

      sendLine: session.sendLine,
      readReply: session.readReply
    };

    finish(null, conn);
  });

  // Connect TCP socket
  socket = net.connect(port, host);
  socket.setTimeout(timeout);

  socket.on('timeout', function() {
    finish(new Error('Timeout ' + host + ':' + port));
  });

  socket.on('error', function(err) {
    finish(err);
  });

  socket.on('close', function() {
    if (!done) finish(new Error('Connection closed'));
  });

  // Feed socket data into session
  socket.on('data', function(chunk) {
    session.feed(chunk);
  });
  setupDrain(socket);

  // Start: session waits for banner + sends EHLO
  session.greet();
}


// ============================================================
//  sendMail
// ============================================================

function sendMail(options, cb) {
  options = options || {};

  let composed = null;
  let rawMessage = null;

  if (options.raw) {
    rawMessage = toU8(options.raw);
  } else {
    composed = composeMessage({
      from: options.from, to: options.to, cc: options.cc, bcc: options.bcc,
      subject: options.subject, text: options.text, html: options.html,
      attachments: options.attachments, headers: options.headers,
      messageId: options.messageId, date: options.date,
      replyTo: options.replyTo, priority: options.priority
    });
    rawMessage = composed.raw;
  }

  let envFrom = extractAddress(options.from);
  let envTo = extractAddressList([].concat(options.to || []).concat(options.cc || []).concat(options.bcc || []));

  if (!envFrom || envTo.length === 0) return cb(new Error('Missing from or to'));

  let messageId = composed ? composed.messageId : (options.messageId || null);

  if (options.relay) {
    return sendViaRelay(options.relay, envFrom, envTo, rawMessage, messageId, options, cb);
  }

  // Group recipients by (Punycode-encoded) domain — what MX lookup needs.
  // IDN local-parts + domains are kept in their original form for handoff;
  // the ASCII domain is used only for DNS/MX. Each group also tracks
  // whether the envelope requires SMTPUTF8 (non-ASCII local-parts), because
  // if any recipient needs it, the whole envelope to that domain does.
  let byDomain = {};
  for (let i = 0; i < envTo.length; i++) {
    let raw = envTo[i];
    let at = raw.lastIndexOf('@');
    if (at < 0) continue;
    let domain = raw.substring(at + 1);
    let asciiDomain = domainToAscii(domain) || domain;  // preserve on failure
    if (!byDomain[asciiDomain]) {
      byDomain[asciiDomain] = { recipients: [], needsUtf8: false };
    }
    byDomain[asciiDomain].recipients.push(raw);
    if (addressNeedsSmtputf8(raw)) byDomain[asciiDomain].needsUtf8 = true;
  }
  // Also track whether the envelope sender's local-part is non-ASCII —
  // that propagates the SMTPUTF8 requirement to every delivery.
  let fromNeedsUtf8 = addressNeedsSmtputf8(envFrom);

  let domains = Object.keys(byDomain);
  let results = [], errors = [], pending = domains.length;

  if (pending === 0) return cb(new Error('No valid recipients'));

  for (let i = 0; i < domains.length; i++) {
    (function(domain) {
      let group = byDomain[domain];
      let envelopeNeedsUtf8 = group.needsUtf8 || fromNeedsUtf8;
      deliverToDomain(domain, envFrom, group.recipients, rawMessage,
        Object.assign({}, options, { envelopeNeedsUtf8: envelopeNeedsUtf8 }),
        function(err, info) {
          if (err) errors.push({ domain: domain, error: err });
          else results.push(info);
          if (--pending === 0) {
            if (errors.length > 0 && results.length === 0) cb(errors[0].error);
            else cb(null, { messageId: messageId, accepted: results, rejected: errors });
          }
        });
    })(domains[i]);
  }
}


// ============================================================
//  Direct delivery via MX
// ============================================================

function deliverToDomain(domain, envFrom, recipients, rawMessage, options, cb) {
  resolveMX(domain, function(err, mxRecords) {
    if (err) return cb(err);
    let mxIndex = 0;

    function tryNextMX() {
      if (mxIndex >= mxRecords.length) return cb(new Error('All MX failed for ' + domain));
      let mx = mxRecords[mxIndex++];

      SMTPConnection({
        host: mx.exchange, port: 25,
        localHostname: options.localHostname || 'localhost',
        timeout: options.timeout || 30000,
        ignoreTLS: options.ignoreTLS || false
      }, function(err, conn) {
        if (err) return tryNextMX();

        // After EHLO, `conn.capabilities` reflects the peer's supported
        // extensions. Decide the SMTPUTF8 posture for this transaction:
        //   • peer supports & envelope needs → pass SMTPUTF8 param; addresses stay UTF-8
        //   • peer supports & envelope doesn't need → no-op (both harmless)
        //   • peer doesn't support & envelope needs → try Punycode fallback:
        //       every recipient (and the sender) is rewritten via
        //       addressForAsciiOnlyPeer. If any yields null (non-ASCII
        //       local-part), bounce that delivery — there is no safe wire
        //       representation.
        let peerCaps = conn.capabilities || {};
        let peerUtf8 = !!peerCaps.smtputf8;
        let wantUtf8 = !!options.envelopeNeedsUtf8;

        let effFrom       = envFrom;
        let effRecipients = recipients.slice();

        if (wantUtf8 && !peerUtf8) {
          // Fallback: Punycode domains. Non-ASCII local-parts are fatal here.
          let mappedFrom = addressForAsciiOnlyPeer(envFrom);
          if (mappedFrom == null) {
            conn.quit();
            return cb(new Error('Peer ' + mx.exchange + ' does not advertise SMTPUTF8 and sender local-part is non-ASCII'));
          }
          effFrom = mappedFrom;

          let mappedTo = [];
          for (let r = 0; r < recipients.length; r++) {
            let m = addressForAsciiOnlyPeer(recipients[r]);
            if (m == null) {
              conn.quit();
              return cb(new Error('Peer ' + mx.exchange + ' does not advertise SMTPUTF8 and recipient ' + recipients[r] + ' has a non-ASCII local-part'));
            }
            mappedTo.push(m);
          }
          effRecipients = mappedTo;
          wantUtf8 = false;   // after fallback we no longer need the param
        } else if (!wantUtf8 && peerUtf8) {
          // Pure-ASCII envelope over a UTF-8-capable peer: still Punycode
          // the domain for the wire (purely defensive — harmless either way).
          effFrom       = addressForAsciiOnlyPeer(envFrom)       || envFrom;
          effRecipients = recipients.map(function(r) { return addressForAsciiOnlyPeer(r) || r; });
        }
        // wantUtf8 && peerUtf8: pass addresses as-is (UTF-8 on the wire).

        let mailParams = { size: rawMessage.length };
        if (wantUtf8 && peerUtf8) mailParams.smtputf8 = true;

        conn.mailFrom(effFrom, mailParams, function(err) {
          if (err) { conn.destroy(); return tryNextMX(); }

          let accepted = [], rejected = [], idx = 0;

          function nextRcpt() {
            if (idx >= effRecipients.length) {
              if (accepted.length === 0) { conn.quit(); return cb(new Error('All recipients rejected')); }
              conn.data(rawMessage, function(err) {
                conn.quit();
                if (err) return cb(err);
                cb(null, { host: mx.exchange, accepted: accepted, rejected: rejected });
              });
              return;
            }
            conn.rcptTo(effRecipients[idx], function(err) {
              // Track the ORIGINAL address in accepted/rejected so callers
              // see what they asked for, not the Punycoded form.
              if (err) rejected.push(recipients[idx]); else accepted.push(recipients[idx]);
              idx++;
              nextRcpt();
            });
          }
          nextRcpt();
        });
      });
    }
    tryNextMX();
  });
}


// ============================================================
//  Relay delivery
// ============================================================

function sendViaRelay(relay, envFrom, envTo, rawMessage, messageId, options, cb) {
  SMTPConnection({
    host: relay.host, port: relay.port || 587,
    localHostname: relay.localHostname || options.localHostname || 'localhost',
    timeout: relay.timeout || 30000,
    ignoreTLS: relay.ignoreTLS || false
  }, function(err, conn) {
    if (err) return cb(err);

    function afterAuth() {
      conn.mailFrom(envFrom, {}, function(err) {
        if (err) { conn.destroy(); return cb(err); }

        let accepted = [], idx = 0;
        function nextRcpt() {
          if (idx >= envTo.length) {
            if (accepted.length === 0) { conn.quit(); return cb(new Error('All recipients rejected')); }
            conn.data(rawMessage, function(err) {
              conn.quit();
              if (err) return cb(err);
              cb(null, { messageId: messageId, host: relay.host, accepted: accepted });
            });
            return;
          }
          conn.rcptTo(envTo[idx], function(err) {
            if (!err) accepted.push(envTo[idx]);
            idx++;
            nextRcpt();
          });
        }
        nextRcpt();
      });
    }

    if (relay.auth && relay.auth.user && relay.auth.pass) {
      conn.authPlain(relay.auth.user, relay.auth.pass, function(err) {
        if (err) { conn.destroy(); return cb(err); }
        afterAuth();
      });
    } else {
      afterAuth();
    }
  });
}


export { sendMail, resolveMX, SMTPConnection };
