
import { EventEmitter } from 'node:events';

import { SMTPConnection } from './client.js';
import * as dnsCache from './dns-cache.js';


// ============================================================
//  Default settings
// ============================================================

const DEFAULTS = {
  maxPerDomain: 3,
  maxMessagesPerConn: 100,
  idleTimeout: 30000,
  rateLimitPerMinute: 60,
  reconnectDelay: 1000,
  mxCacheTTL: 300000,          // 5 minutes
  retryDelays: [
    60000,       // 1 min
    300000,      // 5 min
    1800000,     // 30 min
    7200000,     // 2 hours
    14400000     // 4 hours
  ]
};


// ============================================================
//  OutboundPool
// ============================================================

function OutboundPool(options) {
  if (!(this instanceof OutboundPool)) return new OutboundPool(options);
  options = options || {};

  const ev = new EventEmitter();
  const self = this;

  let settings = {
    maxPerDomain:        options.maxPerDomain        || DEFAULTS.maxPerDomain,
    maxMessagesPerConn:  options.maxMessagesPerConn  || DEFAULTS.maxMessagesPerConn,
    idleTimeout:         options.idleTimeout         || DEFAULTS.idleTimeout,
    rateLimitPerMinute:  options.rateLimitPerMinute  || DEFAULTS.rateLimitPerMinute,
    reconnectDelay:      options.reconnectDelay      || DEFAULTS.reconnectDelay,
    mxCacheTTL:          options.mxCacheTTL          || DEFAULTS.mxCacheTTL,
    retryDelays:         options.retryDelays         || DEFAULTS.retryDelays,
    localHostname:       options.localHostname       || 'localhost',
    ignoreTLS:           options.ignoreTLS           || false,
    timeout:             options.timeout             || 30000
  };

  // Per-domain pools
  let pools = {};

  // Scheduler timer
  let schedulerTimer = null;
  let running = false;


  // ============================================================
  //  MX lookup (uses shared dns-cache)
  // ============================================================

  function getMX(domain, cb) {
    dnsCache.mx(domain, function(err, records) {
      if (err || !records || records.length === 0) {
        records = [{ exchange: domain, priority: 10 }];
      }
      records.sort(function(a, b) { return a.priority - b.priority; });
      cb(null, records);
    });
  }


  // ============================================================
  //  Domain pool management
  // ============================================================

  function getPool(domain) {
    if (!pools[domain]) {
      pools[domain] = {
        domain: domain,
        connections: [],       // { conn, busy, messageCount, idleTimer, alive }
        pending: [],           // { message, cb, attempts, nextRetry, id }
        stats: {
          lastConnectTime: 0,
          lastDisconnectTime: 0,
          activeConnections: 0,
          sentThisMinute: 0,
          minuteStart: Date.now(),
          backoffUntil: 0
        }
      };
    }
    return pools[domain];
  }

  function cleanPool(domain) {
    let pool = pools[domain];
    if (!pool) return;
    if (pool.connections.length === 0 && pool.pending.length === 0) {
      delete pools[domain];
      dnsCache.remove(domain);
    }
  }


  // ============================================================
  //  Rate limiting check
  // ============================================================

  function canSendNow(pool) {
    let stats = pool.stats;
    let now = Date.now();

    // Backoff active?
    if (now < stats.backoffUntil) return false;

    // Rate limit per minute
    if (now - stats.minuteStart > 60000) {
      stats.sentThisMinute = 0;
      stats.minuteStart = now;
    }
    if (stats.sentThisMinute >= settings.rateLimitPerMinute) return false;

    return true;
  }

  function canOpenConnection(pool) {
    let stats = pool.stats;
    let now = Date.now();

    // Max connections reached?
    if (stats.activeConnections >= settings.maxPerDomain) return false;

    // Too soon after last disconnect?
    if (stats.lastDisconnectTime > 0 && now - stats.lastDisconnectTime < settings.reconnectDelay) return false;

    // Backoff active?
    if (now < stats.backoffUntil) return false;

    return true;
  }


  // ============================================================
  //  Connection management
  // ============================================================

  function openConnection(pool, cb) {
    let domain = pool.domain;
    pool.stats.lastConnectTime = Date.now();
    pool.stats.activeConnections++;

    getMX(domain, function(err, mxRecords) {
      if (err) {
        pool.stats.activeConnections--;
        return cb(err);
      }

      let mxIndex = 0;

      function tryNextMX() {
        if (mxIndex >= mxRecords.length) {
          pool.stats.activeConnections--;
          return cb(new Error('All MX failed for ' + domain));
        }

        let mx = mxRecords[mxIndex++];

        SMTPConnection({
          host: mx.exchange,
          port: 25,
          localHostname: settings.localHostname,
          timeout: settings.timeout,
          ignoreTLS: settings.ignoreTLS
        }, function(err, conn) {
          if (err) return tryNextMX();

          let entry = {
            conn: conn,
            busy: false,
            messageCount: 0,
            idleTimer: null,
            alive: true,
            mx: mx.exchange
          };

          pool.connections.push(entry);
          cb(null, entry);
        });
      }

      tryNextMX();
    });
  }

  function closeConnection(pool, entry) {
    entry.alive = false;
    if (entry.idleTimer) {
      clearTimeout(entry.idleTimer);
      entry.idleTimer = null;
    }

    try { entry.conn.quit(); } catch(e) {}

    let idx = pool.connections.indexOf(entry);
    if (idx >= 0) pool.connections.splice(idx, 1);

    pool.stats.activeConnections--;
    pool.stats.lastDisconnectTime = Date.now();

    cleanPool(pool.domain);
  }

  function startIdleTimer(pool, entry) {
    if (entry.idleTimer) clearTimeout(entry.idleTimer);
    entry.idleTimer = setTimeout(function() {
      closeConnection(pool, entry);
    }, settings.idleTimeout);
  }

  function checkConnectionHealth(entry, cb) {
    // Send NOOP to verify connection is alive
    try {
      entry.conn.sendLine('NOOP');
      entry.conn.readReply(function(reply) {
        cb(reply.code === 250);
      });
    } catch(e) {
      cb(false);
    }
  }


  // ============================================================
  //  Send a message through a connection
  // ============================================================

  function sendMessage(pool, entry, msg) {
    entry.busy = true;
    if (entry.idleTimer) {
      clearTimeout(entry.idleTimer);
      entry.idleTimer = null;
    }

    let envFrom = msg.envFrom;
    let envTo = msg.envTo;
    let rawMessage = msg.raw;

    entry.conn.mailFrom(envFrom, { size: rawMessage.length }, function(err) {
      if (err) {
        entry.busy = false;
        handleSendError(pool, entry, msg, err);
        return;
      }

      // Send all RCPT TO
      let accepted = [];
      let rejected = [];
      let rcptIdx = 0;

      function nextRcpt() {
        if (rcptIdx >= envTo.length) {
          if (accepted.length === 0) {
            entry.busy = false;
            let error = new Error('All recipients rejected');
            error.permanent = true;
            finishMessage(pool, entry, msg, error, null);
            return;
          }

          entry.conn.data(rawMessage, function(err, reply) {
            entry.busy = false;
            entry.messageCount++;
            pool.stats.sentThisMinute++;

            if (err) {
              handleSendError(pool, entry, msg, err);
            } else {
              finishMessage(pool, entry, msg, null, {
                accepted: accepted,
                rejected: rejected,
                mx: entry.mx
              });
            }
          });
          return;
        }

        entry.conn.rcptTo(envTo[rcptIdx], function(err) {
          if (err) rejected.push(envTo[rcptIdx]);
          else accepted.push(envTo[rcptIdx]);
          rcptIdx++;
          nextRcpt();
        });
      }

      nextRcpt();
    });
  }


  // ============================================================
  //  Handle send result
  // ============================================================

  function finishMessage(pool, entry, msg, err, info) {
    if (err) {
      // Is it retryable?
      let retryable = !err.permanent && msg.attempts < settings.retryDelays.length;

      if (retryable) {
        msg.attempts++;
        msg.nextRetry = Date.now() + settings.retryDelays[msg.attempts - 1];
        pool.pending.push(msg);
        ev.emit('retry', { id: msg.id, attempts: msg.attempts, error: err.message, nextRetry: msg.nextRetry });
      } else {
        // Permanent failure
        if (msg.cb) msg.cb(err);
        ev.emit('bounce', { id: msg.id, from: msg.envFrom, to: msg.envTo, error: err.message });
      }
    } else {
      if (msg.cb) msg.cb(null, { messageId: msg.messageId, accepted: info.accepted, rejected: info.rejected, mx: info.mx });
      ev.emit('sent', { id: msg.id, messageId: msg.messageId, accepted: info.accepted, mx: info.mx });
    }

    // After message: reuse connection or close
    afterMessageSent(pool, entry);
  }

  function handleSendError(pool, entry, msg, err) {
    let code = 0;
    let m = /(\d{3})/.exec(err.message);
    if (m) code = parseInt(m[1], 10);

    // 421 — close connection, backoff
    if (code === 421) {
      pool.stats.backoffUntil = Date.now() + settings.reconnectDelay * 10;
      closeConnection(pool, entry);
      err.permanent = false;
      finishMessage(pool, entry, msg, err, null);
      return;
    }

    // 5xx — permanent
    if (code >= 500 && code < 600) {
      err.permanent = true;
      finishMessage(pool, entry, msg, err, null);
      afterMessageSent(pool, entry);
      return;
    }

    // 4xx — temporary
    err.permanent = false;
    finishMessage(pool, entry, msg, err, null);
    afterMessageSent(pool, entry);
  }

  function afterMessageSent(pool, entry) {
    if (!entry.alive) return;

    // Max messages per connection reached?
    if (entry.messageCount >= settings.maxMessagesPerConn) {
      closeConnection(pool, entry);
      return;
    }

    // More messages waiting?
    let next = pickNextMessage(pool);
    if (next) {
      // RSET to clear transaction, then send next
      try {
        entry.conn.sendLine('RSET');
        entry.conn.readReply(function(reply) {
          if (reply.code === 250) {
            sendMessage(pool, entry, next);
          } else {
            // RSET failed — connection is dead
            closeConnection(pool, entry);
            pool.pending.unshift(next);
          }
        });
      } catch(e) {
        closeConnection(pool, entry);
        pool.pending.unshift(next);
      }
    } else {
      // No more messages — idle
      entry.busy = false;
      startIdleTimer(pool, entry);
    }
  }


  // ============================================================
  //  Message queue management
  // ============================================================

  let messageIdCounter = 0;

  function pickNextMessage(pool) {
    let now = Date.now();
    for (let i = 0; i < pool.pending.length; i++) {
      if (pool.pending[i].nextRetry <= now) {
        return pool.pending.splice(i, 1)[0];
      }
    }
    return null;
  }


  // ============================================================
  //  Scheduler
  // ============================================================

  function schedule() {
    let domains = Object.keys(pools);
    let hasPending = false;

    for (let i = 0; i < domains.length; i++) {
      let pool = pools[domains[i]];
      if (!pool || pool.pending.length === 0) continue;
      hasPending = true;
      if (!canSendNow(pool)) continue;

      // Try to find an idle connection
      let idleEntry = null;
      for (let j = 0; j < pool.connections.length; j++) {
        if (!pool.connections[j].busy && pool.connections[j].alive) {
          idleEntry = pool.connections[j];
          break;
        }
      }

      let msg = pickNextMessage(pool);
      if (!msg) continue;

      if (idleEntry) {
        // Check health before reusing
        if (idleEntry.idleTimer) {
          clearTimeout(idleEntry.idleTimer);
          idleEntry.idleTimer = null;
        }

        checkConnectionHealth(idleEntry, function(alive) {
          if (alive) {
            try {
              idleEntry.conn.sendLine('RSET');
              idleEntry.conn.readReply(function(reply) {
                if (reply.code === 250) {
                  sendMessage(pool, idleEntry, msg);
                } else {
                  closeConnection(pool, idleEntry);
                  pool.pending.unshift(msg);
                }
              });
            } catch(e) {
              closeConnection(pool, idleEntry);
              pool.pending.unshift(msg);
            }
          } else {
            closeConnection(pool, idleEntry);
            pool.pending.unshift(msg);
          }
        });
      } else if (canOpenConnection(pool)) {
        openConnection(pool, function(err, entry) {
          if (err) {
            pool.pending.unshift(msg);
            return;
          }
          sendMessage(pool, entry, msg);
        });
      } else {
        pool.pending.unshift(msg);
      }
    }

    // Auto-stop when nothing pending
    if (!hasPending && schedulerTimer) {
      stopScheduler();
    }
  }

  function startScheduler() {
    if (schedulerTimer) return;
    running = true;
    schedulerTimer = setInterval(schedule, 1000);
    if (schedulerTimer.unref) schedulerTimer.unref(); // don't prevent process exit
  }

  function stopScheduler() {
    running = false;
    if (schedulerTimer) {
      clearInterval(schedulerTimer);
      schedulerTimer = null;
    }
  }


  // ============================================================
  //  Public API: enqueue message
  // ============================================================

  function enqueue(msg) {
    // msg: { envFrom, envTo: [], raw, messageId, cb }
    let domain = msg.envTo[0].split('@')[1] || '';
    let pool = getPool(domain);

    let entry = {
      id: ++messageIdCounter,
      envFrom: msg.envFrom,
      envTo: msg.envTo,
      raw: msg.raw,
      messageId: msg.messageId || null,
      cb: msg.cb || null,
      attempts: 0,
      nextRetry: 0
    };

    pool.pending.push(entry);

    // Make sure scheduler is running
    if (!running) startScheduler();

    // Trigger immediate schedule
    schedule();

    return entry.id;
  }


  // ============================================================
  //  Public API: close all
  // ============================================================

  function closeAll(cb) {
    stopScheduler();

    let domains = Object.keys(pools);
    for (let i = 0; i < domains.length; i++) {
      let pool = pools[domains[i]];
      // Fail all pending
      for (let j = 0; j < pool.pending.length; j++) {
        let msg = pool.pending[j];
        if (msg.cb) msg.cb(new Error('Pool shutting down'));
      }
      pool.pending = [];

      // Close all connections
      let conns = pool.connections.slice();
      for (let k = 0; k < conns.length; k++) {
        closeConnection(pool, conns[k]);
      }
    }

    pools = {};
    if (cb) cb();
  }


  // ============================================================
  //  Public API: stats
  // ============================================================

  function getStats() {
    let stats = {};
    let domains = Object.keys(pools);
    for (let i = 0; i < domains.length; i++) {
      let pool = pools[domains[i]];
      stats[domains[i]] = {
        connections: pool.connections.length,
        busy: pool.connections.filter(function(c) { return c.busy; }).length,
        pending: pool.pending.length,
        sentThisMinute: pool.stats.sentThisMinute,
        backoffUntil: pool.stats.backoffUntil > Date.now() ? pool.stats.backoffUntil : null
      };
    }
    return stats;
  }


  // ============================================================
  //  API
  // ============================================================

  let api = {
    enqueue: enqueue,
    closeAll: closeAll,
    getStats: getStats,
    startScheduler: startScheduler,
    stopScheduler: stopScheduler,

    on:  function(name, fn) { ev.on(name, fn); },
    off: function(name, fn) { ev.off(name, fn); },

    get poolCount() { return Object.keys(pools).length; },
    get settings() { return Object.assign({}, settings); }
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


export { OutboundPool, DEFAULTS as POOL_DEFAULTS };
