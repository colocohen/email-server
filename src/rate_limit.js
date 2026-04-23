// ============================================================================
//  rate_limit.js
// ----------------------------------------------------------------------------
//  Per-IP rate limiting and brute-force protection shared across all three
//  inbound protocols (SMTP, IMAP, POP3). Opt-in via createServer's
//  `rateLimit` option; when omitted the limiter is a no-op.
//
//  What's tracked, per remote IP:
//    • active connection count (reject if at cap)
//    • recent authentication failures within a sliding window (ban if too many)
//    • inbound SMTP messages accepted in the current hour (reject if over cap)
//    • manual bans (temporary, auto-expire)
//
//  Memory is bounded — housekeeping runs on every decision and periodically,
//  dropping entries whose relevance has lapsed (no active connections, no
//  recent failures, not banned). See `gc()`.
//
//  Configuration shape (all fields optional — omit to disable that check):
//
//     {
//       maxConnectionsPerIp:    10,          // concurrent; reject over
//       maxAuthFailuresPerIp:   5,           // within the window, then ban
//       authFailureWindow:      300000,      // ms, default 5 min
//       banDuration:            3600000,     // ms, default 1 hour
//       maxMessagesPerHourPerIp: 100,        // SMTP-inbound acceptances
//       exemptIps:              ['127.0.0.1','::1']
//     }
//
//  Public API:
//
//     const rl = createRateLimiter(config);
//     rl.canConnect(ip)         → { ok: true } | { ok: false, reason, retryAfter? }
//     rl.recordConnection(ip)   — call after canConnect passes; pairs with release
//     rl.releaseConnection(ip)  — on socket close
//     rl.recordAuthFailure(ip)  — on a rejected login/authenticate
//     rl.recordAuthSuccess(ip)  — clears the failure window for that IP
//     rl.canAcceptMessage(ip)   → { ok, reason? }  — SMTP inbound only
//     rl.recordMessage(ip)      — after accept
//     rl.ban(ip, durationMs)    — manual ban from developer code
//     rl.unban(ip)              — manual clear
//     rl.close()                — stop GC timer
//
//  The limiter is designed to fail safe: if ip is null/undefined (e.g. unix
//  socket or proxy header missing), every check returns ok=true. Callers
//  should prefer best-effort enforcement over rejecting real users.
// ============================================================================


function createRateLimiter(config) {
  config = config || {};

  const maxConn         = config.maxConnectionsPerIp      || 0;     // 0 = unlimited
  const maxAuthFail     = config.maxAuthFailuresPerIp     || 0;
  const authWindow      = config.authFailureWindow        || 300000;
  const banDuration     = config.banDuration              || 3600000;
  const maxMsgPerHour   = config.maxMessagesPerHourPerIp  || 0;
  const hourWindow      = 60 * 60 * 1000;

  const exemptSet = new Set(config.exemptIps || []);

  // Per-IP state. Keys cleaned up when no longer relevant.
  //   connections: count of active connections
  //   failures:    array of failure timestamps (sliding window)
  //   messages:    array of timestamps of accepted messages (for hourly cap)
  //   bannedUntil: epoch ms; deletion implicit when now > bannedUntil
  const state = new Map();   // ip → { connections, failures, messages, bannedUntil }

  function getEntry(ip) {
    let e = state.get(ip);
    if (!e) {
      e = { connections: 0, failures: [], messages: [], bannedUntil: 0 };
      state.set(ip, e);
    }
    return e;
  }

  // Drop the entry if nothing meaningful is being tracked.
  function maybeEvict(ip, e) {
    if (e.connections > 0) return;
    if (e.failures.length > 0) return;
    if (e.messages.length > 0) return;
    if (e.bannedUntil > Date.now()) return;
    state.delete(ip);
  }

  // Prune stale failure / message timestamps. In-place.
  function prune(e, now) {
    if (e.failures.length > 0) {
      let cutoff = now - authWindow;
      let i = 0;
      while (i < e.failures.length && e.failures[i] < cutoff) i++;
      if (i > 0) e.failures.splice(0, i);
    }
    if (e.messages.length > 0) {
      let cutoff = now - hourWindow;
      let i = 0;
      while (i < e.messages.length && e.messages[i] < cutoff) i++;
      if (i > 0) e.messages.splice(0, i);
    }
  }

  function isExempt(ip) {
    return !ip || exemptSet.has(ip);
  }

  // ---------------- Connection-level ----------------

  function canConnect(ip) {
    if (isExempt(ip)) return { ok: true };
    let e = state.get(ip);
    let now = Date.now();

    if (e && e.bannedUntil > now) {
      return {
        ok: false,
        reason: 'banned',
        retryAfter: Math.ceil((e.bannedUntil - now) / 1000)
      };
    }
    if (maxConn > 0 && e && e.connections >= maxConn) {
      return { ok: false, reason: 'too_many_connections' };
    }
    return { ok: true };
  }

  function recordConnection(ip) {
    if (isExempt(ip)) return;
    getEntry(ip).connections++;
  }

  function releaseConnection(ip) {
    if (isExempt(ip)) return;
    let e = state.get(ip);
    if (!e) return;
    if (e.connections > 0) e.connections--;
    maybeEvict(ip, e);
  }

  // ---------------- Auth failure tracking ----------------

  function recordAuthFailure(ip) {
    if (isExempt(ip)) return { banned: false };
    if (maxAuthFail === 0) return { banned: false };

    let e = getEntry(ip);
    let now = Date.now();
    prune(e, now);
    e.failures.push(now);

    if (e.failures.length >= maxAuthFail) {
      e.bannedUntil = now + banDuration;
      e.failures = [];    // fresh ban resets counter
      return { banned: true, bannedUntil: e.bannedUntil };
    }
    return { banned: false, failuresInWindow: e.failures.length };
  }

  function recordAuthSuccess(ip) {
    if (isExempt(ip)) return;
    let e = state.get(ip);
    if (!e) return;
    // A successful auth clears the failure window — the IP has proven
    // it's a legitimate client in possession of real credentials.
    if (e.failures.length > 0) e.failures = [];
    maybeEvict(ip, e);
  }

  // ---------------- SMTP inbound message rate ----------------

  function canAcceptMessage(ip) {
    if (isExempt(ip)) return { ok: true };
    if (maxMsgPerHour === 0) return { ok: true };

    let e = state.get(ip);
    if (!e) return { ok: true };
    let now = Date.now();
    prune(e, now);
    if (e.messages.length >= maxMsgPerHour) {
      return { ok: false, reason: 'hourly_message_cap' };
    }
    return { ok: true };
  }

  function recordMessage(ip) {
    if (isExempt(ip)) return;
    if (maxMsgPerHour === 0) return;
    let e = getEntry(ip);
    let now = Date.now();
    prune(e, now);
    e.messages.push(now);
  }

  // ---------------- Manual ban / unban ----------------

  function ban(ip, durationMs) {
    if (!ip) return;
    let e = getEntry(ip);
    let now = Date.now();
    e.bannedUntil = now + (durationMs || banDuration);
  }

  function unban(ip) {
    if (!ip) return;
    let e = state.get(ip);
    if (!e) return;
    e.bannedUntil = 0;
    e.failures = [];
    maybeEvict(ip, e);
  }

  // ---------------- GC (trim bans that have expired) ----------------

  function gc() {
    let now = Date.now();
    let dead = [];
    state.forEach(function(e, ip) {
      prune(e, now);
      if (e.bannedUntil !== 0 && e.bannedUntil <= now) e.bannedUntil = 0;
      if (e.connections === 0 && e.failures.length === 0 &&
          e.messages.length === 0 && e.bannedUntil === 0) {
        dead.push(ip);
      }
    });
    for (let i = 0; i < dead.length; i++) state.delete(dead[i]);
  }

  // Run GC periodically. The interval is unref'd so it doesn't keep a
  // Node process alive purely for rate-limit housekeeping.
  const gcTimer = setInterval(gc, Math.min(authWindow, hourWindow) / 2);
  if (gcTimer.unref) gcTimer.unref();

  function close() {
    clearInterval(gcTimer);
    state.clear();
  }

  // Exposed for tests + advanced developer use.
  function snapshot(ip) {
    let e = state.get(ip);
    if (!e) return null;
    return {
      connections: e.connections,
      failuresInWindow: e.failures.length,
      messagesInHour: e.messages.length,
      bannedUntil: e.bannedUntil > Date.now() ? e.bannedUntil : 0
    };
  }

  return {
    canConnect:         canConnect,
    recordConnection:   recordConnection,
    releaseConnection:  releaseConnection,
    recordAuthFailure:  recordAuthFailure,
    recordAuthSuccess:  recordAuthSuccess,
    canAcceptMessage:   canAcceptMessage,
    recordMessage:      recordMessage,
    ban:                ban,
    unban:              unban,
    close:              close,
    snapshot:           snapshot
  };
}


export { createRateLimiter };
