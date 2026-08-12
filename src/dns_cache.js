
import dns from 'node:dns';
import { domainToAscii, isAscii } from './utils.js';


// ============================================================
//  Shared DNS cache — single cache used by dkim, spf, dmarc, rdns, pool
// ============================================================
//
// All callers route through here, so this is the single chokepoint where we
// apply IDN Punycode normalization. Callers can pass UTF-8 domain names
// ('אתר.co.il') and the resolver will transparently look up the ASCII form
// ('xn--4db2cf.co.il'). The cache key is also the ASCII form, so lookups
// for the same domain spelled two different ways share a cache entry.

const DEFAULT_TTL = 300000;      // 5 minutes — positive results
const NEGATIVE_TTL = 60000;      // 1 minute — failed lookups (NXDOMAIN etc.)
                                 // Without negative caching, a sender spamming
                                 // from a nonexistent domain triggers a fresh
                                 // DNS query on EVERY message (SPF+DKIM+DMARC
                                 // each ask) — an easy amplification vector.
const MAX_ENTRIES = 10000;       // hard cap — evict oldest-expiring beyond this
let cache = new Map();           // Map preserves insertion order → cheap FIFO-ish eviction

// Periodic GC: drop expired entries so the cache doesn't grow unbounded on a
// busy server seeing many unique domains. unref'd so it never keeps the
// process alive (same pattern as rate_limit.js).
const GC_INTERVAL = 60000;
const gcTimer = setInterval(function() {
  let now = Date.now();
  cache.forEach(function(entry, key) {
    if (entry.expires <= now) cache.delete(key);
  });
}, GC_INTERVAL);
if (gcTimer.unref) gcTimer.unref();

function cacheSet(key, entry) {
  // Enforce the size cap: delete oldest-inserted entries first. Map
  // iteration order is insertion order, so this is O(evicted).
  if (cache.size >= MAX_ENTRIES) {
    let toEvict = cache.size - MAX_ENTRIES + 1;
    for (let k of cache.keys()) {
      cache.delete(k);
      if (--toEvict <= 0) break;
    }
  }
  cache.set(key, entry);
}

// PTR lookups take an IP, not a domain — never IDN-encode those.
function normalizeName(type, name) {
  if (!name) return name;
  if (type === 'PTR') return name;
  if (isAscii(name)) return name;
  let ascii = domainToAscii(name);
  return ascii || name;
}

// In-flight request coalescing: if 3 concurrent messages from the same domain
// all trigger an SPF TXT lookup, only ONE query goes to the resolver — the
// rest attach to its completion. Prevents thundering-herd on cache misses.
let inFlight = new Map();   // key → [cb, cb, ...]

function lookup(type, name, cb) {
  name = normalizeName(type, name);
  let key = type + ':' + name;
  let cached = cache.get(key);
  if (cached && cached.expires > Date.now()) {
    return cb(cached.err || null, cached.data);
  }

  let resolver;
  switch (type) {
    case 'TXT':   resolver = dns.resolveTxt; break;
    case 'A':     resolver = dns.resolve4; break;
    case 'AAAA':  resolver = dns.resolve6; break;
    case 'MX':    resolver = dns.resolveMx; break;
    case 'PTR':   resolver = dns.reverse; break;
    default:      return cb(new Error('Unknown DNS type: ' + type));
  }

  // Coalesce concurrent identical lookups
  let waiters = inFlight.get(key);
  if (waiters) { waiters.push(cb); return; }
  inFlight.set(key, [cb]);

  // Node's resolver THROWS synchronously on a malformed argument — a PTR
  // lookup of something that is not an IP raises EINVAL rather than calling
  // back with an error. Since every caller here reaches us from network
  // input (a client's HELO name, a PROXY header, an SPF record), an
  // unguarded throw turns a malformed remote value into a process crash.
  // Report it through the callback like any other lookup failure.
  let launched = false;
  try {
    resolver(name, onResolved);
    launched = true;
  } catch (e) {
    inFlight.delete(key);
    return cb(e);
  }
  if (!launched) return;

  function onResolved(err, data) {
    if (!err && data) {
      cacheSet(key, { data: data, expires: Date.now() + DEFAULT_TTL });
    } else if (err && (err.code === 'ENOTFOUND' || err.code === 'ENODATA')) {
      // Negative-cache definitive misses (short TTL). Transient failures
      // (SERVFAIL, timeouts) are NOT cached — the next attempt may succeed.
      cacheSet(key, { err: err, data: undefined, expires: Date.now() + NEGATIVE_TTL });
    }
    let cbs = inFlight.get(key) || [];
    inFlight.delete(key);
    for (let i = 0; i < cbs.length; i++) cbs[i](err, data);
  }
}

// Convenience wrappers
function txt(name, cb)     { lookup('TXT', name, cb); }
function a(name, cb)       { lookup('A', name, cb); }
function aaaa(name, cb)    { lookup('AAAA', name, cb); }
function mx(name, cb)      { lookup('MX', name, cb); }
function ptr(ip, cb)       { lookup('PTR', ip, cb); }

function clear() { cache.clear(); }

function remove(name) {
  let toDelete = [];
  cache.forEach(function(_entry, key) {
    if (key.indexOf(name) >= 0) toDelete.push(key);
  });
  for (let i = 0; i < toDelete.length; i++) cache.delete(toDelete[i]);
}


export { lookup, txt, a, aaaa, mx, ptr, clear, remove };
