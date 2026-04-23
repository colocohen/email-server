
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

const DEFAULT_TTL = 300000; // 5 minutes
let cache = {};

// PTR lookups take an IP, not a domain — never IDN-encode those.
function normalizeName(type, name) {
  if (!name) return name;
  if (type === 'PTR') return name;
  if (isAscii(name)) return name;
  let ascii = domainToAscii(name);
  return ascii || name;
}

function lookup(type, name, cb) {
  name = normalizeName(type, name);
  let key = type + ':' + name;
  let cached = cache[key];
  if (cached && cached.expires > Date.now()) {
    return cb(null, cached.data);
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

  resolver(name, function(err, data) {
    if (!err && data) {
      cache[key] = { data: data, expires: Date.now() + DEFAULT_TTL };
    }
    cb(err, data);
  });
}

// Convenience wrappers
function txt(name, cb)     { lookup('TXT', name, cb); }
function a(name, cb)       { lookup('A', name, cb); }
function aaaa(name, cb)    { lookup('AAAA', name, cb); }
function mx(name, cb)      { lookup('MX', name, cb); }
function ptr(ip, cb)       { lookup('PTR', ip, cb); }

function clear() { cache = {}; }

function remove(name) {
  let keys = Object.keys(cache);
  for (let i = 0; i < keys.length; i++) {
    if (keys[i].indexOf(name) >= 0) delete cache[keys[i]];
  }
}


export { lookup, txt, a, aaaa, mx, ptr, clear, remove };
