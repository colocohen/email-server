
import dns from 'node:dns';


// ============================================================
//  Shared DNS cache — single cache used by dkim, spf, dmarc, rdns, pool
// ============================================================

const DEFAULT_TTL = 300000; // 5 minutes
let cache = {};

function lookup(type, name, cb) {
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
