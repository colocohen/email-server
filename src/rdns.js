
import * as dnsCache from './dns_cache.js';


// ============================================================
//  Addresses
//
//  A sender connecting over IPv6 has an IPv6 address, and the name it
//  claims (PTR, EHLO) leads back to it through AAAA, not A. Only A was
//  asked, so every IPv6 sender failed both checks — Gmail among them.
//
//  IPv6 has many spellings of one address ('2001:db8::1',
//  '2001:db8:0:0::1', upper or lower case), so addresses are compared in
//  one canonical form. An IPv4-mapped IPv6 address ('::ffff:1.2.3.4', how a
//  dual-stack socket reports an IPv4 client) is the IPv4 address.
// ============================================================

function cleanAddress(ip) {
  let s = String(ip || '').trim();
  let mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(s);
  if (mapped) return mapped[1];
  if (s.indexOf(':') < 0) return s;
  try { return new URL('http://[' + s + ']/').hostname.slice(1, -1); }
  catch (e) { return s.toLowerCase(); }
}

function isV6(ip) { return ip.indexOf(':') >= 0; }

// The addresses a name has, of the family of ip, canonical. cb(addrs).
function forward(name, ip, cb) {
  let lookup = isV6(ip) ? dnsCache.aaaa : dnsCache.a;
  lookup(name, function(err, addrs) {
    if (err || !addrs) return cb([]);
    cb(addrs.map(cleanAddress));
  });
}


// ============================================================
//  FCrDNS check (Forward-Confirmed Reverse DNS)
// ============================================================

function checkFCrDNS(ip, cb) {
  if (!ip) {
    return cb(null, { result: 'none', reason: 'No IP' });
  }

  let cleanIP = cleanAddress(ip);

  // Step 1: PTR lookup
  dnsCache.ptr(cleanIP, function(err, hostnames) {
    if (err || !hostnames || hostnames.length === 0) {
      return cb(null, { result: 'fail', ip: cleanIP, reason: 'No PTR record' });
    }

    // Step 2: Forward lookup — check each PTR hostname
    let idx = 0;

    function checkNext() {
      if (idx >= hostnames.length) {
        return cb(null, {
          result: 'fail',
          ip: cleanIP,
          ptrHostnames: hostnames,
          reason: 'No forward match'
        });
      }

      let hostname = hostnames[idx++];

      forward(hostname, cleanIP, function(addrs) {
        if (addrs.indexOf(cleanIP) >= 0) {
          return cb(null, {
            result: 'pass',
            ip: cleanIP,
            hostname: hostname,
            ptrHostnames: hostnames
          });
        }
        checkNext();
      });
    }

    checkNext();
  });
}


// ============================================================
//  EHLO hostname verification
// ============================================================

function checkEhloHostname(ip, ehloHostname, cb) {
  if (!ip || !ehloHostname) {
    return cb(null, { result: 'none' });
  }

  let cleanIP = cleanAddress(ip);

  forward(ehloHostname, cleanIP, function(addrs) {
    if (addrs.indexOf(cleanIP) >= 0) {
      return cb(null, { result: 'pass', hostname: ehloHostname, ip: cleanIP });
    }
    cb(null, { result: 'fail', hostname: ehloHostname, ip: cleanIP, reason: 'EHLO hostname does not resolve to IP' });
  });
}


export { checkFCrDNS, checkEhloHostname };
