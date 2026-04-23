
import * as dnsCache from './dns_cache.js';


// ============================================================
//  FCrDNS check (Forward-Confirmed Reverse DNS)
// ============================================================

function checkFCrDNS(ip, cb) {
  if (!ip) {
    return cb(null, { result: 'none', reason: 'No IP' });
  }

  let cleanIP = String(ip).replace(/^::ffff:/i, '');

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

      dnsCache.a(hostname, function(err, addrs) {
        if (!err && addrs) {
          for (let i = 0; i < addrs.length; i++) {
            if (addrs[i] === cleanIP) {
              return cb(null, {
                result: 'pass',
                ip: cleanIP,
                hostname: hostname,
                ptrHostnames: hostnames
              });
            }
          }
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

  let cleanIP = String(ip).replace(/^::ffff:/i, '');

  dnsCache.a(ehloHostname, function(err, addrs) {
    if (!err && addrs) {
      for (let i = 0; i < addrs.length; i++) {
        if (addrs[i] === cleanIP) {
          return cb(null, { result: 'pass', hostname: ehloHostname, ip: cleanIP });
        }
      }
    }
    cb(null, { result: 'fail', hostname: ehloHostname, ip: cleanIP, reason: 'EHLO hostname does not resolve to IP' });
  });
}


export { checkFCrDNS, checkEhloHostname };
