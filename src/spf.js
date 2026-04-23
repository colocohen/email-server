
import net from 'node:net';

import * as dnsCache from './dns_cache.js';


// ============================================================
//  SPF check (RFC 7208)
// ============================================================

function checkSPF(ip, domain, cb) {
  if (!ip || !domain) {
    return cb(null, { result: 'none', domain: domain });
  }

  dnsCache.txt(domain, function(err, records) {
    if (err || !records) {
      return cb(null, { result: 'none', domain: domain, reason: 'No TXT records' });
    }

    // Find SPF record
    let flat = records.map(function(r) { return r.join(''); });
    let spfRecord = flat.find(function(r) { return /^v=spf1\b/i.test(r); });

    if (!spfRecord) {
      return cb(null, { result: 'none', domain: domain, reason: 'No SPF record' });
    }

    // Parse and evaluate — shared lookup counter (RFC 7208: max 10)
    let lookupCount = { count: 0, max: 10 };
    evaluateSPF(ip, domain, spfRecord, lookupCount, cb);
  });
}


// ============================================================
//  SPF evaluation
// ============================================================

function evaluateSPF(ip, domain, spfRecord, lookups, cb) {
  // Check total DNS lookup limit (RFC 7208 §4.6.4)
  if (lookups.count > lookups.max) {
    return cb(null, { result: 'permerror', domain: domain, reason: 'Too many DNS lookups' });
  }

  let terms = spfRecord.replace(/^v=spf1\s*/i, '').trim().split(/\s+/);
  let idx = 0;

  function nextTerm() {
    if (idx >= terms.length) {
      // Default: neutral
      return cb(null, { result: 'neutral', domain: domain });
    }

    let term = terms[idx++];
    if (!term) return nextTerm();

    // Parse qualifier
    let qualifier = '+'; // default pass
    if (term[0] === '+' || term[0] === '-' || term[0] === '~' || term[0] === '?') {
      qualifier = term[0];
      term = term.slice(1);
    }

    let resultForQualifier = qualifierToResult(qualifier);

    // --- all ---
    if (term.toLowerCase() === 'all') {
      return cb(null, { result: resultForQualifier, domain: domain, mechanism: 'all' });
    }

    // --- ip4:addr ---
    if (/^ip4:/i.test(term)) {
      let cidr = term.slice(4);
      if (matchIPv4(ip, cidr)) {
        return cb(null, { result: resultForQualifier, domain: domain, mechanism: term });
      }
      return nextTerm();
    }

    // --- ip6:addr ---
    if (/^ip6:/i.test(term)) {
      let cidr = term.slice(4);
      if (matchIPv6(ip, cidr)) {
        return cb(null, { result: resultForQualifier, domain: domain, mechanism: term });
      }
      return nextTerm();
    }

    // --- a / a:domain ---
    if (/^a(?::|$)/i.test(term)) {
      lookups.count++;
      let aDomain = term.indexOf(':') >= 0 ? term.split(':').slice(1).join(':') : domain;
      dnsCache.a(aDomain, function(err, addrs) {
        if (!err && addrs) {
          for (let i = 0; i < addrs.length; i++) {
            if (normalizeIP(addrs[i]) === normalizeIP(ip)) {
              return cb(null, { result: resultForQualifier, domain: domain, mechanism: term });
            }
          }
        }
        // Also check AAAA
        dnsCache.aaaa(aDomain, function(err2, addrs6) {
          if (!err2 && addrs6) {
            for (let i = 0; i < addrs6.length; i++) {
              if (normalizeIP(addrs6[i]) === normalizeIP(ip)) {
                return cb(null, { result: resultForQualifier, domain: domain, mechanism: term });
              }
            }
          }
          nextTerm();
        });
      });
      return;
    }

    // --- mx / mx:domain ---
    if (/^mx(?::|$)/i.test(term)) {
      lookups.count++;
      let mxDomain = term.indexOf(':') >= 0 ? term.split(':').slice(1).join(':') : domain;
      dnsCache.mx(mxDomain, function(err, mxRecords) {
        if (err || !mxRecords || mxRecords.length === 0) return nextTerm();

        let mxHosts = mxRecords.map(function(r) { return r.exchange; });
        let mxIdx = 0;

        function checkNextMX() {
          if (mxIdx >= mxHosts.length) return nextTerm();
          let mxHost = mxHosts[mxIdx++];

          dnsCache.a(mxHost, function(err, addrs) {
            if (!err && addrs) {
              for (let i = 0; i < addrs.length; i++) {
                if (normalizeIP(addrs[i]) === normalizeIP(ip)) {
                  return cb(null, { result: resultForQualifier, domain: domain, mechanism: term });
                }
              }
            }
            checkNextMX();
          });
        }

        checkNextMX();
      });
      return;
    }

    // --- include:domain ---
    if (/^include:/i.test(term)) {
      lookups.count++;
      let includeDomain = term.slice(8);
      dnsCache.txt(includeDomain, function(err, records) {
        if (err || !records) return nextTerm();
        let flat = records.map(function(r) { return r.join(''); });
        let incSPF = flat.find(function(r) { return /^v=spf1\b/i.test(r); });
        if (!incSPF) return nextTerm();

        evaluateSPF(ip, includeDomain, incSPF, lookups, function(err, incResult) {
          if (incResult && incResult.result === 'pass') {
            return cb(null, { result: resultForQualifier, domain: domain, mechanism: term });
          }
          nextTerm();
        });
      });
      return;
    }

    // --- redirect=domain ---
    if (/^redirect=/i.test(term)) {
      lookups.count++;
      let redirDomain = term.slice(9);
      dnsCache.txt(redirDomain, function(err, records) {
        if (err || !records) return cb(null, { result: 'permerror', domain: domain });
        let flat = records.map(function(r) { return r.join(''); });
        let redirSPF = flat.find(function(r) { return /^v=spf1\b/i.test(r); });
        if (!redirSPF) return cb(null, { result: 'permerror', domain: domain });
        evaluateSPF(ip, redirDomain, redirSPF, lookups, cb);
      });
      return;
    }

    // Unknown mechanism — skip
    nextTerm();
  }

  nextTerm();
}


// ============================================================
//  IP matching helpers
// ============================================================

function normalizeIP(ip) {
  if (!ip) return '';
  // Strip IPv6-mapped IPv4 prefix
  let s = String(ip).replace(/^::ffff:/i, '');
  return s.toLowerCase();
}

function matchIPv4(ip, cidr) {
  let normIP = normalizeIP(ip);
  if (!net.isIPv4(normIP)) return false;

  let parts = cidr.split('/');
  let addr = parts[0];
  let mask = parts[1] ? parseInt(parts[1], 10) : 32;

  let ipNum = ipv4ToNum(normIP);
  let addrNum = ipv4ToNum(addr);
  let maskBits = (0xFFFFFFFF << (32 - mask)) >>> 0;

  return (ipNum & maskBits) === (addrNum & maskBits);
}

function ipv4ToNum(ip) {
  let parts = ip.split('.');
  return ((parseInt(parts[0]) << 24) | (parseInt(parts[1]) << 16) |
          (parseInt(parts[2]) << 8) | parseInt(parts[3])) >>> 0;
}

function matchIPv6(ip, cidr) {
  // Basic IPv6 CIDR match — simplified
  let normIP = normalizeIP(ip);
  if (net.isIPv4(normIP)) return false;

  let parts = cidr.split('/');
  let addr = parts[0];
  // Simple exact match for now (full CIDR would need more complex bit ops)
  return normalizeIP(addr) === normIP;
}

function qualifierToResult(q) {
  if (q === '+') return 'pass';
  if (q === '-') return 'fail';
  if (q === '~') return 'softfail';
  if (q === '?') return 'neutral';
  return 'neutral';
}


// ============================================================
//  Exports
// ============================================================

export { checkSPF };
