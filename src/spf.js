
import net from 'node:net';

import * as dnsCache from './dns_cache.js';


// ============================================================
//  SPF check (RFC 7208)
// ============================================================

// checkSPF(ip, domain, cb)
// checkSPF(ip, domain, options, cb)   — options = { sender, helo }
//
// `sender` (the full MAIL FROM address) and `helo` feed macro expansion
// (RFC 7208 §7): records using %{s}, %{l}, %{o} or %{h} cannot be evaluated
// without them. Both are optional — when absent the RFC's own defaults apply
// (postmaster@<domain> for the sender, <domain> for HELO), so existing
// 3-argument callers keep working unchanged.
function checkSPF(ip, domain, options, cb) {
  if (typeof options === 'function') { cb = options; options = null; }
  options = options || {};

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
    evaluateSPF(ip, domain, spfRecord, lookupCount, cb, options.sender, options.helo);
  });
}


// ============================================================
//  SPF evaluation
// ============================================================

function evaluateSPF(ip, domain, spfRecord, lookups, cb, sender, heloName) {
  let terms = spfRecord.replace(/^v=spf1\s*/i, '').trim().split(/\s+/);
  let idx = 0;

  // RFC 7208 §4.6.4 — at most 10 DNS-querying mechanisms per evaluation
  // (a, mx, ptr, exists, include, redirect). The cap exists to stop an SPF
  // record being used to amplify traffic at a third party, so it must be
  // enforced BEFORE each query, not only when recursing into an include:
  // eleven `include:` terms in ONE record entered this function a single
  // time, so the old check at the top never fired again and the record went
  // on querying — then fell through to `-all` and reported `fail`, a
  // verdict the domain owner never authorised.
  //
  // Returns true when the caller must stop (and has already answered).
  function overLimit() {
    if (lookups.count >= lookups.max) {
      cb(null, { result: 'permerror', domain: domain, reason: 'Too many DNS lookups (max ' + lookups.max + ')' });
      return true;
    }
    return false;
  }

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
      if (overLimit()) return;
      lookups.count++;
      let aDomain = term.indexOf(':') >= 0
        ? expandMacros(term.split(':').slice(1).join(':'), ip, domain, sender, heloName) : domain;
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
      if (overLimit()) return;
      lookups.count++;
      let mxDomain = term.indexOf(':') >= 0
        ? expandMacros(term.split(':').slice(1).join(':'), ip, domain, sender, heloName) : domain;
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
      if (overLimit()) return;
      lookups.count++;
      let includeDomain = expandMacros(term.slice(8), ip, domain, sender, heloName);
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
        }, sender, heloName);
      });
      return;
    }

    // --- redirect=domain ---
    if (/^redirect=/i.test(term)) {
      if (overLimit()) return;
      lookups.count++;
      let redirDomain = expandMacros(term.slice(9), ip, domain, sender, heloName);
      dnsCache.txt(redirDomain, function(err, records) {
        if (err || !records) return cb(null, { result: 'permerror', domain: domain });
        let flat = records.map(function(r) { return r.join(''); });
        let redirSPF = flat.find(function(r) { return /^v=spf1\b/i.test(r); });
        if (!redirSPF) return cb(null, { result: 'permerror', domain: domain });
        evaluateSPF(ip, redirDomain, redirSPF, lookups, cb, sender, heloName);
      });
      return;
    }

    // --- exists:domain ---
    // Matches when the (macro-expanded) name resolves to ANY A record. The
    // value returned is irrelevant — existence is the whole test. This is how
    // RBL-style and per-sender SPF policies are expressed, e.g.
    //   exists:%{i}._spf.%{d}
    if (/^exists:/i.test(term)) {
      if (overLimit()) return;
      lookups.count++;
      let existsName = expandMacros(term.slice(7), ip, domain, sender, heloName);
      dnsCache.a(existsName, function(err, addrs) {
        if (!err && addrs && addrs.length > 0) {
          return cb(null, { result: resultForQualifier, domain: domain, mechanism: term });
        }
        nextTerm();
      });
      return;
    }

    // --- ptr / ptr:domain ---
    // Validated reverse lookup (RFC 7208 §5.5): PTR the client IP, then
    // forward-confirm each name, then check the confirmed name is the target
    // domain or a subdomain of it. The RFC discourages `ptr` and caps the
    // names examined at 10 — but records in the wild still use it, and
    // treating it as unknown made an SPF record evaluate to the wrong result.
    if (/^ptr(?::|$)/i.test(term)) {
      if (overLimit()) return;
      lookups.count++;
      let ptrTarget = term.indexOf(':') >= 0
        ? expandMacros(term.split(':').slice(1).join(':'), ip, domain, sender, heloName)
        : domain;
      let cleanIp = normalizeIP(ip);
      dnsCache.ptr(cleanIp, function(err, names) {
        if (err || !names || names.length === 0) return nextTerm();
        let list = names.slice(0, 10);   // §5.5 — hard cap
        let i = 0;
        (function checkNextPtr() {
          if (i >= list.length) return nextTerm();
          let name = String(list[i++]).replace(/\.$/, '').toLowerCase();
          let target = String(ptrTarget).replace(/\.$/, '').toLowerCase();
          if (name !== target && !name.endsWith('.' + target)) return checkNextPtr();
          // Forward-confirm before trusting the PTR.
          dnsCache.a(name, function(aerr, addrs) {
            if (!aerr && addrs) {
              for (let k = 0; k < addrs.length; k++) {
                if (normalizeIP(addrs[k]) === cleanIp) {
                  return cb(null, { result: resultForQualifier, domain: domain, mechanism: term });
                }
              }
            }
            checkNextPtr();
          });
        })();
      });
      return;
    }

    // --- exp= / unknown modifiers ---
    // A modifier is "name=value". Unknown ones are ignored per RFC 7208 §6 —
    // unlike unknown MECHANISMS, which are a syntax error (below).
    if (/^[a-z][a-z0-9_.-]*=/i.test(term)) {
      return nextTerm();
    }

    // Unknown mechanism → permerror (RFC 7208 §4.6.1 / §7.1). Silently
    // skipping it was unsafe in the other direction: a record like
    //   "v=spf1 unknown-mech -all"
    // would fall through to `-all` and hard-FAIL a legitimate sender, or,
    // with `?all`, silently downgrade a policy the domain owner wrote. A
    // record we cannot fully evaluate must say so.
    return cb(null, {
      result: 'permerror', domain: domain,
      reason: 'Unknown mechanism: ' + term
    });
  }

  nextTerm();
}


// ============================================================
//  Macro expansion (RFC 7208 §7)
// ============================================================
//
// SPF records may embed macros: "exists:%{i}._spf.%{d}" or "a:%{d2}".
// Without expansion these are looked up literally, which always fails — and
// a domain using them would silently never match.
//
// Supported letters: s (sender), l (local-part), o (sender domain),
// d (current domain), i (IP, dotted or nibble form), h (HELO), v ("in-addr"
// or "ip6"). Transformers: a digit (keep the last N labels), "r" (reverse),
// and custom delimiters. Unsupported letters expand to empty rather than
// throwing — a partial expansion still beats a literal lookup.
function expandMacros(str, ip, domain, sender, helo) {
  if (!str || str.indexOf('%') < 0) return str;

  let normIp = normalizeIP(ip);
  let isV4 = net.isIPv4(normIp);
  let senderStr = sender || ('postmaster@' + domain);
  let atIdx = senderStr.lastIndexOf('@');
  let localPart = atIdx > 0 ? senderStr.slice(0, atIdx) : 'postmaster';
  let senderDomain = atIdx > 0 ? senderStr.slice(atIdx + 1) : domain;

  function ipNibbles(addr) {
    let bytes = ipv6ToBytes(addr);
    if (!bytes) return addr;
    let out = [];
    for (let i = 0; i < 16; i++) {
      out.push((bytes[i] >> 4).toString(16));
      out.push((bytes[i] & 0x0F).toString(16));
    }
    return out.join('.');
  }

  function baseValue(letter) {
    switch (letter) {
      case 's': return senderStr;
      case 'l': return localPart;
      case 'o': return senderDomain;
      case 'd': return domain;
      case 'i': return isV4 ? normIp : ipNibbles(normIp);
      case 'p': return 'unknown';        // §7.3 discourages %{p}; 'unknown' is the prescribed fallback
      case 'v': return isV4 ? 'in-addr' : 'ip6';
      case 'h': return helo || domain;
      case 'c': return normIp;
      case 'r': return domain;
      case 't': return String(Math.floor(Date.now() / 1000));
      default:  return '';
    }
  }

  // %{letter}{digits}{r}{delimiters} — also %% %_ %-
  return str.replace(/%(\{([a-zA-Z])(\d*)(r?)([.\-+,/_=]*)\}|%|_|-)/g,
    function(match, body, letter, digits, reverse, delims) {
      if (body === '%') return '%';
      if (body === '_') return ' ';
      if (body === '-') return '%20';

      let value = baseValue(String(letter).toLowerCase());
      // An uppercase letter means URL-escape the result (§7.3).
      let upper = letter !== String(letter).toLowerCase();

      let splitOn = delims && delims.length ? delims : '.';
      let parts = String(value).split(new RegExp('[' + splitOn.replace(/[.\-+,/_=\\\]]/g, '\\$&') + ']'));
      if (reverse) parts.reverse();
      if (digits) {
        let n = parseInt(digits, 10);
        if (n > 0 && n < parts.length) parts = parts.slice(parts.length - n);
      }
      let out = parts.join('.');
      return upper ? encodeURIComponent(out) : out;
    });
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

// Expand an IPv6 address string into a 16-byte Uint8Array.
// Handles '::' compression, mixed IPv4-mapped tails ('::ffff:1.2.3.4'),
// and leading-zero-omitted groups. Returns null on invalid input.
function ipv6ToBytes(addr) {
  let s = String(addr || '').toLowerCase();
  if (!net.isIPv6(s)) return null;

  // Split off an embedded IPv4 tail if present ("...:1.2.3.4")
  let v4Tail = null;
  let lastColon = s.lastIndexOf(':');
  if (s.indexOf('.') > lastColon) {
    v4Tail = s.slice(lastColon + 1);
    s = s.slice(0, lastColon) + ':0:0';   // placeholder — replaced below
  }

  let halves = s.split('::');
  let head = halves[0] ? halves[0].split(':').filter(Boolean) : [];
  let tail = halves.length > 1 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
  let groups;
  if (halves.length > 1) {
    let missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    groups = head.concat(new Array(missing).fill('0'), tail);
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;

  let bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    let v = parseInt(groups[i], 16);
    if (isNaN(v) || v < 0 || v > 0xFFFF) return null;
    bytes[i * 2]     = (v >> 8) & 0xFF;
    bytes[i * 2 + 1] = v & 0xFF;
  }

  // Write the IPv4 tail into the last 4 bytes if there was one
  if (v4Tail) {
    let p = v4Tail.split('.');
    if (p.length !== 4) return null;
    for (let i = 0; i < 4; i++) {
      let n = parseInt(p[i], 10);
      if (isNaN(n) || n < 0 || n > 255) return null;
      bytes[12 + i] = n;
    }
  }
  return bytes;
}

// Compare the first `bits` bits of two 16-byte addresses.
function ipv6PrefixEqual(a, b, bits) {
  if (bits > 128) bits = 128;
  let fullBytes = bits >> 3;
  for (let i = 0; i < fullBytes; i++) {
    if (a[i] !== b[i]) return false;
  }
  let remBits = bits & 7;
  if (remBits === 0) return true;
  let mask = (0xFF << (8 - remBits)) & 0xFF;
  return (a[fullBytes] & mask) === (b[fullBytes] & mask);
}

function matchIPv6(ip, cidr) {
  let normIP = normalizeIP(ip);
  if (net.isIPv4(normIP)) return false;

  let parts = cidr.split('/');
  let addr = parts[0];
  let prefixLen = parts[1] !== undefined ? parseInt(parts[1], 10) : 128;
  if (isNaN(prefixLen) || prefixLen < 0 || prefixLen > 128) return false;

  let ipBytes = ipv6ToBytes(normIP);
  let netBytes = ipv6ToBytes(addr);
  if (!ipBytes || !netBytes) return false;

  return ipv6PrefixEqual(ipBytes, netBytes, prefixLen);
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
