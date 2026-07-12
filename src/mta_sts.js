// ============================================================================
//  mta_sts.js  —  SENDER-side MTA-STS (RFC 8461)
// ----------------------------------------------------------------------------
//  domain.js generates MTA-STS material for OUR domains (the receiving side).
//  This module is the other half: before delivering to a REMOTE domain, a
//  conforming sender discovers the recipient domain's policy and — when the
//  policy mode is "enforce" — refuses to deliver except over verified TLS to
//  an MX matching the policy.
//
//  Discovery (RFC 8461 §3):
//    1. DNS TXT at `_mta-sts.<domain>`:  "v=STSv1; id=<opaque>"
//       (no record → no policy → deliver as usual)
//    2. HTTPS GET https://mta-sts.<domain>/.well-known/mta-sts.txt
//       over a VALIDATED TLS connection (cert failures = fetch failure).
//
//  Policy file format (key: value lines):
//    version: STSv1
//    mode: enforce | testing | none
//    mx: mail.example.com
//    mx: *.example.net
//    max_age: 86400
//
//  Enforcement semantics implemented by the caller (smtp_client):
//    mode=enforce → only policy-matching MX hosts may be used, STARTTLS is
//                   mandatory, and the certificate must validate for the MX
//                   host. Anything else = do not deliver (treat as transient
//                   failure so mail queues rather than bounces — §5.1).
//    mode=testing/none → deliver as usual (testing failures are reportable
//                   via TLS-RPT, which is emitted as a 'tlsFailure' event).
// ============================================================================

import https from 'node:https';
import * as dnsCache from './dns_cache.js';

// Policy cache: domain → { policy, expires }
// RFC 8461 §3.3: cache per policy max_age. We clamp to sane bounds so a
// hostile/misconfigured policy can't pin itself for a year or thrash us.
const MIN_CACHE_MS = 60 * 1000;               // 1 minute floor
const MAX_CACHE_MS = 7 * 24 * 3600 * 1000;    // 7 day ceiling
const NEGATIVE_CACHE_MS = 10 * 60 * 1000;     // "no policy" cached 10 minutes
const MAX_POLICY_BYTES = 64 * 1024;           // RFC 8461 §3.2 upper bound

let policyCache = new Map();

// Parse the mta-sts.txt body. Returns {version, mode, mx: [...], maxAge}
// or null when structurally invalid.
function parseStsPolicy(text) {
  let lines = String(text || '').split(/\r?\n/);
  let policy = { version: null, mode: null, mx: [], maxAge: null };
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].trim();
    if (!line) continue;
    let idx = line.indexOf(':');
    if (idx < 0) continue;
    let key = line.slice(0, idx).trim().toLowerCase();
    let val = line.slice(idx + 1).trim();
    if (key === 'version')      policy.version = val;
    else if (key === 'mode')    policy.mode = val.toLowerCase();
    else if (key === 'mx')      policy.mx.push(val.toLowerCase());
    else if (key === 'max_age') policy.maxAge = parseInt(val, 10);
  }
  if (policy.version !== 'STSv1') return null;
  if (['enforce', 'testing', 'none'].indexOf(policy.mode) < 0) return null;
  if (policy.mode !== 'none' && policy.mx.length === 0) return null;
  if (!isFinite(policy.maxAge) || policy.maxAge == null) policy.maxAge = 86400;
  return policy;
}

// Does an MX hostname match a policy mx pattern?
// Patterns are exact hostnames or a single leading wildcard label
// ("*.example.com" matches "mx1.example.com" but NOT "example.com"
// and NOT "a.b.example.com" — one label only, per RFC 8461 §4.1).
function mxMatchesPolicy(mxHost, policy) {
  let host = String(mxHost || '').toLowerCase().replace(/\.$/, '');
  for (let i = 0; i < policy.mx.length; i++) {
    let pat = policy.mx[i].replace(/\.$/, '');
    if (pat.slice(0, 2) === '*.') {
      let suffix = pat.slice(1);                  // ".example.com"
      if (host.length > suffix.length && host.endsWith(suffix)) {
        let label = host.slice(0, host.length - suffix.length);
        if (label.indexOf('.') < 0) return true;  // exactly one extra label
      }
    } else if (host === pat) {
      return true;
    }
  }
  return false;
}

// Fetch the policy file over validated HTTPS.
function fetchPolicyFile(domain, cb) {
  let req = https.get({
    host: 'mta-sts.' + domain,
    path: '/.well-known/mta-sts.txt',
    timeout: 10000,
    // RFC 8461 §3.2: the HTTPS certificate MUST validate — an attacker who
    // can forge this fetch could serve a fake "mode: none" policy.
    rejectUnauthorized: true,
    headers: { 'User-Agent': 'email-server-mta-sts' }
  }, function(res) {
    if (res.statusCode !== 200) {
      res.resume();
      return cb(new Error('MTA-STS policy fetch: HTTP ' + res.statusCode));
    }
    let size = 0;
    let chunks = [];
    res.on('data', function(c) {
      size += c.length;
      if (size > MAX_POLICY_BYTES) { req.destroy(); return cb(new Error('MTA-STS policy too large')); }
      chunks.push(c);
    });
    res.on('end', function() {
      cb(null, Buffer.concat(chunks).toString('utf-8'));
    });
    res.on('error', cb);
  });
  req.on('timeout', function() { req.destroy(new Error('MTA-STS policy fetch timeout')); });
  req.on('error', cb);
}

// Public entry: getPolicy(domain, cb) → cb(null, policy | null)
//   policy = { version, mode, mx, maxAge, id }  or  null (no policy / lookup failed)
// Failures are NON-FATAL by design: an unreachable policy server must not
// block delivery to a domain that never opted into MTA-STS. But if a CACHED
// enforce policy exists and refresh fails, the cached one keeps applying
// until it expires (§3.3 — prevents downgrade-by-DoS on the policy host).
function getPolicy(domain, cb) {
  domain = String(domain || '').toLowerCase().replace(/\.$/, '');
  let cached = policyCache.get(domain);
  if (cached && cached.expires > Date.now()) {
    return cb(null, cached.policy);
  }

  // Step 1: DNS TXT _mta-sts.<domain>
  dnsCache.txt('_mta-sts.' + domain, function(err, records) {
    let stsRecord = null;
    if (!err && records) {
      for (let i = 0; i < records.length; i++) {
        let joined = Array.isArray(records[i]) ? records[i].join('') : String(records[i]);
        if (/^v=STSv1\b/i.test(joined.trim())) { stsRecord = joined.trim(); break; }
      }
    }
    if (!stsRecord) {
      // No policy advertised. If we hold an unexpired cached policy we keep
      // honoring it (handled above); otherwise negative-cache the absence.
      policyCache.set(domain, { policy: null, expires: Date.now() + NEGATIVE_CACHE_MS });
      return cb(null, null);
    }
    let idMatch = /id\s*=\s*([^;\s]+)/i.exec(stsRecord);
    let id = idMatch ? idMatch[1] : null;

    // Same id as cached (even if expired)? Refresh the ttl without refetching.
    if (cached && cached.policy && cached.policy.id === id && id !== null) {
      cached.expires = Date.now() + clampCache(cached.policy.maxAge);
      return cb(null, cached.policy);
    }

    // Step 2: HTTPS policy file
    fetchPolicyFile(domain, function(ferr, text) {
      if (ferr) {
        // Fetch failed. If a previous (even stale) enforce policy exists,
        // keep applying it rather than silently downgrading (§3.3).
        if (cached && cached.policy && cached.policy.mode === 'enforce') {
          cached.expires = Date.now() + MIN_CACHE_MS;   // brief extension, retry soon
          return cb(null, cached.policy);
        }
        policyCache.set(domain, { policy: null, expires: Date.now() + NEGATIVE_CACHE_MS });
        return cb(null, null);
      }
      let policy = parseStsPolicy(text);
      if (!policy) {
        policyCache.set(domain, { policy: null, expires: Date.now() + NEGATIVE_CACHE_MS });
        return cb(null, null);
      }
      policy.id = id;
      policyCache.set(domain, { policy: policy, expires: Date.now() + clampCache(policy.maxAge) });
      cb(null, policy);
    });
  });
}

function clampCache(maxAgeSeconds) {
  let ms = (maxAgeSeconds || 86400) * 1000;
  if (ms < MIN_CACHE_MS) ms = MIN_CACHE_MS;
  if (ms > MAX_CACHE_MS) ms = MAX_CACHE_MS;
  return ms;
}

function clearPolicyCache() { policyCache.clear(); }

export { getPolicy, parseStsPolicy, mxMatchesPolicy, clearPolicyCache };
