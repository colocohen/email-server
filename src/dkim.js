
import crypto from 'node:crypto';

import * as dnsCache from './dns_cache.js';
import { u8ToBinStr, parseTags, parseMailHeaders } from './utils.js';


// ============================================================
//  Canonicalization (RFC 6376 §3.4)
// ============================================================

// Pre-compiled patterns for canonicalization (called per header/line)
const RE_UNFOLD = /\r\n[ \t]+/g;
const RE_WSP_COMPRESS = /[ \t]+/g;
const RE_WSP_TRAILING = /[ \t]+$/g;
const RE_WSP_LEADING = /^[ \t]+/g;
const RE_NORMALIZE_NL = /\r?\n/g;

// --- Relaxed header canonicalization ---
function canonicalizeHeaderRelaxed(name, value) {
  let n = name.toLowerCase().trim();
  let v = value
    .replace(RE_UNFOLD, ' ')
    .replace(RE_WSP_COMPRESS, ' ')
    .replace(RE_WSP_TRAILING, '')
    .replace(RE_WSP_LEADING, '');
  return n + ':' + v;
}

// --- Simple header canonicalization (RFC 6376 §3.4.1) ---
// The header is hashed EXACTLY as it appeared on the wire: original case,
// original whitespace, original folding. Nothing is normalized. Callers pass
// the raw header line (name and value together, without the trailing CRLF).
function canonicalizeHeaderSimple(raw) {
  return raw;
}

// --- Simple body canonicalization (RFC 6376 §3.4.3) ---
// The body is hashed as-is, with exactly one change: trailing empty lines are
// removed and the body is terminated by a single CRLF. Whitespace inside and
// at the end of lines is preserved — which is precisely why a message signed
// with c=simple cannot be verified with the relaxed algorithm.
function canonicalizeBodySimple(body) {
  let str = (body instanceof Uint8Array) ? u8ToBinStr(body) :
            (Buffer.isBuffer(body)) ? body.toString('latin1') : String(body);

  // Normalize any bare LF to CRLF first so the trailing-CRLF trimming below
  // works on a consistent representation (the wire form is always CRLF).
  str = str.replace(RE_NORMALIZE_NL, '\r\n');

  // Strip trailing CRLFs, then re-add exactly one. An empty body canonicalizes
  // to a single CRLF.
  while (str.length >= 2 && str.slice(-2) === '\r\n') str = str.slice(0, -2);
  return str + '\r\n';
}

// Split a "c=" tag value into its header and body algorithms.
// Per RFC 6376 §3.5: "relaxed/simple", a bare "relaxed" (body defaults to
// simple), or absent entirely (defaults to "simple/simple").
function parseCanonicalization(c) {
  let header = 'simple', body = 'simple';
  if (c) {
    let parts = String(c).trim().toLowerCase().split('/');
    if (parts[0] === 'relaxed' || parts[0] === 'simple') header = parts[0];
    if (parts.length > 1 && (parts[1] === 'relaxed' || parts[1] === 'simple')) body = parts[1];
  }
  return { header: header, body: body };
}

// Canonicalize a body with whichever algorithm the signature specified.
function canonicalizeBody(body, algo) {
  return algo === 'relaxed' ? canonicalizeBodyRelaxed(body) : canonicalizeBodySimple(body);
}

// Canonicalize one header with whichever algorithm the signature specified.
// `h` is a parsed header {name, raw}; relaxed needs the name and value apart,
// simple needs the untouched raw line.
function canonicalizeHeader(h, algo) {
  if (algo === 'relaxed') {
    return canonicalizeHeaderRelaxed(h.name, h.raw.replace(/^[^:]+:\s*/, ''));
  }
  return canonicalizeHeaderSimple(h.raw);
}


// --- Relaxed body canonicalization ---
// DKIM canonicalization operates on OCTETS (RFC 6376 §3.4.4). We therefore
// decode bytes with the byte-preserving latin1 codec (byte <-> char-code
// 1:1), NOT UTF-8: a UTF-8 decode replaces invalid sequences (e.g. Latin-1
// 0xE9) with U+FFFD, so the hash no longer matches the wire bytes and every
// verifier (Gmail, mailauth, opendkim) reports "body hash did not verify".
// The WSP/newline regexes below only ever match ASCII chars, so they behave
// identically on a latin1 string. Callers that pass a plain JS string are
// assumed to hold ASCII/latin1-representable content; hashing later
// re-encodes with 'latin1' to recover the exact octets.
function canonicalizeBodyRelaxed(body) {
  let str = (body instanceof Uint8Array) ? u8ToBinStr(body) :
            (Buffer.isBuffer(body)) ? body.toString('latin1') : String(body);

  let lines = str.replace(RE_NORMALIZE_NL, '\n').split('\n');
  let out = [];

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i]
      .replace(RE_WSP_COMPRESS, ' ')
      .replace(RE_WSP_TRAILING, '');
    out.push(line);
  }

  while (out.length > 0 && out[out.length - 1] === '') {
    out.pop();
  }

  if (out.length === 0) return '\r\n';
  return out.join('\r\n') + '\r\n';
}


// ============================================================
//  Header parsing helpers
// ============================================================

// Return a copy of `primary` carrying the full per-signature list. A copy,
// not the object itself: `primary` is an element of `results`, so assigning
// the array onto it would create a cycle that throws in JSON.stringify —
// which is exactly what a developer does when logging the auth result.
function withSignatures(primary, results) {
  let out = {};
  for (let k in primary) {
    if (Object.prototype.hasOwnProperty.call(primary, k)) out[k] = primary[k];
  }
  out.signatures = results;
  return out;
}

function findHeader(headers, name) {
  let low = name.toLowerCase();
  for (let i = headers.length - 1; i >= 0; i--) {
    if (headers[i].name.toLowerCase() === low) return headers[i];
  }
  return null;
}

// Return the n-th instance of a header counting from the BOTTOM of the
// message (n = 0 is the last one). DKIM signs headers bottom-up, and a
// signature may name the same field more than once in h= — "oversigning",
// which pins the field count so an attacker can't prepend an extra copy.
// Each repeat must consume the next instance upward.
function findHeaderNth(headers, name, n) {
  let low = name.toLowerCase();
  let seen = 0;
  for (let i = headers.length - 1; i >= 0; i--) {
    if (headers[i].name.toLowerCase() === low) {
      if (seen === n) return headers[i];
      seen++;
    }
  }
  return null;
}


// ============================================================
//  DKIM Sign (RFC 6376)
// ============================================================

const DEFAULT_SIGNED_HEADERS = [
  'from', 'to', 'cc', 'subject', 'date', 'message-id',
  'mime-version', 'content-type', 'content-transfer-encoding',
  'reply-to', 'in-reply-to', 'references'
];

function sign(rawMessage, options) {
  options = options || {};

  // Byte-preserving decode (latin1) — see canonicalizeBodyRelaxed. The
  // original wire octets survive the string roundtrip so the body hash and
  // the returned signed message stay byte-identical to the input.
  let rawBuf = (rawMessage instanceof Uint8Array) ? Buffer.from(rawMessage) :
               (Buffer.isBuffer(rawMessage)) ? rawMessage :
               Buffer.from(String(rawMessage), 'latin1');
  let str = rawBuf.toString('latin1');

  let domain = options.domain;
  let selector = options.selector;
  let privateKey = options.privateKey;
  let algo = options.algo || 'rsa-sha256';

  if (!domain || !selector || !privateKey) {
    throw new Error('DKIM sign requires domain, selector, privateKey');
  }

  let parsed = parseMailHeaders(str);
  let headers = parsed.headers;
  let body = parsed.body;

  // Canonicalize body (relaxed)
  let canonBody = canonicalizeBodyRelaxed(body);

  // Body hash (SHA-256) — encode the canonicalized latin1 string back to its
  // exact octets ('latin1'), never the default 'utf8' which would re-expand
  // chars >= 0x80 into multi-byte sequences the verifier never sees.
  let bodyHash = crypto.createHash('sha256').update(canonBody, 'latin1').digest('base64');

  // Determine which headers to sign (only those present in the message)
  let signedHeaderNames = options.signHeaders || DEFAULT_SIGNED_HEADERS;
  let actualSigned = [];
  for (let i = 0; i < signedHeaderNames.length; i++) {
    let h = findHeader(headers, signedHeaderNames[i]);
    if (h) actualSigned.push(signedHeaderNames[i]);
  }

  // Always include 'from'
  if (actualSigned.indexOf('from') < 0) actualSigned.unshift('from');

  // Build timestamp
  let timestamp = Math.floor(Date.now() / 1000);

  // Build DKIM-Signature header value (without b= value)
  let sigAlgoTag = (algo === 'ed25519-sha256') ? 'ed25519-sha256' : 'rsa-sha256';

  let dkimHeader = 'v=1; a=' + sigAlgoTag + '; c=relaxed/relaxed; d=' + domain +
    '; s=' + selector +
    '; t=' + timestamp +
    '; h=' + actualSigned.join(':') +
    '; bh=' + bodyHash +
    '; b=';

  // Canonicalize headers for signing
  let signData = '';
  for (let i = 0; i < actualSigned.length; i++) {
    let h = findHeader(headers, actualSigned[i]);
    if (h) {
      signData += canonicalizeHeaderRelaxed(h.name, h.raw.replace(/^[^:]+:\s*/, '')) + '\r\n';
    }
  }

  // Add the DKIM-Signature header itself (without the b= value, just tag)
  signData += canonicalizeHeaderRelaxed('dkim-signature', dkimHeader);

  // Sign — signData is a latin1 string of the canonicalized header octets;
  // 'latin1' encoding recovers those exact bytes for the signature input.
  let signature;
  if (algo === 'ed25519-sha256') {
    // Ed25519-SHA256 (RFC 8463 §3): the value signed is the SHA-256 DIGEST of
    // the canonicalized header block — NOT the header block itself. Ed25519 is
    // otherwise a "pure" scheme that would happily sign the raw bytes, which
    // is what this did before: it produced a well-formed signature that every
    // conforming verifier (dkimpy, opendkim, Gmail) rejects, because they hash
    // first. The comment here described the correct behaviour all along.
    let keyObj = crypto.createPrivateKey(privateKey);
    let digest = crypto.createHash('sha256').update(signData, 'latin1').digest();
    signature = crypto.sign(null, digest, keyObj);
  } else {
    // RSA-SHA256
    let signer = crypto.createSign('SHA256');
    signer.update(signData, 'latin1');
    signature = signer.sign(privateKey);
  }

  let b64Sig = signature.toString('base64');

  // Fold the signature for line length
  let fullDkimValue = dkimHeader + foldB64(b64Sig);
  let dkimHeaderLine = 'DKIM-Signature: ' + fullDkimValue;

  // Prepend DKIM-Signature to the message. Returned as a Buffer built from
  // the ORIGINAL raw bytes (not a decoded string) so 8-bit body content is
  // relayed byte-identical to what was hashed. The header line itself is
  // pure ASCII. Buffer is accepted everywhere the previous string was
  // (socket.write, sendMail raw, Buffer.concat, toString()).
  let signedMessage = Buffer.concat([
    Buffer.from(dkimHeaderLine + '\r\n', 'latin1'),
    rawBuf
  ]);

  return {
    header: dkimHeaderLine,
    signature: b64Sig,
    bodyHash: bodyHash,
    signedHeaders: actualSigned,
    message: signedMessage
  };
}

function foldB64(b64) {
  let out = '';
  let lineLen = 0;
  for (let i = 0; i < b64.length; i++) {
    if (lineLen >= 72) {
      out += '\r\n        ';
      lineLen = 8;
    }
    out += b64[i];
    lineLen++;
  }
  return out;
}


// ============================================================
//  DKIM Verify (RFC 6376)
// ============================================================

function verify(rawMessage, cb) {
  // Byte-preserving decode (latin1) — see canonicalizeBodyRelaxed. Without
  // it, verifying a message whose body carries non-UTF8 octets computes a
  // hash over U+FFFD replacements and reports a false "Body hash mismatch".
  let str = (rawMessage instanceof Uint8Array) ? u8ToBinStr(rawMessage) :
            (Buffer.isBuffer(rawMessage)) ? rawMessage.toString('latin1') : String(rawMessage);

  let parsed = parseMailHeaders(str);
  let headers = parsed.headers;
  let body = parsed.body;

  // Collect EVERY DKIM-Signature. A message that passed through a mailing
  // list or a forwarder carries several, and only checking one (previously
  // the last) meant a message whose valid signature sat anywhere else was
  // reported as failing. RFC 6376 §6.1: a verifier tries signatures until
  // one passes; the message is authenticated if ANY signature verifies.
  let sigHeaders = [];
  for (let i = 0; i < headers.length; i++) {
    if (headers[i].name.toLowerCase() === 'dkim-signature') sigHeaders.push(headers[i]);
  }
  if (sigHeaders.length === 0) {
    return cb(null, { result: 'none', reason: 'No DKIM-Signature header' });
  }

  // Try each in turn; remember the most informative failure so that when all
  // of them fail the caller still learns why.
  let results = [];
  let idx = 0;

  function tryNext() {
    if (idx >= sigHeaders.length) {
      // None passed. Report the first failure, but carry every result so a
      // caller that cares about a specific signer's domain can look.
      return cb(null, withSignatures(results[0], results));
    }
    verifyOne(sigHeaders[idx++], function(res) {
      results.push(res);
      if (res.result === 'pass') {
        return cb(null, withSignatures(res, results));
      }
      tryNext();
    });
  }

  function verifyOne(dkimHeader, done) {
    // Parse DKIM-Signature tags
    let tags = parseTags(dkimHeader.value);
    if (!tags.v || !tags.a || !tags.d || !tags.s || !tags.h || !tags.bh || !tags.b) {
      return done({ result: 'permerror', reason: 'Missing required DKIM tags' });
    }

    let domain = tags.d;
    let selector = tags.s;
    let algo = tags.a;
    let signedHeaderList = tags.h.split(':').map(function(s) { return s.trim().toLowerCase(); });
    let claimedBodyHash = tags.bh;
    let signatureB64 = tags.b.replace(/\s+/g, '');

    // RFC 6376 §3.5 "x=": the signature is expired and MUST be treated as
    // though it were never there. Without this check an attacker who obtains
    // a leaked or rotated-out key can replay old signed mail indefinitely.
    // The value is seconds since the epoch; a malformed one is ignored
    // rather than treated as expired.
    if (tags.x) {
      let expiry = parseInt(tags.x, 10);
      if (!isNaN(expiry) && expiry > 0 && Date.now() / 1000 > expiry) {
        return done({ result: 'fail', reason: 'Signature expired (x=' + expiry + ')', domain: domain });
      }
      // §3.5 also requires x= to be greater than t= when both are present.
      if (tags.t) {
        let signedAt = parseInt(tags.t, 10);
        if (!isNaN(expiry) && !isNaN(signedAt) && expiry < signedAt) {
          return done({ result: 'permerror', reason: 'Signature expiry precedes timestamp', domain: domain });
        }
      }
    }

    // RFC 6376 §3.5 "c=": which canonicalization the SIGNER used. Verifying
    // with the wrong algorithm produces a completely different hash, so a
    // perfectly valid c=simple message was previously reported as a body-hash
    // failure — which, through DMARC alignment, can get legitimate mail
    // rejected. Default when absent is "simple/simple", NOT relaxed.
    let canon = parseCanonicalization(tags.c);

    // Verify body hash
    let canonBody = canonicalizeBody(body, canon.body);
    let computedBodyHash = crypto.createHash('sha256').update(canonBody, 'latin1').digest('base64');

    if (computedBodyHash !== claimedBodyHash) {
      return done({ result: 'fail', reason: 'Body hash mismatch', domain: domain });
    }

    // DNS lookup for public key (with cache)
    let dnsName = selector + '._domainkey.' + domain;
    dnsCache.txt(dnsName, function(err, records) {
      if (err || !records || records.length === 0) {
        return done({ result: 'temperror', reason: 'DNS lookup failed for ' + dnsName, domain: domain });
      }

      let flat = records.map(function(r) { return r.join(''); });
      let dkimRecord = flat.find(function(r) { return r.indexOf('v=DKIM1') >= 0; });

      if (!dkimRecord) {
        return done({ result: 'permerror', reason: 'No DKIM record at ' + dnsName, domain: domain });
      }

      let pubKeyB64 = extractDkimPublicKey(dkimRecord, algo);
      if (!pubKeyB64) {
        return done({ result: 'permerror', reason: 'Could not extract public key', domain: domain });
      }

      // Reconstruct signing data. Headers are consumed BOTTOM-UP: when h=
      // names the same field twice (oversigning), the second reference must
      // pick the next instance further up the message, not the same one
      // again (RFC 6376 §5.4.2).
      let used = {};
      let signData = '';
      for (let i = 0; i < signedHeaderList.length; i++) {
        let name = signedHeaderList[i];
        let h = findHeaderNth(headers, name, used[name] || 0);
        if (h) {
          used[name] = (used[name] || 0) + 1;
          signData += canonicalizeHeader(h, canon.header) + '\r\n';
        }
      }

      // Add the DKIM-Signature header itself with an emptied b= value. Under
      // simple canonicalization the rest of the line must survive byte for
      // byte, so we edit only the b= run in place.
      let dkimWithoutB;
      if (canon.header === 'relaxed') {
        let dkimRaw = dkimHeader.raw.replace(/^[^:]+:\s*/, '');
        dkimWithoutB = canonicalizeHeaderRelaxed('dkim-signature',
          dkimRaw.replace(/b=[^;]*(?:;|$)/, function(m) { return m.slice(-1) === ';' ? 'b=;' : 'b='; }));
      } else {
        dkimWithoutB = dkimHeader.raw.replace(/(b=)[^;]*/, '$1');
      }
      signData += dkimWithoutB;

      // Build public key PEM
      let pubKeyPem = buildPublicKeyPem(pubKeyB64, algo);

      // Verify signature
      let signatureBuffer = Buffer.from(signatureB64, 'base64');

      try {
        let valid = false;
        if (algo === 'ed25519-sha256') {
          // Mirror of the signing path — verify against the SHA-256 digest
          // of the header block (RFC 8463 §3), not the block itself.
          valid = crypto.verify(null,
            crypto.createHash('sha256').update(signData, 'latin1').digest(),
            pubKeyPem, signatureBuffer);
        } else {
          let verifier = crypto.createVerify('SHA256');
          verifier.update(signData, 'latin1');
          valid = verifier.verify(pubKeyPem, signatureBuffer);
        }

        if (valid) {
          done({ result: 'pass', domain: domain, selector: selector, algo: algo,
                 canonicalization: canon.header + '/' + canon.body });
        } else {
          done({ result: 'fail', reason: 'Signature verification failed', domain: domain });
        }
      } catch(e) {
        done({ result: 'permerror', reason: 'Crypto error: ' + e.message, domain: domain });
      }
    });
  }

  tryNext();
}


// ============================================================
//  DKIM tag parsing
// ============================================================



// ============================================================
//  Public key extraction from DNS record
// ============================================================

function extractDkimPublicKey(record, algo) {
  let tags = parseTags(record);
  return tags.p || null;
}

function buildPublicKeyPem(b64Key, algo) {
  if (algo === 'ed25519-sha256') {
    // Ed25519: b64Key is raw 32-byte key, wrap in SPKI DER
    let rawKey = Buffer.from(b64Key, 'base64');
    if (rawKey.length === 32) {
      // Build SPKI: OID header (12 bytes) + raw key (32 bytes)
      let spkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
      let spkiDer = Buffer.concat([spkiHeader, rawKey]);
      let spkiB64 = spkiDer.toString('base64');
      return '-----BEGIN PUBLIC KEY-----\n' + spkiB64 + '\n-----END PUBLIC KEY-----';
    }
    // Already full SPKI
    return '-----BEGIN PUBLIC KEY-----\n' + b64Key + '\n-----END PUBLIC KEY-----';
  }

  // RSA: b64Key is already SPKI DER
  // Wrap in PEM with proper line breaks
  let wrapped = '';
  for (let i = 0; i < b64Key.length; i += 64) {
    wrapped += b64Key.slice(i, i + 64) + '\n';
  }
  return '-----BEGIN PUBLIC KEY-----\n' + wrapped + '-----END PUBLIC KEY-----';
}


// ============================================================
//  Exports
// ============================================================

export {
  sign,
  verify,
  canonicalizeHeaderRelaxed,
  canonicalizeBodyRelaxed,
  canonicalizeHeaderSimple,
  canonicalizeBodySimple,
  parseCanonicalization
};
