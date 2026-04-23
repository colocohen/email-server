
import crypto from 'node:crypto';

import * as dnsCache from './dns_cache.js';
import { toU8, u8ToStr, parseTags, parseMailHeaders } from './utils.js';


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

// --- Relaxed body canonicalization ---
function canonicalizeBodyRelaxed(body) {
  let str = (body instanceof Uint8Array) ? u8ToStr(body) :
            (Buffer.isBuffer(body)) ? body.toString('utf-8') : String(body);

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

function findHeader(headers, name) {
  let low = name.toLowerCase();
  for (let i = headers.length - 1; i >= 0; i--) {
    if (headers[i].name.toLowerCase() === low) return headers[i];
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

  let str = (rawMessage instanceof Uint8Array) ? u8ToStr(rawMessage) :
            (Buffer.isBuffer(rawMessage)) ? rawMessage.toString('utf-8') : String(rawMessage);

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

  // Body hash (SHA-256)
  let bodyHash = crypto.createHash('sha256').update(canonBody).digest('base64');

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

  // Sign
  let signature;
  if (algo === 'ed25519-sha256') {
    // Ed25519: sign the SHA-256 hash of the data
    let keyObj = crypto.createPrivateKey(privateKey);
    signature = crypto.sign(null, Buffer.from(signData), keyObj);
  } else {
    // RSA-SHA256
    let signer = crypto.createSign('SHA256');
    signer.update(signData);
    signature = signer.sign(privateKey);
  }

  let b64Sig = signature.toString('base64');

  // Fold the signature for line length
  let fullDkimValue = dkimHeader + foldB64(b64Sig);
  let dkimHeaderLine = 'DKIM-Signature: ' + fullDkimValue;

  // Prepend DKIM-Signature to the message
  let signedMessage = dkimHeaderLine + '\r\n' + str;

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
  let str = (rawMessage instanceof Uint8Array) ? u8ToStr(rawMessage) :
            (Buffer.isBuffer(rawMessage)) ? rawMessage.toString('utf-8') : String(rawMessage);

  let parsed = parseMailHeaders(str);
  let headers = parsed.headers;
  let body = parsed.body;

  // Find DKIM-Signature header
  let dkimHeader = findHeader(headers, 'DKIM-Signature');
  if (!dkimHeader) {
    return cb(null, { result: 'none', reason: 'No DKIM-Signature header' });
  }

  // Parse DKIM-Signature tags
  let tags = parseTags(dkimHeader.value);
  if (!tags.v || !tags.a || !tags.d || !tags.s || !tags.h || !tags.bh || !tags.b) {
    return cb(null, { result: 'permerror', reason: 'Missing required DKIM tags' });
  }

  let domain = tags.d;
  let selector = tags.s;
  let algo = tags.a;
  let signedHeaderList = tags.h.split(':').map(function(s) { return s.trim().toLowerCase(); });
  let claimedBodyHash = tags.bh;
  let signatureB64 = tags.b.replace(/\s+/g, '');

  // Verify body hash
  let canonBody = canonicalizeBodyRelaxed(body);
  let computedBodyHash = crypto.createHash('sha256').update(canonBody).digest('base64');

  if (computedBodyHash !== claimedBodyHash) {
    return cb(null, { result: 'fail', reason: 'Body hash mismatch', domain: domain });
  }

  // DNS lookup for public key (with cache)
  let dnsName = selector + '._domainkey.' + domain;
  dnsCache.txt(dnsName, function(err, records) {
    if (err || !records || records.length === 0) {
      return cb(null, { result: 'temperror', reason: 'DNS lookup failed for ' + dnsName, domain: domain });
    }

    let flat = records.map(function(r) { return r.join(''); });
    let dkimRecord = flat.find(function(r) { return r.indexOf('v=DKIM1') >= 0; });

    if (!dkimRecord) {
      return cb(null, { result: 'permerror', reason: 'No DKIM record at ' + dnsName, domain: domain });
    }

    let pubKeyB64 = extractDkimPublicKey(dkimRecord, algo);
    if (!pubKeyB64) {
      return cb(null, { result: 'permerror', reason: 'Could not extract public key', domain: domain });
    }

    // Reconstruct signing data
    let signData = '';
    for (let i = 0; i < signedHeaderList.length; i++) {
      let h = findHeader(headers, signedHeaderList[i]);
      if (h) {
        signData += canonicalizeHeaderRelaxed(h.name, h.raw.replace(/^[^:]+:\s*/, '')) + '\r\n';
      }
    }

    // Add DKIM-Signature header without b= value
    let dkimRaw = dkimHeader.raw.replace(/^[^:]+:\s*/, '');
    let dkimWithoutB = dkimRaw.replace(/b=[^;]*(?:;|$)/, 'b=');
    signData += canonicalizeHeaderRelaxed('dkim-signature', dkimWithoutB);

    // Build public key PEM
    let pubKeyPem = buildPublicKeyPem(pubKeyB64, algo);

    // Verify signature
    let signatureBuffer = Buffer.from(signatureB64, 'base64');

    try {
      let valid = false;
      if (algo === 'ed25519-sha256') {
        valid = crypto.verify(null, Buffer.from(signData), pubKeyPem, signatureBuffer);
      } else {
        let verifier = crypto.createVerify('SHA256');
        verifier.update(signData);
        valid = verifier.verify(pubKeyPem, signatureBuffer);
      }

      if (valid) {
        cb(null, { result: 'pass', domain: domain, selector: selector, algo: algo });
      } else {
        cb(null, { result: 'fail', reason: 'Signature verification failed', domain: domain });
      }
    } catch(e) {
      cb(null, { result: 'permerror', reason: 'Crypto error: ' + e.message, domain: domain });
    }
  });
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
  canonicalizeBodyRelaxed
};
