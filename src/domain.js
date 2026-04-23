
import crypto from 'node:crypto';


// ============================================================
//  buildDomainMailMaterial
// ============================================================

function buildDomainMailMaterial(domain, options) {
  if (!domain || typeof domain !== 'string') {
    throw new Error('domain is required');
  }
  options = options || {};

  let material = {
    domain: domain,
    dkim: buildDkimMaterial(domain, options.dkim),
    tls: options.tls || null,
    mtaSts: null,
    tlsRpt: null,
    requiredDNS: [],
    verifyDNS: null
  };

  // MTA-STS (RFC 8461) — opt-in via options.mtaSts. When enabled, the library
  // produces the policy file contents, the TXT record, and an HTTP handler the
  // user can mount on their mta-sts.<domain> HTTPS endpoint. The actual HTTPS
  // hosting (cert, subdomain) is on the operator.
  if (options.mtaSts) {
    material.mtaSts = buildMtaStsMaterial(domain, options.mtaSts);
  }

  // TLS-RPT (RFC 8460) — opt-in. Enabled when the caller provides either a
  // ready-made `rua` URI (e.g. 'mailto:...' or 'https://...') or the shorter
  // `ruaEmail` shortcut.
  if (options.tlsRpt && (options.tlsRpt.ruaEmail || options.tlsRpt.rua)) {
    material.tlsRpt = buildTlsRptMaterial(domain, options.tlsRpt);
  }

  // Build required DNS records
  material.requiredDNS = buildRequiredDNS(domain, material.dkim, options.policy,
                                          material.mtaSts, material.tlsRpt);

  // verifyDNS function
  material.verifyDNS = function(cb) {
    verifyDNS(domain, material.dkim, material.mtaSts, material.tlsRpt, cb);
  };

  return material;
}


// ============================================================
//  MTA-STS (RFC 8461)
// ============================================================
//
// MTA-STS lets a receiving domain tell all sending servers: "every hop to
// me MUST be TLS, with a cert that validates against my MX name." Without
// it, attackers on the network can force STARTTLS to be skipped (downgrade
// attack) and mail is delivered in plaintext.
//
// Deployment requires three pieces:
//
//   1. DNS TXT at _mta-sts.<domain> announcing the policy exists + its id
//   2. HTTPS-served policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt
//   3. A TLS certificate for the mta-sts.<domain> subdomain
//
// This library generates (1) and (2) — the operator provides (3) via
// whatever HTTPS stack they already run (certbot, Cloudflare, etc).
//
// The `id` field in both the TXT and the policy MUST match and MUST change
// whenever the policy changes; clients cache by id. We default to an
// ISO-derived timestamp which is monotonic and human-readable.

function buildMtaStsMaterial(domain, opts) {
  let mode  = (opts.mode || 'enforce').toLowerCase();   // enforce | testing | none
  let maxAge = opts.maxAgeSeconds || 604800;            // 1 week — RFC 8461 §3.2 recommends >= 1 day
  // Accept either `mx: ['mx.example.com']` or `mx: 'mx.example.com'` (single).
  // Wildcards like '*.mail.example.com' are allowed per §3.2.
  let mx = opts.mx;
  if (typeof mx === 'string') mx = [mx];
  if (!Array.isArray(mx) || mx.length === 0) mx = ['mx.' + domain];

  let id = opts.id || buildStsId();

  // Build policy file text. Format per RFC 8461 §3.2 — LF line separators,
  // key/value pairs. Clients treat CRLF the same as LF so we use \r\n for
  // wire-friendliness.
  let policy = '';
  policy += 'version: STSv1\r\n';
  policy += 'mode: ' + mode + '\r\n';
  for (let i = 0; i < mx.length; i++) {
    policy += 'mx: ' + mx[i] + '\r\n';
  }
  policy += 'max_age: ' + maxAge + '\r\n';

  return {
    id:        id,
    mode:      mode,
    mx:        mx,
    maxAge:    maxAge,
    policy:    policy,
    policyUrl: 'https://mta-sts.' + domain + '/.well-known/mta-sts.txt',
    policyHost:'mta-sts.' + domain,

    // HTTP(S) handler you can mount directly onto an http / https server:
    //
    //   http.createServer(material.mtaSts.serve).listen(...)
    //
    // Serves the policy with the right content-type and cache headers.
    // Only responds to /.well-known/mta-sts.txt — everything else 404s.
    serve: function(req, res) {
      // Accept both exact path and trailing-slash variants
      let path = (req.url || '').split('?')[0];
      if (path !== '/.well-known/mta-sts.txt') {
        res.statusCode = 404;
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.end('Not Found\n');
        return;
      }
      res.statusCode = 200;
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      // RFC 8461 §3.3 — clients fetch based on id + TXT, so a short
      // cache window (e.g. 5 min) is fine; the policy itself is stable.
      res.setHeader('Cache-Control', 'max-age=300, public');
      res.end(policy);
    }
  };
}

// Build a stable STS policy id. Format suggested by RFC 8461 §3.1: any
// 1-32 character string; we use an ISO-like timestamp which is naturally
// monotonic and human-readable.
function buildStsId() {
  let d = new Date();
  return d.getUTCFullYear().toString() +
         pad2(d.getUTCMonth() + 1) +
         pad2(d.getUTCDate()) +
         'T' +
         pad2(d.getUTCHours()) +
         pad2(d.getUTCMinutes()) +
         pad2(d.getUTCSeconds()) + 'Z';
}
function pad2(n) { return (n < 10 ? '0' : '') + n; }


// ============================================================
//  TLS-RPT (RFC 8460)
// ============================================================
//
// Paired with MTA-STS. Tells other MTAs: "if TLS to me fails, email a
// report to this address." Daily aggregate JSON reports from Gmail/Outlook
// arrive in your inbox so you can detect cert expiry, MTA-STS misconfigs,
// or active downgrade attempts you'd otherwise miss.
//
// Ruas can be mailto: or https: URIs. We accept an email address (wrapped
// as mailto:) or a full URI for flexibility.
function buildTlsRptMaterial(domain, opts) {
  let rua;
  if (opts.rua) {
    rua = opts.rua;
  } else if (opts.ruaEmail) {
    rua = 'mailto:' + opts.ruaEmail;
  } else {
    rua = 'mailto:tls-reports@' + domain;
  }
  return {
    rua:   rua,
    value: 'v=TLSRPTv1; rua=' + rua
  };
}


// ============================================================
//  DKIM key generation / normalization
// ============================================================

function buildDkimMaterial(domain, dkimOpts) {
  dkimOpts = dkimOpts || {};

  let algo = dkimOpts.algo || 'rsa-sha256';
  let selector = dkimOpts.selector || buildSelector();
  let privateKey = dkimOpts.privateKey || null;
  let publicKey = null;

  if (!privateKey) {
    // Auto-generate key pair
    let pair = generateKeyPair(algo);
    privateKey = pair.privateKey;
    publicKey = pair.publicKey;
  } else {
    // Extract public key from provided private key
    publicKey = extractPublicKey(privateKey, algo);
  }

  // Build DNS TXT value for the public key
  let dnsValue = buildDkimDnsValue(algo, publicKey);

  return {
    selector: selector,
    algo: algo,
    privateKey: privateKey,
    publicKey: publicKey,
    dnsName: selector + '._domainkey.' + domain,
    dnsValue: dnsValue
  };
}

function buildSelector() {
  let d = new Date();
  let y = d.getFullYear();
  let m = String(d.getMonth() + 1).padStart(2, '0');
  return 's' + y + m;
}

function generateKeyPair(algo) {
  if (algo === 'ed25519-sha256') {
    let pair = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' }
    });
    return { privateKey: pair.privateKey, publicKey: pair.publicKey };
  }

  // Default: rsa-sha256
  let pair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' }
  });
  return { privateKey: pair.privateKey, publicKey: pair.publicKey };
}

function extractPublicKey(privateKeyPem, algo) {
  try {
    let keyObj = crypto.createPrivateKey(privateKeyPem);
    let pubPem = keyObj.export({ type: 'spki', format: 'pem' });
    return pubPem;
  } catch(e) {
    return null;
  }
}

function buildDkimDnsValue(algo, publicKeyPem) {
  if (!publicKeyPem) return null;

  let k = (algo === 'ed25519-sha256') ? 'ed25519' : 'rsa';

  if (k === 'ed25519') {
    // Ed25519: DNS needs raw 32-byte public key, not full SPKI
    try {
      let keyObj = crypto.createPublicKey(publicKeyPem);
      let raw = keyObj.export({ type: 'spki', format: 'der' });
      // SPKI for Ed25519 is 44 bytes: 12 bytes ASN.1 header + 32 bytes key
      let rawKey = raw.slice(raw.length - 32);
      let b64 = Buffer.from(rawKey).toString('base64');
      return 'v=DKIM1; k=ed25519; p=' + b64;
    } catch(e) {
      // Fallback: use full PEM base64
      let b64 = publicKeyPem
        .replace(/-----BEGIN PUBLIC KEY-----/, '')
        .replace(/-----END PUBLIC KEY-----/, '')
        .replace(/\s+/g, '');
      return 'v=DKIM1; k=ed25519; p=' + b64;
    }
  }

  // RSA: full SPKI DER as base64
  let b64 = publicKeyPem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s+/g, '');
  return 'v=DKIM1; k=rsa; h=sha256; p=' + b64;
}


// ============================================================
//  Build required DNS records
// ============================================================

function buildRequiredDNS(domain, dkim, policy, mtaSts, tlsRpt) {
  policy = policy || {};
  let records = [];

  // DKIM
  if (dkim && dkim.dnsName && dkim.dnsValue) {
    records.push({
      type: 'TXT',
      name: dkim.dnsName,
      value: dkim.dnsValue
    });
  }

  // SPF
  records.push({
    type: 'TXT',
    name: domain,
    value: policy.spfTxt || 'v=spf1 mx a ~all'
  });

  // DMARC
  records.push({
    type: 'TXT',
    name: '_dmarc.' + domain,
    value: policy.dmarcTxt || 'v=DMARC1; p=quarantine; adkim=s; aspf=s'
  });

  // MX hint
  records.push({
    type: 'MX',
    name: domain,
    value: '10 mx.' + domain
  });

  // MTA-STS (RFC 8461) — two records when enabled:
  //   (a) _mta-sts.<domain> TXT announcing the policy id
  //   (b) A/AAAA for mta-sts.<domain> is NOT our concern — that's whoever
  //       hosts the HTTPS — but we flag it so the operator knows to set it.
  if (mtaSts) {
    records.push({
      type:  'TXT',
      name:  '_mta-sts.' + domain,
      value: 'v=STSv1; id=' + mtaSts.id
    });
    records.push({
      type:  'A_OR_CNAME',
      name:  mtaSts.policyHost,
      value: '<point to the HTTPS server that will serve the policy file>',
      note:  'Needs HTTPS with a valid TLS cert for this hostname. ' +
             'Policy file: ' + mtaSts.policyUrl
    });
  }

  // TLS-RPT (RFC 8460) — TXT record at _smtp._tls.<domain>
  if (tlsRpt) {
    records.push({
      type:  'TXT',
      name:  '_smtp._tls.' + domain,
      value: tlsRpt.value
    });
  }

  return records;
}


// ============================================================
//  Verify DNS records
// ============================================================

function verifyDNS(domain, dkim, mtaSts, tlsRpt, cb) {
  let dns;
  try { dns = require('dns'); } catch(e) {
    return cb(new Error('dns module not available'));
  }

  let results = { dkim: false, spf: false, dmarc: false, mx: false };
  if (mtaSts) results.mtaSts = false;
  if (tlsRpt) results.tlsRpt = false;

  // Count tasks up-front so we can fan-in cleanly
  let pending = 4 + (mtaSts ? 1 : 0) + (tlsRpt ? 1 : 0);

  function done() {
    pending--;
    if (pending === 0) cb(null, results);
  }

  // Check DKIM
  if (dkim && dkim.dnsName) {
    dns.resolveTxt(dkim.dnsName, function(err, records) {
      if (!err && records) {
        let flat = records.map(function(r) { return r.join(''); });
        results.dkim = flat.some(function(r) { return r.indexOf('v=DKIM1') >= 0; });
      }
      done();
    });
  } else {
    done();
  }

  // Check SPF
  dns.resolveTxt(domain, function(err, records) {
    if (!err && records) {
      let flat = records.map(function(r) { return r.join(''); });
      results.spf = flat.some(function(r) { return r.indexOf('v=spf1') >= 0; });
    }
    done();
  });

  // Check DMARC
  dns.resolveTxt('_dmarc.' + domain, function(err, records) {
    if (!err && records) {
      let flat = records.map(function(r) { return r.join(''); });
      results.dmarc = flat.some(function(r) { return r.indexOf('v=DMARC1') >= 0; });
    }
    done();
  });

  // Check MX
  dns.resolveMx(domain, function(err, records) {
    if (!err && records && records.length > 0) {
      results.mx = true;
    }
    done();
  });

  // Check MTA-STS TXT — just the TXT record. We don't fetch the HTTPS
  // policy here because that requires an HTTPS GET which is a different
  // beast; leave that to an explicit policy-fetch helper if desired.
  if (mtaSts) {
    dns.resolveTxt('_mta-sts.' + domain, function(err, records) {
      if (!err && records) {
        let flat = records.map(function(r) { return r.join(''); });
        results.mtaSts = flat.some(function(r) {
          return /v=STSv1\b/i.test(r) && r.indexOf('id=' + mtaSts.id) >= 0;
        });
      }
      done();
    });
  }

  // Check TLS-RPT TXT
  if (tlsRpt) {
    dns.resolveTxt('_smtp._tls.' + domain, function(err, records) {
      if (!err && records) {
        let flat = records.map(function(r) { return r.join(''); });
        results.tlsRpt = flat.some(function(r) { return /v=TLSRPTv1\b/i.test(r); });
      }
      done();
    });
  }
}


export { buildDomainMailMaterial };
