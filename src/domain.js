
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
    requiredDNS: [],
    verifyDNS: null
  };

  // Build required DNS records
  material.requiredDNS = buildRequiredDNS(domain, material.dkim, options.policy);

  // verifyDNS function
  material.verifyDNS = function(cb) {
    verifyDNS(domain, material.dkim, cb);
  };

  return material;
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

function buildRequiredDNS(domain, dkim, policy) {
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

  return records;
}


// ============================================================
//  Verify DNS records
// ============================================================

function verifyDNS(domain, dkim, cb) {
  let dns;
  try { dns = require('dns'); } catch(e) {
    return cb(new Error('dns module not available'));
  }

  let results = { dkim: false, spf: false, dmarc: false, mx: false };
  let pending = 4;

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
}


export { buildDomainMailMaterial };
