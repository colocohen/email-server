/**
 * DKIM keys: read and written by cryptographic-formats (PEM, PKCS#8, PKCS#1,
 * SPKI), generated, signed and verified by cryptographic-primitives — the
 * library picks native or pure JavaScript.
 *
 *   privateKey(input)        a PEM private key (string or Buffer: PKCS#8 or
 *                            PKCS#1 "RSA PRIVATE KEY"), its DER, or a
 *                            node:crypto KeyObject →
 *                            { algorithm, publicKeyPem, sign(bytes) }
 *   publicKey(pem)           an SPKI PEM → { algorithm, verify(bytes, sig) }
 *   generateKeyPair(algo)    'ed25519-sha256' | 'rsa-sha256' (2048 bits) →
 *                            { privateKey, publicKey } as PEM
 *
 * algorithm is 'rsaEncryption' or 'Ed25519'. RSA signs and verifies
 * RSASSA-PKCS1-v1_5 with SHA-256 over the bytes; Ed25519 signs the bytes
 * as they are (DKIM hands it their SHA-256 digest, RFC 8463 §3).
 */

import * as PEM from 'cryptographic-formats/pem';
import * as PKCS8 from 'cryptographic-formats/pkcs8';
import * as SPKI from 'cryptographic-formats/spki';
import * as RSA from 'cryptographic-primitives/rsa.js';
import * as ED25519 from 'cryptographic-primitives/ed25519.js';
import { sha256_sync } from 'cryptographic-primitives/sha2.js';

const PEM_FORMS = { 'PRIVATE KEY': PKCS8.from_der, 'RSA PRIVATE KEY': PKCS8.pkcs1_from_der };

function big(bytes) {
  let n = 0n;
  for (let i = 0; i < bytes.length; i++) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}
function bytes_of(n) {
  let h = n.toString(16);
  if (h.length % 2) h = '0' + h;
  return new Uint8Array(Buffer.from(h, 'hex'));
}

// A node:crypto KeyObject, told by its shape (read through its own export(),
// so this module needs no node:crypto)
function isKeyObject(x) {
  return !!x && typeof x === 'object' && typeof x.export === 'function' && typeof x.type === 'string';
}

// The parsed private key (cryptographic-formats' { algorithm, rsa | scalar })
function parsePrivate(input) {
  if (isKeyObject(input)) return PKCS8.from_der(new Uint8Array(input.export({ format: 'der', type: 'pkcs8' })));
  let isText = typeof input === 'string' || (input instanceof Uint8Array && input.length > 0 && input[0] !== 0x30);
  if (isText) {
    let blocks = PEM.decode(typeof input === 'string' ? input : Buffer.from(input).toString('latin1'));
    for (let i = 0; i < blocks.length; i++) {
      let read = PEM_FORMS[blocks[i].label];
      if (read && !blocks[i].encrypted) return read(blocks[i].der);
    }
    throw new Error('no unencrypted private key in the PEM (' + blocks.map(function (b) { return b.label; }).join(', ') + ')');
  }
  let der = new Uint8Array(input);
  try { return PKCS8.from_der(der); } catch (e) { return PKCS8.pkcs1_from_der(der); }
}

// One key per input (a domain signs every message with the same key): its
// signer made once. Bounded, oldest out first.
const PRIVATE = new Map();

function privateKey(input) {
  let id = typeof input === 'string' ? input : null;
  let k = id !== null ? PRIVATE.get(id) : null;
  if (k) return k;
  let p = parsePrivate(input);
  let spki, signer, sign;
  if (p.algorithm === 'rsaEncryption') {
    let r = p.rsa;
    spki = SPKI.to_der({ algorithm: 'rsaEncryption', rsa: { n: r.n, e: r.e } });
    signer = RSA.signer_create({ n: big(r.n), e: big(r.e), d: big(r.d), p: big(r.p), q: big(r.q),
                                 dp: big(r.dp), dq: big(r.dq), qinv: big(r.qinv) });
    sign = function (bytes) { return signer.sign_pkcs1_message_sync(bytes, sha256_sync); };
  } else if (p.algorithm === 'Ed25519') {
    spki = SPKI.to_der({ algorithm: 'Ed25519', point: ED25519.get_public_key_sync(p.scalar) });
    signer = ED25519.signer_create(p.scalar);
    sign = function (bytes) { return signer.sign_sync(bytes); };
  } else {
    throw new Error('DKIM signs with RSA or Ed25519 keys, not ' + p.algorithm);
  }
  k = { algorithm: p.algorithm, publicKeyPem: PEM.encode(spki, 'PUBLIC KEY'), sign: sign };
  if (id !== null) {
    if (PRIVATE.size >= 100) {
      let old = PRIVATE.keys().next().value;
      PRIVATE.delete(old);
    }
    PRIVATE.set(id, k);
  }
  return k;
}

// A verifier per public key: a receiver sees the same few selectors again and again
const PUBLIC = new Map();

function publicKey(pem) {
  let k = PUBLIC.get(pem);
  if (k) return k;
  let s = SPKI.from_der(PEM.decode_one(pem, 'PUBLIC KEY').der);
  let verify;
  if (s.algorithm === 'rsaEncryption') {
    let v = RSA.verifier_create({ n: big(s.rsa.n), e: big(s.rsa.e) });
    verify = function (bytes, sig) { return v.verify_pkcs1_message_sync(bytes, sig, sha256_sync) === true; };
  } else if (s.algorithm === 'Ed25519') {
    let v = ED25519.verifier_create(s.point, undefined, undefined, 'strict');
    verify = function (bytes, sig) { return v.verify_sync(bytes, sig) === true; };
  } else {
    throw new Error('a DKIM key is RSA or Ed25519, not ' + s.algorithm);
  }
  k = { algorithm: s.algorithm, verify: verify };
  if (PUBLIC.size >= 1000) PUBLIC.delete(PUBLIC.keys().next().value);
  PUBLIC.set(pem, k);
  return k;
}

function generateKeyPair(algo) {
  let pkcs8, spki;
  if (algo === 'ed25519-sha256') {
    let kp = ED25519.keygen_sync();
    pkcs8 = PKCS8.to_der({ algorithm: 'Ed25519', scalar: kp.sk });
    spki = SPKI.to_der({ algorithm: 'Ed25519', point: kp.pk });
    kp.sk.fill(0);
  } else {
    let k = RSA.keygen_sync(2048, null, 65537n);
    let rsa = { n: bytes_of(k.n), e: bytes_of(k.e), d: bytes_of(k.d), p: bytes_of(k.p), q: bytes_of(k.q),
                dp: bytes_of(k.dp), dq: bytes_of(k.dq), qinv: bytes_of(k.qinv) };
    pkcs8 = PKCS8.to_der({ algorithm: 'rsaEncryption', rsa: rsa });
    spki = SPKI.to_der({ algorithm: 'rsaEncryption', rsa: { n: rsa.n, e: rsa.e } });
  }
  return { privateKey: PEM.encode(pkcs8, 'PRIVATE KEY'), publicKey: PEM.encode(spki, 'PUBLIC KEY') };
}

export { privateKey, publicKey, generateKeyPair };
