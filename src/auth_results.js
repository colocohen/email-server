// ============================================================================
//  auth_results.js  —  Authentication-Results header (RFC 8601)
// ----------------------------------------------------------------------------
//  The library runs SPF, DKIM, DMARC and rDNS on every inbound message and
//  hands the verdicts to the developer on `mail.auth`. That covers the code
//  that acts on the message right now — but nothing downstream can see them:
//  an MDA, a spam filter, a client rendering "verified sender", or an admin
//  reading raw source all look for the standard header, not for a JS object
//  that stopped existing when the callback returned.
//
//  This module renders those verdicts into the RFC 8601 header:
//
//    Authentication-Results: mx.ours.net;
//            spf=pass smtp.mailfrom=example.com;
//            dkim=pass header.d=example.com;
//            dmarc=pass header.from=example.com;
//            iprev=pass policy.iprev=203.0.113.5
//
//  Security note (RFC 8601 §5): this header is only trustworthy when it was
//  added by the receiving boundary MTA — i.e. by us. Any copy that arrived
//  WITH the message is forgeable and must be removed before ours is added,
//  otherwise a sender can simply include "dmarc=pass" of their own and every
//  downstream reader believes it. stripInbound() below does that removal, and
//  the server calls it before prepending.
//
//  This module is pure (no I/O) and self-contained.
// ============================================================================

// Values that RFC 8601 §2.7 defines per method. Anything else is coerced to
// 'none' rather than passed through — an unexpected token here would be
// copied verbatim into a header other systems parse.
const VALID = {
  spf:    ['none', 'pass', 'fail', 'softfail', 'neutral', 'temperror', 'permerror'],
  dkim:   ['none', 'pass', 'fail', 'policy', 'neutral', 'temperror', 'permerror'],
  dmarc:  ['none', 'pass', 'fail', 'temperror', 'permerror'],
  iprev:  ['none', 'pass', 'fail', 'temperror', 'permerror']
};

function clean(method, value) {
  let v = String(value || 'none').toLowerCase();
  return VALID[method].indexOf(v) >= 0 ? v : 'none';
}

// A property value must be a dot-atom / quoted string. Real-world domains and
// addresses are dot-atoms already; anything with a space or a special goes in
// quotes so a malformed value can't break the header's structure.
function propValue(s) {
  let str = String(s == null ? '' : s);
  if (/^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~.@]+$/.test(str)) return str;
  return '"' + str.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/[\r\n]/g, ' ') + '"';
}

// Build the header VALUE (without the "Authentication-Results:" name and
// without a trailing CRLF).
//
//   opts = {
//     authservId:  'mx.ours.net',   // required — this server's identity
//     spf:         'pass',  spfDomain:  'example.com',   // envelope MAIL FROM domain
//     dkim:        'pass',  dkimDomain: 'example.com',   // the d= of the passing signature
//     dmarc:       'pass',  fromDomain: 'example.com',   // the From: header domain
//     iprev:       'pass',  ip:         '203.0.113.5'
//   }
//
// Methods with no result are omitted entirely; a header listing only the
// authserv-id (meaning "I checked nothing") is legal per §2.2 and is what
// you get when nothing ran.
function buildAuthResults(opts) {
  opts = opts || {};
  let id = opts.authservId || 'localhost';
  let parts = [];

  if (opts.spf) {
    let s = 'spf=' + clean('spf', opts.spf);
    if (opts.spfDomain) s += ' smtp.mailfrom=' + propValue(opts.spfDomain);
    parts.push(s);
  }
  if (opts.dkim) {
    let s = 'dkim=' + clean('dkim', opts.dkim);
    if (opts.dkimDomain) s += ' header.d=' + propValue(opts.dkimDomain);
    parts.push(s);
  }
  if (opts.dmarc) {
    let s = 'dmarc=' + clean('dmarc', opts.dmarc);
    if (opts.fromDomain) s += ' header.from=' + propValue(opts.fromDomain);
    parts.push(s);
  }
  if (opts.iprev) {
    let s = 'iprev=' + clean('iprev', opts.iprev);
    if (opts.ip) s += ' policy.iprev=' + propValue(opts.ip);
    parts.push(s);
  }

  if (parts.length === 0) return propValue(id) + '; none';

  // Fold at the method boundaries — where every MTA folds, and the only
  // place RFC 5322 permits (existing WSP).
  return propValue(id) + ';\r\n\t' + parts.join(';\r\n\t');
}

// Remove every Authentication-Results header already present. See the
// security note at the top: an inbound copy is attacker-controlled.
//
// Operates on octets and preserves them exactly (no charset decoding), and
// only scans the header block so a body line that looks like a header can't
// be mistaken for one. Returns a Buffer.
function stripInbound(raw) {
  let buf = Buffer.isBuffer(raw) ? raw :
            (raw instanceof Uint8Array ? Buffer.from(raw) : Buffer.from(String(raw), 'utf-8'));

  const NAME = 'authentication-results:';
  let keep = [];
  let len = buf.length;
  let lineStart = 0;

  while (lineStart < len) {
    // Blank line at column 0 ends the header block — copy the rest verbatim.
    if (buf[lineStart] === 0x0D || buf[lineStart] === 0x0A) {
      keep.push(buf.slice(lineStart));
      lineStart = len;
      break;
    }

    // Find the end of this unfolded header (this line plus any continuations).
    let j = lineStart;
    while (j < len && buf[j] !== 0x0A) j++;
    j++;
    while (j < len && (buf[j] === 0x20 || buf[j] === 0x09)) {
      while (j < len && buf[j] !== 0x0A) j++;
      j++;
    }

    let isAR = true;
    for (let k = 0; k < NAME.length; k++) {
      let b = buf[lineStart + k];
      if (b === undefined) { isAR = false; break; }
      let lower = (b >= 65 && b <= 90) ? b + 32 : b;
      if (lower !== NAME.charCodeAt(k)) { isAR = false; break; }
    }
    if (!isAR) keep.push(buf.slice(lineStart, j));

    lineStart = j;
  }

  return Buffer.concat(keep);
}

// Prepend a freshly-built Authentication-Results header, removing any that
// arrived with the message. Returns a Buffer.
//
// Placement: immediately BELOW the first header when that header is our own
// `Received:`, otherwise at the very top. RFC 5321 §4.4 requires the trace
// header of the current hop to be the topmost line — the Received chain is
// read top-down to reconstruct the delivery path, and slipping another header
// above it breaks that reading. This ordering also matches what receivers see
// from Gmail and from Postfix+OpenDKIM.
function prependAuthResults(raw, opts) {
  let stripped = stripInbound(raw);
  let header = Buffer.from('Authentication-Results: ' + buildAuthResults(opts) + '\r\n', 'utf-8');

  // Locate the end of the first header (including any folded continuations).
  let len = stripped.length;
  const RECEIVED = 'received:';
  let isReceived = true;
  for (let k = 0; k < RECEIVED.length; k++) {
    let b = stripped[k];
    if (b === undefined) { isReceived = false; break; }
    let lower = (b >= 65 && b <= 90) ? b + 32 : b;
    if (lower !== RECEIVED.charCodeAt(k)) { isReceived = false; break; }
  }
  if (!isReceived) return Buffer.concat([header, stripped]);

  let j = 0;
  while (j < len && stripped[j] !== 0x0A) j++;
  j++;
  while (j < len && (stripped[j] === 0x20 || stripped[j] === 0x09)) {
    while (j < len && stripped[j] !== 0x0A) j++;
    j++;
  }
  return Buffer.concat([stripped.slice(0, j), header, stripped.slice(j)]);
}

export { buildAuthResults, stripInbound, prependAuthResults };
