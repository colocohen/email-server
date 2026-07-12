// ============================================================================
//  received.js  —  Received: trace headers (RFC 5321 §4.4) + loop detection
// ----------------------------------------------------------------------------
//  A conforming MTA stamps every inbound message with a Received: header so
//  the delivery path is traceable, and refuses mail that has looped through
//  too many hops. Both live here.
//
//  This module is pure (no I/O) and self-contained. The server layer calls
//  buildReceivedHeader() when a message arrives and prepends the result to the
//  raw bytes; it calls countReceivedHops() to enforce a loop ceiling.
// ============================================================================

const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const DAYS   = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];

// RFC 5322 date-time, e.g. "Wed, 22 Apr 2026 15:04:05 +0000"
function rfc5322Date(d) {
  d = d || new Date();
  let pad = n => (n < 10 ? '0' + n : '' + n);
  let off = -d.getTimezoneOffset();
  let sign = off < 0 ? '-' : '+';
  let abs = Math.abs(off);
  let tz = sign + pad(Math.floor(abs / 60)) + pad(abs % 60);
  return DAYS[d.getDay()] + ', ' + pad(d.getDate()) + ' ' + MONTHS[d.getMonth()] + ' ' +
         d.getFullYear() + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' +
         pad(d.getSeconds()) + ' ' + tz;
}

// Fold a long Received value to keep lines under ~78 chars (RFC 5322 §2.2.3).
// We fold at the clause boundaries (from / by / with / id / for), which is
// where real MTAs fold, keeping the header readable.
function foldReceived(value) {
  // Insert a CRLF + TAB before each clause keyword when the running line grows.
  let out = 'Received:';
  let lineLen = out.length;
  let tokens = value.split(' ');
  for (let i = 0; i < tokens.length; i++) {
    let t = tokens[i];
    let isClause = /^(from|by|via|with|id|for)$/.test(t) && i > 0;
    if (isClause && lineLen > 60) {
      out += '\r\n\t' + t;
      lineLen = 1 + t.length;
    } else {
      out += ' ' + t;
      lineLen += 1 + t.length;
    }
  }
  return out;
}

// Build a single Received: header (WITHOUT trailing CRLF).
//
//   opts = {
//     from:        remote HELO/EHLO name (string) or null
//     fromIp:      remote IP (string) or null
//     fromRdns:    reverse-DNS hostname of the client (string) or null
//     by:          this server's hostname (string, required)
//     protocol:    'SMTP' | 'ESMTP' | 'ESMTPS' | 'ESMTPSA' | 'LMTP' ...
//                  (SA = authenticated; S = TLS). Auto-derived if not given.
//     tls:         boolean — connection was TLS
//     authenticated: boolean — session authenticated (submission)
//     id:          this server's internal queue/connection id (string) or null
//     forRecipient: envelope recipient to note in "for <addr>" (string) or null
//                   Only include ONE recipient here (RFC 5321 §4.4 — never leak
//                   the full BCC-inclusive recipient list).
//     date:        Date (defaults to now)
//   }
//
// Produces, e.g.:
//   Received: from mail.example.com (mail.example.com [203.0.113.5])
//           by mx.ours.net with ESMTPS id ab12cd34
//           for <user@ours.net>; Wed, 22 Apr 2026 15:04:05 +0000
function buildReceivedHeader(opts) {
  opts = opts || {};
  let by = opts.by || 'localhost';

  // "from" clause: "from <helo> (<rdns> [<ip>])"
  let fromClause = '';
  if (opts.from || opts.fromIp || opts.fromRdns) {
    fromClause = 'from ' + (opts.from || 'unknown');
    let paren = [];
    if (opts.fromRdns) paren.push(opts.fromRdns);
    if (opts.fromIp)   paren.push('[' + opts.fromIp + ']');
    if (paren.length)  fromClause += ' (' + paren.join(' ') + ')';
  }

  // Derive the protocol token if not explicitly provided.
  let protocol = opts.protocol;
  if (!protocol) {
    protocol = 'ESMTP';
    if (opts.tls) protocol += 'S';
    if (opts.authenticated) protocol += 'A';
  }

  let parts = [];
  if (fromClause) parts.push(fromClause);
  parts.push('by ' + by);
  parts.push('with ' + protocol);
  if (opts.id) parts.push('id ' + opts.id);
  if (opts.forRecipient) {
    let r = opts.forRecipient;
    parts.push('for <' + r.replace(/^<|>$/g, '') + '>');
  }

  // The date is separated from the trace clauses by ';' per the ABNF.
  let value = parts.join(' ') + '; ' + rfc5322Date(opts.date);
  return foldReceived(value);
}

// Prepend a freshly-built Received header to raw message bytes. Returns a new
// Buffer. Accepts Buffer/Uint8Array/string for `raw`.
function prependReceived(raw, opts) {
  let header = buildReceivedHeader(opts) + '\r\n';
  let headerBuf = Buffer.from(header, 'utf-8');
  let rawBuf = Buffer.isBuffer(raw) ? raw :
               (raw instanceof Uint8Array ? Buffer.from(raw) : Buffer.from(String(raw), 'utf-8'));
  return Buffer.concat([headerBuf, rawBuf]);
}

// Count the Received: headers already present in a message. Used for loop
// detection: RFC 5321 §6.3 recommends refusing mail once the count crosses a
// threshold (commonly ~100), since each relay adds one and an unbroken loop
// grows it without bound. Only scans the header block (stops at the first
// blank line), so body content that looks like a header can't inflate it.
function countReceivedHops(raw) {
  let buf = Buffer.isBuffer(raw) ? raw :
            (raw instanceof Uint8Array ? Buffer.from(raw) : Buffer.from(String(raw), 'utf-8'));
  let count = 0;
  let len = buf.length;
  let lineStart = 0;

  while (lineStart < len) {
    // A line that begins with CR or LF at column 0 is the blank line that
    // terminates the header block — stop scanning (body follows).
    if (buf[lineStart] === 0x0D || buf[lineStart] === 0x0A) break;

    // Case-insensitive "Received:" at column 0 of this header line.
    if (lineStart + 9 <= len &&
        (buf[lineStart]     === 0x52 || buf[lineStart]     === 0x72) && // R
        (buf[lineStart + 1] === 0x65 || buf[lineStart + 1] === 0x45) && // e
        (buf[lineStart + 2] === 0x63 || buf[lineStart + 2] === 0x43) && // c
        (buf[lineStart + 3] === 0x65 || buf[lineStart + 3] === 0x45) && // e
        (buf[lineStart + 4] === 0x69 || buf[lineStart + 4] === 0x49) && // i
        (buf[lineStart + 5] === 0x76 || buf[lineStart + 5] === 0x56) && // v
        (buf[lineStart + 6] === 0x65 || buf[lineStart + 6] === 0x45) && // e
        (buf[lineStart + 7] === 0x64 || buf[lineStart + 7] === 0x44) && // d
        buf[lineStart + 8] === 0x3A) {                                  // :
      count++;
    }

    // Advance to the start of the next unfolded header line: skip to the next
    // LF, then skip any continuation lines (those beginning with SP/HTAB).
    let j = lineStart;
    while (j < len && buf[j] !== 0x0A) j++;
    j++; // past the LF
    while (j < len && (buf[j] === 0x20 || buf[j] === 0x09)) {
      // folded continuation — skip to the next LF too
      while (j < len && buf[j] !== 0x0A) j++;
      j++;
    }
    lineStart = j;
  }
  return count;
}

export { buildReceivedHeader, prependReceived, countReceivedHops, rfc5322Date };
