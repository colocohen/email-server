// ============================================================================
//  dsn.js — Delivery Status Notifications (RFC 3461 / 3464)
// ----------------------------------------------------------------------------
//  Builds a well-formed multipart/report MIME message describing the outcome
//  of a delivery attempt. Returned as a raw Buffer ready to hand to
//  sendMail({ raw: ... }) or an outbound connection directly.
//
//  Report format (RFC 3462 for multipart/report + RFC 3464 for the
//  message/delivery-status subtype):
//
//     multipart/report; report-type=delivery-status; boundary="..."
//       ├── part 1: text/plain (human-readable explanation)
//       ├── part 2: message/delivery-status (per-recipient machine-readable)
//       └── part 3: message/rfc822 or message/rfc822-headers
//                   (original message, per the sender's RET preference)
//
//  The per-recipient block in part 2 uses these fields:
//    Final-Recipient: rfc822; <addr>
//    Original-Recipient: rfc822; <addr>     (present when ORCPT was given)
//    Action: failed | delayed | delivered | relayed | expanded
//    Status: 5.x.x | 4.x.x | 2.x.x          (enhanced status code)
//    Diagnostic-Code: smtp; <reply>         (present on failed/delayed)
//    Remote-MTA: dns; <host>                (present if known)
//    Last-Attempt-Date: <rfc5322 date>      (present on failed/delayed)
//
//  Per RFC 3461 §6, the DSN MUST be sent with an empty (null) MAIL FROM to
//  prevent mail loops — a DSN that bounces generates no further DSN. The
//  envelope recipient is the message's original envelope sender.
// ============================================================================

import crypto from 'node:crypto';


// Build a DSN Buffer. `options` shape:
//
//   {
//     reportingMta: 'mail.example.com',    // required — our hostname
//     originalEnvelopeId: 'xyz123',        // optional — from MAIL FROM ENVID
//     arrivalDate: Date | string,           // when we first accepted the message
//     originalMessage: Buffer,              // the message that couldn't be delivered
//     returnContent: 'full' | 'headers',    // matches sender's RET preference
//     recipients: [
//       {
//         finalRecipient: 'bob@example.com',
//         originalRecipient: 'bob@example.com',     // optional — from ORCPT
//         action: 'failed' | 'delayed' | 'delivered' | 'relayed' | 'expanded',
//         status: '5.1.1',                          // enhanced status code
//         diagnostic: '550 5.1.1 User unknown',     // SMTP reply text
//         remoteMta: 'mx.example.com',              // optional
//         lastAttempt: Date | string,               // optional
//         willRetryUntil: Date | string             // optional, for 'delayed'
//       }
//     ],
//     // Envelope info — used for the DSN's own From/To/Subject
//     from: 'postmaster@example.com',      // default if unset: 'postmaster@<reportingMta>'
//     to: 'sender@example.com'             // the original envelope sender
//   }
function buildDsn(options) {
  options = options || {};

  const reportingMta = options.reportingMta || 'localhost';
  const from = options.from || ('postmaster@' + reportingMta);
  const to = options.to || '';
  const arrival = options.arrivalDate ? formatDate(options.arrivalDate) : formatDate(new Date());
  const originalMsg = options.originalMessage || Buffer.alloc(0);
  const returnContent = (options.returnContent || 'headers').toLowerCase();
  const recipients = Array.isArray(options.recipients) ? options.recipients : [];

  // Pick an overall action word for the subject line — 'failed' beats
  // 'delayed' beats 'delivered' since a bounce is the most urgent signal.
  let overall = 'delivered';
  for (let i = 0; i < recipients.length; i++) {
    let a = recipients[i].action;
    if (a === 'failed')  { overall = 'failed';  break; }
    if (a === 'delayed')   overall = 'delayed';
  }
  const subject = overall === 'failed' ? 'Undelivered Mail Returned to Sender'
                : overall === 'delayed' ? 'Delivery Status Notification (Delay)'
                : 'Delivery Status Notification';

  const boundary = '=_dsn_' + crypto.randomBytes(12).toString('hex');

  let out = '';
  // --- Outer headers ---
  out += 'From: ' + from + '\r\n';
  out += 'To: ' + to + '\r\n';
  out += 'Subject: ' + subject + '\r\n';
  out += 'Date: ' + formatDate(new Date()) + '\r\n';
  out += 'Message-ID: <dsn-' + crypto.randomBytes(8).toString('hex') + '@' + reportingMta + '>\r\n';
  out += 'MIME-Version: 1.0\r\n';
  out += 'Content-Type: multipart/report; report-type=delivery-status;\r\n';
  out += ' boundary="' + boundary + '"\r\n';
  out += 'Auto-Submitted: auto-replied\r\n';
  out += '\r\n';
  out += 'This is a MIME-formatted delivery status notification.\r\n';

  // --- Part 1: human-readable text/plain ---
  out += '\r\n--' + boundary + '\r\n';
  out += 'Content-Type: text/plain; charset=utf-8\r\n';
  out += 'Content-Transfer-Encoding: 8bit\r\n';
  out += '\r\n';
  out += humanReadable(recipients, overall, reportingMta);

  // --- Part 2: message/delivery-status ---
  out += '\r\n--' + boundary + '\r\n';
  out += 'Content-Type: message/delivery-status\r\n';
  out += '\r\n';
  out += deliveryStatusBlock(reportingMta, options.originalEnvelopeId, arrival, recipients);

  // --- Part 3: original message or headers only ---
  out += '\r\n--' + boundary + '\r\n';
  if (returnContent === 'full') {
    out += 'Content-Type: message/rfc822\r\n';
    out += '\r\n';
    // Concatenate as buffer — original message may be 8-bit / binary.
    let hdr = Buffer.from(out, 'utf-8');
    let footer = Buffer.from('\r\n--' + boundary + '--\r\n', 'utf-8');
    return Buffer.concat([hdr, originalMsg, footer]);
  } else {
    out += 'Content-Type: message/rfc822-headers\r\n';
    out += '\r\n';
    out += extractHeaders(originalMsg);
    out += '\r\n--' + boundary + '--\r\n';
    return Buffer.from(out, 'utf-8');
  }
}


function humanReadable(recipients, overall, mta) {
  let s = '';
  if (overall === 'failed') {
    s += 'This message was not delivered.\r\n\r\n';
  } else if (overall === 'delayed') {
    s += 'This message has been delayed.\r\n';
    s += 'The server will continue trying to deliver it.\r\n\r\n';
  } else {
    s += 'This is a delivery status notification.\r\n\r\n';
  }
  s += 'Reporting-MTA: ' + mta + '\r\n\r\n';

  for (let i = 0; i < recipients.length; i++) {
    let r = recipients[i];
    s += '-- Recipient: ' + r.finalRecipient + '\r\n';
    s += '   Action:   ' + (r.action || 'failed') + '\r\n';
    if (r.status)     s += '   Status:   ' + r.status + '\r\n';
    if (r.diagnostic) s += '   Reason:   ' + r.diagnostic + '\r\n';
    if (r.remoteMta)  s += '   Remote:   ' + r.remoteMta + '\r\n';
    if (r.willRetryUntil) s += '   Retry until: ' + formatDate(r.willRetryUntil) + '\r\n';
    s += '\r\n';
  }
  return s;
}

function deliveryStatusBlock(mta, envid, arrival, recipients) {
  let s = '';

  // Per-message fields (RFC 3464 §2.2)
  s += 'Reporting-MTA: dns; ' + mta + '\r\n';
  if (envid)   s += 'Original-Envelope-Id: ' + envid + '\r\n';
  if (arrival) s += 'Arrival-Date: ' + arrival + '\r\n';

  // Per-recipient fields (RFC 3464 §2.3) — one block per recipient, blank line
  // between. If recipients is empty, synthesize an empty block so part 2 is
  // not completely degenerate (clients accept either way but this is cleaner).
  if (recipients.length === 0) {
    s += '\r\nFinal-Recipient: rfc822; unknown\r\nAction: failed\r\nStatus: 5.0.0\r\n';
    return s;
  }
  for (let i = 0; i < recipients.length; i++) {
    let r = recipients[i];
    s += '\r\n';
    if (r.originalRecipient) {
      s += 'Original-Recipient: rfc822; ' + r.originalRecipient + '\r\n';
    }
    s += 'Final-Recipient: rfc822; ' + (r.finalRecipient || 'unknown') + '\r\n';
    s += 'Action: ' + (r.action || 'failed') + '\r\n';
    s += 'Status: ' + (r.status || '5.0.0') + '\r\n';
    if (r.remoteMta)   s += 'Remote-MTA: dns; ' + r.remoteMta + '\r\n';
    if (r.diagnostic)  s += 'Diagnostic-Code: smtp; ' + r.diagnostic + '\r\n';
    if (r.lastAttempt) s += 'Last-Attempt-Date: ' + formatDate(r.lastAttempt) + '\r\n';
    if (r.willRetryUntil) s += 'Will-Retry-Until: ' + formatDate(r.willRetryUntil) + '\r\n';
  }
  return s;
}

// Extract just the header block from a raw message (up to the first blank line).
// Used when the sender asked for RET=HDRS (returnContent === 'headers').
function extractHeaders(raw) {
  if (!raw || raw.length === 0) return '';
  let s = raw.toString('utf-8');
  let end = s.indexOf('\r\n\r\n');
  if (end < 0) return s;
  return s.substring(0, end + 2);
}

// RFC 5322 date string — Node's Date.toUTCString is close but uses "GMT"
// which 5322 recommends be replaced with "+0000" for strict compatibility.
function formatDate(d) {
  if (!(d instanceof Date)) d = new Date(d);
  // Date.toUTCString → "Wed, 22 Apr 2026 15:00:00 GMT"
  return d.toUTCString().replace(/\bGMT\b/, '+0000');
}


export { buildDsn };
