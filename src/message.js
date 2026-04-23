
import {
  toU8,
  u8ToStr,
  hasNonAscii
} from './utils.js';


// ============================================================
//  Text encoding utilities
// ============================================================

const TE = new TextEncoder();

// Pre-compiled patterns for encoded-word decoding (called per header)
const RE_ADJACENT_ENCODED = /\?=\s+=\?/g;
const RE_ENCODED_WORD = /=\?UTF-8\?([QB])\?(.+?)\?=/gi;
const RE_UNDERSCORE = /_/g;
const RE_CRLF_NORMALIZE = /\r?\n/g;
const RE_QP_SOFTBREAK = /=\r?\n/g;
const RE_WHITESPACE_COMPRESS = /\s+/g;

function ensureCRLF(str) {
  return String(str || '').replace(RE_CRLF_NORMALIZE, '\r\n');
}


// ============================================================
//  Base64
// ============================================================

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function base64Encode(u8) {
  let s = '';
  let i = 0;
  for (; i + 2 < u8.length; i += 3) {
    let n = (u8[i] << 16) | (u8[i + 1] << 8) | u8[i + 2];
    s += B64[(n >>> 18) & 63] + B64[(n >>> 12) & 63] + B64[(n >>> 6) & 63] + B64[n & 63];
  }
  if (i < u8.length) {
    let n = (u8[i] << 16) | ((i + 1 < u8.length ? u8[i + 1] : 0) << 8);
    s += B64[(n >>> 18) & 63] + B64[(n >>> 12) & 63] + (i + 1 < u8.length ? B64[(n >>> 6) & 63] : '=') + '=';
  }
  return s;
}

function base64Wrap76(b64) {
  let out = '';
  for (let i = 0; i < b64.length; i += 76) {
    out += b64.slice(i, i + 76) + '\r\n';
  }
  return out;
}

function base64Decode(str) {
  let s = String(str || '').replace(/\s+/g, '');
  let map = {};
  for (let i = 0; i < B64.length; i++) map[B64[i]] = i;
  let out = [];
  for (let j = 0; j < s.length; j += 4) {
    let c1 = map[s[j]], c2 = map[s[j + 1]];
    let c3 = s[j + 2] === '=' ? -1 : map[s[j + 2]];
    let c4 = s[j + 3] === '=' ? -1 : map[s[j + 3]];
    let n = (c1 << 18) | (c2 << 12) | ((c3 < 0 ? 0 : c3) << 6) | (c4 < 0 ? 0 : c4);
    out.push((n >>> 16) & 255);
    if (c3 >= 0) out.push((n >>> 8) & 255);
    if (c4 >= 0) out.push(n & 255);
  }
  return new Uint8Array(out);
}


// ============================================================
//  Quoted-Printable
// ============================================================

function qpEncode(u8) {
  let out = '';
  let lineLen = 0;
  for (let i = 0; i < u8.length; i++) {
    let b = u8[i];
    let isSafe = (b === 9) || (b === 32) || (b >= 33 && b <= 60) || (b >= 62 && b <= 126);
    let token;
    if (!isSafe || b === 61) {
      let hex = b.toString(16).toUpperCase();
      if (hex.length < 2) hex = '0' + hex;
      token = '=' + hex;
    } else {
      token = String.fromCharCode(b);
    }
    if (lineLen + token.length > 73) {
      out += '=\r\n';
      lineLen = 0;
    }
    out += token;
    lineLen += token.length;
    if (b === 10 && i > 0 && u8[i - 1] === 13) lineLen = 0;
  }
  return ensureCRLF(out);
}

function qpDecode(str) {
  let s = String(str || '').replace(RE_QP_SOFTBREAK, '');
  let out = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '=' && i + 2 < s.length) {
      let v = parseInt(s.substr(i + 1, 2), 16);
      if (!isNaN(v)) { out.push(v); i += 2; continue; }
    }
    out.push(s.charCodeAt(i));
  }
  return new Uint8Array(out);
}


// ============================================================
//  Encoded-word (RFC 2047) for headers
// ============================================================

function needsEncodedWord(s) {
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c < 32 || c > 126) return true;
  }
  return false;
}

function headerQEncode(utf8String) {
  let u8 = toU8(utf8String);
  let s = '';
  for (let i = 0; i < u8.length; i++) {
    let b = u8[i];
    if (b === 32) { s += '_'; continue; }
    let isAscii = (b >= 33 && b <= 60) || (b >= 62 && b <= 126);
    if (isAscii && b !== 61 && b !== 63 && b !== 95) {
      s += String.fromCharCode(b);
    } else {
      let h = b.toString(16).toUpperCase();
      if (h.length < 2) h = '0' + h;
      s += '=' + h;
    }
  }
  let prefix = '=?UTF-8?Q?';
  let suffix = '?=';
  let max = 75 - prefix.length;
  let out = '';
  let pos = 0;
  while (pos < s.length) {
    let chunk = s.slice(pos, pos + max);
    out += prefix + chunk + suffix;
    pos += max;
    if (pos < s.length) out += '\r\n ';
  }
  return out;
}

function headerBEncode(utf8String) {
  let u8 = toU8(utf8String);
  let prefix = '=?UTF-8?B?';
  let suffix = '?=';
  // Each encoded word should fit in ~75 chars total
  // prefix(10) + suffix(2) = 12, so ~63 chars for base64
  // 63 base64 chars = 47 bytes, but use 45 (multiple of 3) for clean base64
  let maxBytes = 45;
  let out = '';
  let pos = 0;

  while (pos < u8.length) {
    let end = Math.min(pos + maxBytes, u8.length);
    // Don't split in the middle of a multi-byte UTF-8 sequence
    while (end < u8.length && end > pos && (u8[end] & 0xC0) === 0x80) {
      end--;
    }
    if (end === pos) end = Math.min(pos + maxBytes, u8.length); // fallback

    let chunk = u8.slice(pos, end);
    let b64 = base64Encode(chunk);
    if (out.length > 0) out += '\r\n ';
    out += prefix + b64 + suffix;
    pos = end;
  }

  return out;
}

function encodeHeaderValue(value) {
  let v = String(value == null ? '' : value);
  if (!needsEncodedWord(v)) return v;
  let u8 = toU8(v);
  return (u8.length < 40) ? headerQEncode(v) : headerBEncode(v);
}

function decodeEncodedWords(v) {
  if (!v) return '';
  let result = v.replace(RE_ADJACENT_ENCODED, '?==?');
  result = result.replace(RE_ENCODED_WORD, function(_, mode, data) {
    if (mode.toUpperCase() === 'B') return u8ToStr(base64Decode(data));
    return u8ToStr(qpDecode(data.replace(RE_UNDERSCORE, ' ')));
  });
  return result;
}


// ============================================================
//  Header folding
// ============================================================

function foldHeader(name, value) {
  // If value already contains encoded-words with folding, don't re-fold
  if (value.indexOf('=?') >= 0) {
    return name + ': ' + value;
  }
  let line = name + ': ' + value;
  let out = '';
  while (line.length > 78) {
    let cut = line.lastIndexOf(' ', 78);
    if (cut <= name.length + 2) cut = 78;
    out += line.slice(0, cut) + '\r\n ';
    line = line.slice(cut + 1);
  }
  out += line;
  return out;
}


// ============================================================
//  Address helpers
// ============================================================

function normalizeAddress(a) {
  if (!a) return null;
  if (typeof a === 'string') {
    let m = /^(.*)<([^>]+)>$/.exec(a);
    if (m) return { name: String(m[1] || '').trim().replace(/(^"|"$)/g, ''), address: String(m[2] || '').trim() };
    return { name: '', address: String(a).trim() };
  }
  if (typeof a === 'object') {
    return { name: a.name ? String(a.name) : '', address: a.address ? String(a.address) : '' };
  }
  return null;
}

function formatAddressForHeader(obj) {
  let name = obj.name || '';
  let addr = obj.address || '';
  if (name) {
    let disp = encodeHeaderValue(name).replace(/\r\n\s*/g, ' ');
    return '"' + disp + '" <' + addr + '>';
  }
  return '<' + addr + '>';
}

function addressListToHeader(val) {
  if (val == null) return null;
  let arr = Array.isArray(val) ? val : [val];
  let out = [];
  for (let i = 0; i < arr.length; i++) {
    let o = normalizeAddress(arr[i]);
    if (!o || !o.address) continue;
    out.push(formatAddressForHeader(o));
  }
  return out.length ? out.join(', ') : null;
}


// ============================================================
//  MIME type detection
// ============================================================

const MIME_TYPES = {
  'txt': 'text/plain', 'html': 'text/html', 'htm': 'text/html', 'css': 'text/css',
  'csv': 'text/csv', 'xml': 'text/xml', 'json': 'application/json',
  'js': 'application/javascript', 'pdf': 'application/pdf',
  'zip': 'application/zip', 'gz': 'application/gzip', 'tar': 'application/x-tar',
  'doc': 'application/msword', 'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'xls': 'application/vnd.ms-excel', 'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'ppt': 'application/vnd.ms-powerpoint', 'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'gif': 'image/gif',
  'svg': 'image/svg+xml', 'webp': 'image/webp', 'ico': 'image/x-icon', 'bmp': 'image/bmp',
  'mp3': 'audio/mpeg', 'wav': 'audio/wav', 'ogg': 'audio/ogg',
  'mp4': 'video/mp4', 'webm': 'video/webm', 'avi': 'video/x-msvideo',
  'eml': 'message/rfc822', 'ics': 'text/calendar',
  '7z': 'application/x-7z-compressed', 'rar': 'application/x-rar-compressed'
};

function detectMimeType(filename) {
  if (!filename) return 'application/octet-stream';
  let ext = String(filename).split('.').pop().toLowerCase();
  return MIME_TYPES[ext] || 'application/octet-stream';
}


// ============================================================
//  Content-Type builder
// ============================================================

function buildContentType(type, subtype, params) {
  let s = type + '/' + subtype;
  if (params) {
    for (let k in params) {
      if (!params.hasOwnProperty(k)) continue;
      let v = String(params[k]);
      if (/[\s";]/.test(v)) s += '; ' + k + '="' + v.replace(/["\\]/g, '\\$&') + '"';
      else s += '; ' + k + '=' + v;
    }
  }
  return s;
}


// ============================================================
//  Transfer encoding selection
// ============================================================

function chooseTextTE(u8, allow8bit) {
  if (!hasNonAscii(u8)) return '7bit';
  return allow8bit ? '8bit' : 'quoted-printable';
}

function encodeTextPart(u8, allow8bit) {
  let te = chooseTextTE(u8, allow8bit);
  if (te === '7bit' || te === '8bit') return { transfer: te, data: ensureCRLF(u8ToStr(u8)) };
  return { transfer: 'quoted-printable', data: qpEncode(u8) };
}

function encodeAttachmentPart(u8) {
  return { transfer: 'base64', data: base64Wrap76(base64Encode(u8)) };
}


// ============================================================
//  Helpers
// ============================================================

function boundary() {
  return 'b-' + Math.floor(Math.random() * 1e9).toString(36) + '-' + Date.now().toString(36);
}

function nowRfc2822Date() {
  let d = new Date();
  let wd = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][d.getUTCDay()];
  let mo = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][d.getUTCMonth()];
  let dd = String(d.getUTCDate()).padStart(2, '0');
  let hh = String(d.getUTCHours()).padStart(2, '0');
  let mm = String(d.getUTCMinutes()).padStart(2, '0');
  let ss = String(d.getUTCSeconds()).padStart(2, '0');
  return wd + ', ' + dd + ' ' + mo + ' ' + d.getUTCFullYear() + ' ' + hh + ':' + mm + ':' + ss + ' +0000';
}

function genMessageId(domainHint) {
  let r = Math.floor(Math.random() * 9007199254740991);
  let t = Date.now();
  let d = (domainHint && /[A-Za-z0-9.-]/.test(domainHint)) ? domainHint : 'localhost';
  return '<' + t.toString(36) + '.' + r.toString(36) + '@' + d + '>';
}

function buildMultipart(b, parts) {
  let out = '';
  for (let i = 0; i < parts.length; i++) {
    out += '--' + b + '\r\n';
    let hs = parts[i].headers || [];
    for (let h = 0; h < hs.length; h++) out += hs[h] + '\r\n';
    out += '\r\n';
    out += parts[i].body || '';
    if (out.slice(-2) !== '\r\n') out += '\r\n';
  }
  out += '--' + b + '--\r\n';
  return out;
}


// ============================================================
//  composeMessage
// ============================================================

function composeMessage(options, caps) {
  options = options || {};
  caps = caps || {};

  let hdr = [];

  // Date
  hdr.push(foldHeader('Date', options.date ? String(options.date) : nowRfc2822Date()));

  // Message-ID
  let fromAddr = '';
  if (options.from) {
    let n = normalizeAddress(options.from);
    if (n) fromAddr = n.address || '';
  }
  let msgId = options.messageId || genMessageId(fromAddr.split('@')[1] || 'localhost');
  hdr.push(foldHeader('Message-ID', msgId));

  // MIME-Version
  hdr.push(foldHeader('MIME-Version', '1.0'));

  // From / Sender / Reply-To
  let fromH = addressListToHeader(options.from);
  if (fromH) hdr.push(foldHeader('From', fromH));
  let senderH = addressListToHeader(options.sender);
  if (senderH) hdr.push(foldHeader('Sender', senderH));
  let replyH = addressListToHeader(options.replyTo);
  if (replyH) hdr.push(foldHeader('Reply-To', replyH));

  // To / Cc
  let toH = addressListToHeader(options.to);
  if (toH) hdr.push(foldHeader('To', toH));
  let ccH = addressListToHeader(options.cc);
  if (ccH) hdr.push(foldHeader('Cc', ccH));

  // Subject
  if (options.subject != null) {
    hdr.push(foldHeader('Subject', encodeHeaderValue(String(options.subject))));
  }

  // Priority
  if (options.priority === 'high') {
    hdr.push(foldHeader('X-Priority', '1 (Highest)'));
    hdr.push(foldHeader('Importance', 'High'));
  } else if (options.priority === 'low') {
    hdr.push(foldHeader('X-Priority', '5 (Lowest)'));
    hdr.push(foldHeader('Importance', 'Low'));
  }

  // Custom headers
  if (options.headers) {
    if (Array.isArray(options.headers)) {
      for (let i = 0; i < options.headers.length; i++) {
        let kv = options.headers[i];
        if (!kv || !kv.key) continue;
        hdr.push(foldHeader(String(kv.key), String(kv.value == null ? '' : kv.value)));
      }
    } else {
      for (let k in options.headers) {
        if (!options.headers.hasOwnProperty(k)) continue;
        hdr.push(foldHeader(String(k), String(options.headers[k])));
      }
    }
  }

  // Body
  let textU8 = options.text != null ? toU8(ensureCRLF(String(options.text))) : null;
  let htmlU8 = options.html != null ? toU8(ensureCRLF(String(options.html))) : null;
  let atts = Array.isArray(options.attachments) ? options.attachments.slice() : [];

  let allow8bit = !!caps.eightBitMime;

  let rootContentType = null;
  let rootBody = '';

  // Simple text-only message
  if (!htmlU8 && !atts.length && textU8) {
    let enc = encodeTextPart(textU8, allow8bit);
    hdr.push(foldHeader('Content-Type', buildContentType('text', 'plain', { charset: 'UTF-8' })));
    hdr.push(foldHeader('Content-Transfer-Encoding', enc.transfer));
    rootBody = enc.data;
  } else {
    // Multipart message
    let altParts = [];

    if (textU8) {
      let e = encodeTextPart(textU8, allow8bit);
      altParts.push({
        headers: [
          foldHeader('Content-Type', buildContentType('text', 'plain', { charset: 'UTF-8' })),
          foldHeader('Content-Transfer-Encoding', e.transfer)
        ],
        body: e.data
      });
    }

    if (htmlU8) {
      let e = encodeTextPart(htmlU8, allow8bit);
      altParts.push({
        headers: [
          foldHeader('Content-Type', buildContentType('text', 'html', { charset: 'UTF-8' })),
          foldHeader('Content-Transfer-Encoding', e.transfer)
        ],
        body: e.data
      });
    }

    // Separate inline (CID) from regular attachments
    let inlineAtts = [];
    let regularAtts = [];
    for (let i = 0; i < atts.length; i++) {
      let a = atts[i];
      if (!a || !a.content) continue;
      if (a.cid) inlineAtts.push(a);
      else regularAtts.push(a);
    }

    // Build attachment parts
    function buildAttPart(att) {
      let u8 = (att.content instanceof Uint8Array) ? att.content : toU8(att.content);
      let enc = encodeAttachmentPart(u8);
      let ct = att.contentType || detectMimeType(att.filename);
      let disp = att.cid ? 'inline' : 'attachment';
      let dispVal = disp + '; filename="' + String(att.filename || 'file') + '"';
      let headers = [
        foldHeader('Content-Type', ct + '; name="' + String(att.filename || 'file') + '"'),
        foldHeader('Content-Transfer-Encoding', enc.transfer),
        foldHeader('Content-Disposition', dispVal)
      ];
      if (att.cid) {
        headers.push(foldHeader('Content-ID', '<' + String(att.cid) + '>'));
      }
      return { headers: headers, body: enc.data };
    }

    let hasInline = inlineAtts.length > 0;

    if (altParts.length && hasInline) {
      // text/html + inline images → alternative with related
      let relBoundary = boundary();
      let htmlPart = altParts.find(function(p) { return p.headers[0].indexOf('text/html') >= 0; });
      let relatedParts = [];
      if (htmlPart) relatedParts.push(htmlPart);
      for (let i = 0; i < inlineAtts.length; i++) relatedParts.push(buildAttPart(inlineAtts[i]));
      let relatedBody = buildMultipart(relBoundary, relatedParts);

      let altOuter = [];
      let textPart = altParts.find(function(p) { return p.headers[0].indexOf('text/plain') >= 0; });
      if (textPart) altOuter.push(textPart);
      altOuter.push({
        headers: [foldHeader('Content-Type', buildContentType('multipart', 'related', { boundary: relBoundary }))],
        body: relatedBody
      });

      let topBoundary = boundary();
      let altBody = buildMultipart(topBoundary, altOuter);

      if (regularAtts.length) {
        let mixBoundary = boundary();
        let mixParts = [
          { headers: [foldHeader('Content-Type', buildContentType('multipart', 'alternative', { boundary: topBoundary }))], body: altBody }
        ];
        for (let i = 0; i < regularAtts.length; i++) mixParts.push(buildAttPart(regularAtts[i]));
        rootContentType = buildContentType('multipart', 'mixed', { boundary: mixBoundary });
        rootBody = buildMultipart(mixBoundary, mixParts);
      } else {
        rootContentType = buildContentType('multipart', 'alternative', { boundary: topBoundary });
        rootBody = altBody;
      }
    } else if (altParts.length > 1) {
      // text + html (no inline images)
      let bAlt = boundary();
      rootContentType = buildContentType('multipart', 'alternative', { boundary: bAlt });
      rootBody = buildMultipart(bAlt, altParts);

      if (regularAtts.length) {
        let mixB = boundary();
        let mixParts = [
          { headers: [foldHeader('Content-Type', rootContentType)], body: rootBody }
        ];
        for (let i = 0; i < regularAtts.length; i++) mixParts.push(buildAttPart(regularAtts[i]));
        rootContentType = buildContentType('multipart', 'mixed', { boundary: mixB });
        rootBody = buildMultipart(mixB, mixParts);
      }
    } else if (regularAtts.length || altParts.length) {
      // Only attachments, or single text/html + attachments
      let mixB = boundary();
      let mixParts = [];
      for (let i = 0; i < altParts.length; i++) mixParts.push(altParts[i]);
      for (let i = 0; i < regularAtts.length; i++) mixParts.push(buildAttPart(regularAtts[i]));
      rootContentType = buildContentType('multipart', 'mixed', { boundary: mixB });
      rootBody = buildMultipart(mixB, mixParts);
    }

    if (rootContentType) {
      hdr.push(foldHeader('Content-Type', rootContentType));
    }
  }

  let headerStr = hdr.join('\r\n');
  let full = headerStr + '\r\n\r\n' + rootBody;
  let rawU8 = toU8(full);

  // SMTP profile
  let bodyU8 = toU8(rootBody);
  let smtpUtf8Needed = false;
  let addrFields = [options.from, options.sender, options.to, options.cc, options.bcc];
  for (let i = 0; i < addrFields.length; i++) {
    let val = addrFields[i];
    if (!val) continue;
    let arr = Array.isArray(val) ? val : [val];
    for (let j = 0; j < arr.length; j++) {
      let n = normalizeAddress(arr[j]);
      if (n && n.address && hasNonAscii(toU8(n.address))) { smtpUtf8Needed = true; break; }
    }
    if (smtpUtf8Needed) break;
  }

  return {
    raw: rawU8,
    messageId: msgId,
    profile: {
      smtpUtf8Needed: smtpUtf8Needed,
      bodyIs8bit: hasNonAscii(bodyU8) && allow8bit,
      size: rawU8.length
    }
  };
}


// ============================================================
//  parseMessage
// ============================================================

function parseMessage(rawU8) {
  if (typeof rawU8 === 'string') rawU8 = toU8(rawU8);
  let hb = splitHeadersBody(rawU8);
  let headers = parseHeaders(hb.head);

  let subjRaw = headerLookup(headers, 'Subject');
  let subject = decodeEncodedWords(subjRaw || '') || subjRaw || '';
  let from = headerLookup(headers, 'From') || '';
  let to = headerLookup(headers, 'To') || '';
  let cc = headerLookup(headers, 'Cc') || '';
  let date = headerLookup(headers, 'Date') || '';
  let messageId = headerLookup(headers, 'Message-ID') || '';

  let ct = parseContentType(headerLookup(headers, 'Content-Type'));
  let te = parseTransfer(headerLookup(headers, 'Content-Transfer-Encoding'));

  let text = null, html = null, attachments = [];

  function handleSingle(ctObj, teStr, bodyStr, partHeaders) {
    let dataU8 = decodeBodyByTE(bodyStr, teStr);
    let mime = (ctObj.type + '/' + ctObj.subtype).toLowerCase();

    if (mime === 'text/plain' && text === null) {
      text = u8ToStr(dataU8).replace(/\r\n$/, '');
      return;
    }
    if (mime === 'text/html' && html === null) {
      html = u8ToStr(dataU8).replace(/\r\n$/, '');
      return;
    }

    let cd = headerLookup(partHeaders || [], 'Content-Disposition') || '';
    let isAttach = /attachment/i.test(cd) || /inline/i.test(cd) || (mime !== 'text/plain' && mime !== 'text/html');

    if (isAttach) {
      let fn = /filename\*?="?([^";]+)"?/i.exec(cd);
      if (!fn) fn = /name="?([^";]+)"?/i.exec(headerLookup(partHeaders || [], 'Content-Type') || '');
      let filename = fn ? fn[1] : 'file';
      attachments.push({
        filename: filename,
        contentType: mime,
        size: dataU8.length,
        content: dataU8,
        cid: (headerLookup(partHeaders || [], 'Content-ID') || '').replace(/[<>]/g, '') || null,
        related: /inline/i.test(cd)
      });
    }
  }

  if (ct.type === 'multipart') {
    let parts = splitMultipart(hb.body, ct.params['boundary'] || '');
    for (let i = 0; i < parts.length; i++) {
      let pCT = parseContentType(headerLookup(parts[i].headers, 'Content-Type'));
      let pTE = parseTransfer(headerLookup(parts[i].headers, 'Content-Transfer-Encoding'));
      if (pCT.type === 'multipart') {
        let subparts = splitMultipart(parts[i].body, pCT.params['boundary'] || '');
        for (let j = 0; j < subparts.length; j++) {
          let sCT = parseContentType(headerLookup(subparts[j].headers, 'Content-Type'));
          let sTE = parseTransfer(headerLookup(subparts[j].headers, 'Content-Transfer-Encoding'));
          handleSingle(sCT, sTE, subparts[j].body, subparts[j].headers);
        }
      } else {
        handleSingle(pCT, pTE, parts[i].body, parts[i].headers);
      }
    }
  } else {
    handleSingle(ct, te, hb.body, headers);
  }

  return {
    headers: headers,
    subject: subject,
    from: from,
    to: to,
    cc: cc,
    date: date,
    messageId: messageId,
    text: text,
    html: html,
    attachments: attachments
  };
}


// ============================================================
//  Parse helpers
// ============================================================

function splitHeadersBody(u8) {
  let s = u8ToStr(u8);
  let idx = s.indexOf('\r\n\r\n');
  if (idx < 0) return { head: s, body: '' };
  return { head: s.slice(0, idx), body: s.slice(idx + 4) };
}

function parseHeaders(headStr) {
  let lines = headStr.split(/\r\n/);
  let out = [];
  let cur = null;
  for (let i = 0; i < lines.length; i++) {
    let L = lines[i];
    if (/^\s/.test(L)) {
      if (cur) cur.value += '\r\n' + L;
      continue;
    }
    let m = /^([^:]+):\s*(.*)$/.exec(L);
    if (m) {
      if (cur) out.push(cur);
      cur = { name: m[1], value: m[2] };
    } else if (cur) {
      cur.value += '\r\n' + L;
    }
  }
  if (cur) out.push(cur);
  // Unfold
  for (let j = 0; j < out.length; j++) {
    out[j].value = out[j].value.replace(/\r\n[ \t]+/g, ' ');
  }
  return out;
}

function headerLookup(headers, name) {
  let low = String(name).toLowerCase();
  for (let i = 0; i < headers.length; i++) {
    if (String(headers[i].name || '').toLowerCase() === low) return headers[i].value;
  }
  return null;
}

function parseContentType(v) {
  if (!v) return { type: 'text', subtype: 'plain', params: {} };
  let m = /^\s*([^\/\s;]+)\/([^;\s]+)\s*(;.*)?$/.exec(v);
  if (!m) return { type: 'text', subtype: 'plain', params: {} };
  let params = {};
  if (m[3]) {
    // Match both quoted and unquoted parameter values
    let rx = /;\s*([^\s=;]+)\s*=\s*(?:"([^"]*)"|([^;\s]*))/g;
    let t;
    while ((t = rx.exec(m[3]))) {
      params[t[1].toLowerCase()] = t[2] !== undefined ? t[2] : t[3];
    }
  }
  return { type: m[1].toLowerCase(), subtype: m[2].toLowerCase(), params: params };
}

function parseTransfer(v) {
  if (!v) return '7bit';
  return String(v).trim().toLowerCase();
}

function splitMultipart(bodyStr, boundaryStr) {
  let b = '--' + boundaryStr;
  let end = '--' + boundaryStr + '--';
  let lines = bodyStr.split(/\r\n/);
  let parts = [];
  let cur = null;
  for (let i = 0; i < lines.length; i++) {
    let L = lines[i];
    if (L === b) {
      if (cur) parts.push(cur);
      cur = { raw: '' };
      continue;
    }
    if (L === end) {
      if (cur) { parts.push(cur); cur = null; }
      break;
    }
    if (cur) cur.raw += L + '\r\n';
  }
  if (cur) parts.push(cur);
  for (let j = 0; j < parts.length; j++) {
    let hnb = splitHeadersBody(toU8(parts[j].raw));
    parts[j].headers = parseHeaders(hnb.head);
    parts[j].body = hnb.body;
  }
  return parts;
}

function decodeBodyByTE(bodyStr, te) {
  te = te || '7bit';
  if (te === 'base64') return base64Decode(bodyStr);
  if (te === 'quoted-printable') return qpDecode(bodyStr);
  return toU8(bodyStr);
}


// ============================================================
//  Tree-based parser (byte-accurate, offset-preserving)
//
//  Designed for IMAP BODY[...] and BODYSTRUCTURE semantics. Unlike parseMessage
//  which returns a flat convenience object, parseMessageTree returns a recursive
//  node tree with exact byte offsets into the original buffer — enabling O(1)
//  extraction of arbitrary MIME sub-parts, header subsets, and partial fetches.
//
//  Future direction: parseMessage will be refactored on top of parseMessageTree
//  once the consumer APIs are unified.
// ============================================================

// CRLF bytes
const CR = 0x0D, LF = 0x0A, SP = 0x20, HT = 0x09, DASH = 0x2D;

// Find the position just after the "\r\n\r\n" that separates headers from body.
// Returns that position, or `end` if no blank line was found (malformed — whole range is headers).
function findHeadersBodySplit(buf, start, end) {
  for (let i = start; i <= end - 4; i++) {
    if (buf[i] === CR && buf[i + 1] === LF && buf[i + 2] === CR && buf[i + 3] === LF) {
      return i + 4;
    }
  }
  // Tolerate bare-LF (some malformed messages): "\n\n"
  for (let i = start; i <= end - 2; i++) {
    if (buf[i] === LF && buf[i + 1] === LF) return i + 2;
  }
  return end;
}

// Parse headers from a byte range, preserving byte offsets for each header line.
// Returns array of { name, value, rawStart, rawEnd } where rawStart..rawEnd covers
// the full header including any folded continuation lines and the trailing CRLF.
// `value` is the unfolded, trimmed string value; `name` is the exact original case.
function parseHeadersWithOffsets(buf, start, end) {
  let out = [];
  let i = start;
  while (i < end) {
    // Skip blank line that terminates headers (shouldn't happen if caller passed [start, headerEnd))
    if (buf[i] === CR && i + 1 < end && buf[i + 1] === LF) { i += 2; break; }
    if (buf[i] === LF) { i += 1; break; }

    let lineStart = i;
    // Find end of this logical header (including continuation lines that begin with SP/HTAB)
    let lineEnd = i;
    while (lineEnd < end) {
      // Find the next CRLF (or bare LF)
      let eol = findEol(buf, lineEnd, end);
      if (eol < 0) { lineEnd = end; break; }
      let afterEol = eol + (buf[eol] === CR && buf[eol + 1] === LF ? 2 : 1);
      // Continuation?
      if (afterEol < end && (buf[afterEol] === SP || buf[afterEol] === HT)) {
        lineEnd = afterEol;
        continue;
      }
      lineEnd = afterEol;
      break;
    }

    // Parse "Name: value" from lineStart..lineEnd. Trim trailing CRLF for value computation.
    let logical = buf.subarray(lineStart, lineEnd).toString('utf-8');
    let colon = logical.indexOf(':');
    if (colon > 0) {
      let name = logical.slice(0, colon).trim();
      // Unfold: replace CRLF+WSP with single space
      let value = logical.slice(colon + 1).replace(/\r?\n[ \t]+/g, ' ').replace(/\r?\n$/, '').trim();
      out.push({ name: name, value: value, rawStart: lineStart, rawEnd: lineEnd });
    }
    // else: malformed line — skip (don't add)

    i = lineEnd;
  }
  return out;
}

function findEol(buf, start, end) {
  for (let i = start; i < end; i++) {
    if (buf[i] === CR || buf[i] === LF) return i;
  }
  return -1;
}

// Split a multipart body into child part ranges by the given boundary string.
// Returns array of { start, end } — byte offsets of each part's content (headers + body).
// Preamble (before first boundary) and epilogue (after close boundary) are not returned.
//
// RFC 2046: boundaries are "[CRLF]--<boundary>[WSP]CRLF" delimiters. Close = "[CRLF]--<boundary>--".
// The CRLF immediately before a boundary is considered part of the boundary delimiter, not the
// part's body — that's why parts can have zero-CRLF-terminated body and still be valid.
function splitMultipartOffsets(buf, bodyStart, bodyEnd, boundary) {
  if (!boundary) return [];
  let dashBoundary = Buffer.from('--' + boundary, 'utf-8');
  let crlfDashBoundary = Buffer.from('\r\n--' + boundary, 'utf-8');

  // Collect boundary positions. Each entry records the byte offset of "--" start.
  let markers = [];

  // Case 1: boundary at very start of body (no preceding CRLF — rare but valid)
  if (bodyEnd - bodyStart >= dashBoundary.length &&
      buf.subarray(bodyStart, bodyStart + dashBoundary.length).equals(dashBoundary)) {
    markers.push({ pos: bodyStart, preCRLFBytes: 0 });
  }

  // Case 2: every "\r\n--boundary" within the body
  let search = bodyStart;
  while (true) {
    let idx = buf.indexOf(crlfDashBoundary, search);
    if (idx < 0 || idx + crlfDashBoundary.length > bodyEnd) break;
    markers.push({ pos: idx + 2, preCRLFBytes: 2 });
    search = idx + crlfDashBoundary.length;
  }

  markers.sort(function(a, b) { return a.pos - b.pos; });

  let parts = [];
  let currentStart = null;
  for (let j = 0; j < markers.length; j++) {
    let m = markers[j];
    let afterDash = m.pos + dashBoundary.length;
    let isClose = afterDash + 1 < bodyEnd && buf[afterDash] === DASH && buf[afterDash + 1] === DASH;

    // Skip past optional transport-padding (SP/HTAB) and CRLF after the boundary
    let scanner = isClose ? afterDash + 2 : afterDash;
    while (scanner < bodyEnd && (buf[scanner] === SP || buf[scanner] === HT)) scanner++;
    let afterDelim;
    if (scanner + 1 < bodyEnd && buf[scanner] === CR && buf[scanner + 1] === LF) {
      afterDelim = scanner + 2;
    } else if (scanner < bodyEnd && buf[scanner] === LF) {
      afterDelim = scanner + 1;
    } else if (isClose) {
      afterDelim = scanner;  // close boundary at buffer end is OK
    } else {
      continue;  // malformed — skip this marker
    }

    // Close any previous part
    if (currentStart !== null) {
      // Part ends where this boundary's preceding CRLF starts
      let partEnd = m.pos - m.preCRLFBytes;
      parts.push({ start: currentStart, end: partEnd });
    }

    if (isClose) break;
    currentStart = afterDelim;
  }

  return parts;
}

// Count CRLF-terminated lines in a byte range (for BODYSTRUCTURE text/* line counts).
function countBodyLines(buf, start, end) {
  let count = 0;
  for (let i = start; i < end; i++) {
    if (buf[i] === LF) count++;
  }
  return count;
}

// Look up a single header value by (case-insensitive) name. Returns the first match, or null.
function findHeader(headers, name) {
  let low = name.toLowerCase();
  for (let i = 0; i < headers.length; i++) {
    if (headers[i].name.toLowerCase() === low) return headers[i].value;
  }
  return null;
}

// Parse a MIME node recursively — the main entry point.
// `buf` may be a Buffer, Uint8Array, or string (string gets UTF-8 encoded).
function parseMessageTree(buf) {
  if (typeof buf === 'string') buf = Buffer.from(buf, 'utf-8');
  else if (buf instanceof Uint8Array && !Buffer.isBuffer(buf)) buf = Buffer.from(buf);
  return parseMimeNode(buf, 0, buf.length);
}

// Parse a single MIME node within the given byte range and recurse for multipart children.
function parseMimeNode(buf, start, end) {
  let headerEnd = findHeadersBodySplit(buf, start, end);
  let bodyStart = headerEnd;
  let bodyEnd = end;

  // Parse headers — note: the blank line is NOT included in our header range
  let headers = parseHeadersWithOffsets(buf, start, headerEnd);

  // Extract commonly-needed header values (pre-computed so BODYSTRUCTURE builder
  // doesn't have to walk headers repeatedly)
  let ctRaw = findHeader(headers, 'Content-Type');
  let ct = parseContentType(ctRaw);
  let cte = findHeader(headers, 'Content-Transfer-Encoding');
  let cd = findHeader(headers, 'Content-Disposition');
  let cdParsed = parseContentDisposition(cd);

  let parts = null;

  if (ct.type === 'multipart' && ct.params.boundary) {
    // Recurse for each part
    let childRanges = splitMultipartOffsets(buf, bodyStart, bodyEnd, ct.params.boundary);
    parts = [];
    for (let i = 0; i < childRanges.length; i++) {
      parts.push(parseMimeNode(buf, childRanges[i].start, childRanges[i].end));
    }
  } else if (ct.type === 'message' && ct.subtype === 'rfc822') {
    // An embedded RFC822 message: the body IS another complete message.
    // Per RFC 3501 §7.4.2, BODYSTRUCTURE treats this as a single encapsulated child.
    parts = [parseMimeNode(buf, bodyStart, bodyEnd)];
  }

  return {
    // Byte offsets (all absolute into the root buffer)
    start:       start,
    end:         end,
    headerStart: start,
    headerEnd:   headerEnd,
    bodyStart:   bodyStart,
    bodyEnd:     bodyEnd,

    // Parsed header summary (pre-computed for speed)
    contentType:              ct.type + '/' + ct.subtype,
    contentTypeParams:        ct.params,
    contentTransferEncoding:  cte ? cte.trim().toLowerCase() : null,
    contentDisposition:       cdParsed.type,
    contentDispositionParams: cdParsed.params,
    contentId:                findHeader(headers, 'Content-ID'),
    contentDescription:       findHeader(headers, 'Content-Description'),
    contentLanguage:          findHeader(headers, 'Content-Language'),
    contentLocation:          findHeader(headers, 'Content-Location'),
    contentMd5:               findHeader(headers, 'Content-MD5'),

    // Full header list (preserves order, duplicates, and byte offsets)
    headers: headers,

    // Body line count (for BODYSTRUCTURE of text/* and message/* parts)
    bodyLines: countBodyLines(buf, bodyStart, bodyEnd),

    // Recursive child parts (null for leaf/single-body parts)
    parts: parts
  };
}

function parseContentDisposition(v) {
  if (!v) return { type: null, params: {} };
  let s = String(v);
  let semi = s.indexOf(';');
  let type = (semi < 0 ? s : s.slice(0, semi)).trim().toLowerCase();
  let params = {};
  if (semi >= 0) {
    let rx = /;\s*([^\s=;]+)\s*=\s*(?:"([^"]*)"|([^;\s]*))/g;
    let m;
    while ((m = rx.exec(s))) {
      params[m[1].toLowerCase()] = m[2] !== undefined ? m[2] : m[3];
    }
  }
  return { type: type || null, params: params };
}


// ============================================================
//  Address-list parser (RFC 5322 pragmatic subset)
//
//  Handles: bare addresses, name-addr ("Alice" <a@x>), display name in various
//  forms (quoted, atoms, encoded-words left raw), comments in parens (skipped),
//  groups ("My Group": a@x, b@y;).
//
//  Returns a flat array where each element is either:
//    { name, mailbox, host }                 — a normal address
//    { group: 'name', members: [addr,...] }  — a group construct
//
//  Strings are returned raw (not decoded). Callers that need decoded display
//  names should apply decodeEncodedWords themselves.
// ============================================================

function parseAddressList(str) {
  if (!str) return [];
  let st = { s: String(str), i: 0 };
  let out = [];
  apSkipCfws(st);
  while (st.i < st.s.length) {
    if (st.s.charAt(st.i) === ',') { st.i++; apSkipCfws(st); continue; }
    let a = apReadAddressOrGroup(st);
    if (a) out.push(a);
    apSkipCfws(st);
  }
  return out;
}

// Skip whitespace and RFC 5322 comments (which may be nested).
function apSkipCfws(st) {
  while (st.i < st.s.length) {
    let c = st.s.charAt(st.i);
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') { st.i++; continue; }
    if (c === '(') { apSkipComment(st); continue; }
    break;
  }
}

function apSkipComment(st) {
  let depth = 1;
  st.i++;  // consume '('
  while (st.i < st.s.length && depth > 0) {
    let c = st.s.charAt(st.i);
    if (c === '\\' && st.i + 1 < st.s.length) { st.i += 2; continue; }
    if (c === '(') depth++;
    else if (c === ')') depth--;
    st.i++;
  }
}

// Read a quoted-string. Current char is assumed to be '"'.
function apReadQuoted(st) {
  st.i++;  // consume opening "
  let out = '';
  while (st.i < st.s.length) {
    let c = st.s.charAt(st.i);
    if (c === '"') { st.i++; return out; }
    if (c === '\\' && st.i + 1 < st.s.length) { out += st.s.charAt(st.i + 1); st.i += 2; continue; }
    out += c;
    st.i++;
  }
  return out;  // unterminated — return what we read
}

// Read an atom — any run of non-special characters.
function apReadAtom(st) {
  let out = '';
  while (st.i < st.s.length) {
    let c = st.s.charAt(st.i);
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') break;
    if ('"<>()@,:;'.indexOf(c) >= 0) break;
    out += c;
    st.i++;
  }
  return out;
}

// Read either a single address or a group, depending on context.
function apReadAddressOrGroup(st) {
  // Collect name words until we see '<', '@' following an atom, ':', ',', ';', or end
  let nameParts = [];
  let localPart = null;
  let domain = null;
  let hasAngle = false;

  while (st.i < st.s.length) {
    apSkipCfws(st);
    if (st.i >= st.s.length) break;
    let c = st.s.charAt(st.i);

    if (c === ',' || c === ';') break;

    if (c === ':') {
      // Group start — everything collected so far is the group name
      st.i++;
      let gname = nameParts.join(' ').trim();
      let members = [];
      apSkipCfws(st);
      while (st.i < st.s.length && st.s.charAt(st.i) !== ';') {
        if (st.s.charAt(st.i) === ',') { st.i++; apSkipCfws(st); continue; }
        let m = apReadAddressOrGroup(st);
        if (m) members.push(m);
        apSkipCfws(st);
      }
      if (st.i < st.s.length && st.s.charAt(st.i) === ';') st.i++;
      return { group: gname || null, members: members };
    }

    if (c === '"') {
      nameParts.push(apReadQuoted(st));
      continue;
    }

    if (c === '<') {
      // Angle-bracketed address — overrides any previous local@host
      hasAngle = true;
      st.i++;  // consume <
      apSkipCfws(st);
      let lp = apReadAtom(st);
      if (st.s.charAt(st.i) === '"') lp = apReadQuoted(st);
      apSkipCfws(st);
      if (st.s.charAt(st.i) === '@') {
        st.i++;
        apSkipCfws(st);
        let d = apReadAtom(st);
        localPart = lp;
        domain = d;
      } else {
        // Bare local part in brackets (unusual but legal)
        localPart = lp;
      }
      apSkipCfws(st);
      if (st.s.charAt(st.i) === '>') st.i++;
      continue;
    }

    // Atom — could be part of display name, or the local part of an email
    let atom = apReadAtom(st);
    if (!atom) { st.i++; continue; }  // unexpected — advance to avoid infinite loop

    // Lookahead: if next non-ws char is '@', this atom is the local part
    let save = st.i;
    apSkipCfws(st);
    if (st.s.charAt(st.i) === '@' && !hasAngle) {
      st.i++;
      apSkipCfws(st);
      let d = apReadAtom(st);
      localPart = atom;
      domain = d;
      continue;
    }
    // Otherwise, it's part of the display name
    st.i = save;
    nameParts.push(atom);
  }

  let name = nameParts.join(' ').trim();
  if (!localPart && !domain && !name) return null;
  return {
    name: name || null,
    mailbox: localPart || null,
    host: domain || null
  };
}


// ============================================================
//  Exports
// ============================================================

export {
  composeMessage,
  parseMessage,

  // Tree-based parser (byte-accurate, for IMAP BODY[...] / BODYSTRUCTURE)
  parseMessageTree,
  findHeadersBodySplit,
  parseHeadersWithOffsets,
  splitMultipartOffsets,
  countBodyLines,
  parseAddressList,

  // Encoding utilities
  base64Encode,
  base64Decode,
  base64Wrap76,
  qpEncode,
  qpDecode,
  encodeHeaderValue,
  decodeEncodedWords,
  foldHeader,

  // Address helpers
  normalizeAddress,
  addressListToHeader,

  // MIME helpers
  detectMimeType,
  buildContentType,
  boundary,
  genMessageId,
  nowRfc2822Date
};
