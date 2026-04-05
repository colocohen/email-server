
import {
  toU8,
  u8ToStr,
  concatU8,
  asciiEqCI,
  isDigit,
  indexOfCRLF
} from './utils.js';


// ============================================================
//  Constants
// ============================================================

const SMTP_REPLY_CLASS = {
  2: 'success',
  3: 'intermediate',
  4: 'tempfail',
  5: 'permfail'
};

const SMTP_REPLY_MEANING = {
  211: 'SystemStatus',
  214: 'Help',
  220: 'ServiceReady',
  221: 'ServiceClosing',
  235: 'AuthSuccessful',
  250: 'Ok',
  251: 'UserNotLocalWillForward',
  252: 'CannotVrfyAccepts',
  334: 'AuthContinue',
  354: 'StartMailInput',
  420: 'Timeout',
  421: 'ServiceNotAvailable',
  450: 'MailboxUnavailable',
  451: 'LocalError',
  452: 'InsufficientStorage',
  454: 'TempAuthFailure',
  500: 'SyntaxError',
  501: 'SyntaxParamError',
  502: 'NotImplemented',
  503: 'BadSequence',
  504: 'ParamNotImplemented',
  521: 'DoesNotAcceptMail',
  530: 'AuthRequired',
  535: 'AuthInvalid',
  550: 'MailboxUnavailable',
  551: 'UserNotLocal',
  552: 'ExceededStorage',
  553: 'MailboxNameNotAllowed',
  554: 'TransactionFailed',
  555: 'ParamNotRecognized'
};

// RFC 3463 Enhanced Status Codes
const ENHANCED_STATUS = {
  '2.0.0': 'Ok',
  '2.1.0': 'OriginatorValid',
  '2.1.5': 'DestinationValid',
  '2.6.0': 'MessageAccepted',
  '2.7.0': 'AuthSuccessful',
  '4.2.1': 'MailboxBusy',
  '4.2.2': 'MailboxFull',
  '4.3.0': 'SystemError',
  '4.3.1': 'SystemFull',
  '4.4.0': 'NetworkError',
  '4.4.2': 'ConnectionTimeout',
  '4.7.0': 'TempAuthFailure',
  '5.1.1': 'MailboxNotFound',
  '5.1.3': 'BadDestinationSyntax',
  '5.1.6': 'DestinationChanged',
  '5.1.10': 'RecipientSyntaxError',
  '5.2.2': 'MailboxFull',
  '5.2.3': 'MessageTooLarge',
  '5.3.2': 'SystemNotAccepting',
  '5.3.4': 'MessageSizeExceeded',
  '5.5.1': 'BadCommand',
  '5.5.2': 'SyntaxError',
  '5.5.4': 'BadParam',
  '5.6.0': 'MediaError',
  '5.7.0': 'SecurityPolicy',
  '5.7.1': 'DeliveryNotAuthorized',
  '5.7.8': 'AuthCredentialsInvalid'
};

const ENHANCED_SUBJECT = {
  '0': 'other',
  '1': 'addressing',
  '2': 'mailbox',
  '3': 'mail-system',
  '4': 'network-routing',
  '5': 'protocol',
  '6': 'media',
  '7': 'security'
};

// Contextual enhanced codes (for building responses)
const CONTEXT_CODE = {
  MAIL_FROM_OK:       '2.1.0',
  RCPT_TO_OK:         '2.1.5',
  DATA_OK:            '2.6.0',
  AUTH_SUCCESS:        '2.7.0',
  AUTH_REQUIRED:       '5.7.0',
  AUTH_INVALID:        '5.7.8',
  POLICY_VIOLATION:    '5.7.1',
  MAILBOX_NOT_FOUND:   '5.1.1',
  MAILBOX_SYNTAX:      '5.1.3',
  MAILBOX_FULL:        '4.2.2',
  SYSTEM_ERROR:        '4.3.0',
  NETWORK_ERROR:       '4.4.0',
  CONNECTION_TIMEOUT:  '4.4.2'
};

// Commands that skip enhanced status codes in responses
const SKIP_ENHANCED = new Set(['HELO', 'EHLO', 'LHLO']);


// ============================================================
//  Auth mechanism canonicalization
// ============================================================

const AUTH_CANON = {
  'PLAIN': 'PLAIN',
  'LOGIN': 'LOGIN',
  'XOAUTH2': 'XOAUTH2',
  'OAUTHBEARER': 'OAUTHBEARER',
  'CRAM-MD5': 'CRAM-MD5',
  'CRAMMD5': 'CRAM-MD5',
  'SCRAM-SHA-1': 'SCRAM-SHA-1',
  'SCRAM-SHA1': 'SCRAM-SHA-1',
  'SCRAM-SHA-256': 'SCRAM-SHA-256',
  'SCRAM-SHA256': 'SCRAM-SHA-256',
  'GSSAPI': 'GSSAPI',
  'NTLM': 'NTLM',
  'ANONYMOUS': 'ANONYMOUS',
  'EXTERNAL': 'EXTERNAL'
};


// ============================================================
//  Reply parsing
// ============================================================

function looksLikeReply(u8) {
  if (u8.length < 6) return false;
  return isDigit(u8[0]) && isDigit(u8[1]) && isDigit(u8[2]) && (u8[3] === 32 || u8[3] === 45);
}

function mapReplyCode(code) {
  let cls = Math.floor(code / 100);
  return {
    class: SMTP_REPLY_CLASS[cls] || 'unknown',
    meaning: SMTP_REPLY_MEANING[code] || 'Unspecified'
  };
}

function mapEnhancedCode(e) {
  let parts = e.split('.');
  let cls = parts[0] === '2' ? 'success' : parts[0] === '4' ? 'tempfail' : 'permfail';
  return {
    code: e,
    class: cls,
    subject: ENHANCED_SUBJECT[parts[1]] || 'other',
    label: ENHANCED_STATUS[e] || null
  };
}

function splitReplyLines(u8) {
  let lines = [];
  let start = 0;
  for (let i = 0; i + 1 < u8.length; i++) {
    if (u8[i] === 13 && u8[i + 1] === 10) {
      lines.push(u8.slice(start, i + 2));
      start = i + 2;
      i++;
    }
  }
  if (start < u8.length) lines.push(u8.slice(start));
  return lines;
}

// Pre-compiled patterns for reply parsing
const RE_ENHANCED = /^(\d\.\d+\.\d+)(?:\s|$)/;
const RE_KNOWN_CAP = /^(?:SIZE(?:\s+\d+)?|AUTH(?:=|\s)|STARTTLS|PIPELINING|CHUNKING|8BITMIME|SMTPUTF8|ENHANCEDSTATUSCODES|DSN|BINARYMIME|DELIVERBY|MT-PRIORITY|REQUIRETLS|ETRN|VRFY|HELP)\b/i;

function parseReplyBlock(u8) {
  let lines = splitReplyLines(u8);
  let code = (u8[0] - 48) * 100 + (u8[1] - 48) * 10 + (u8[2] - 48);
  let enhanced = null;

  let texts = [];
  for (let i = 0; i < lines.length; i++) {
    let L = lines[i];
    let end = L.length;
    if (end >= 2 && L[end - 2] === 13 && L[end - 1] === 10) end -= 2;
    let txt = u8ToStr(L.slice(4, end));
    texts.push(txt);
    if (!enhanced) {
      let m = RE_ENHANCED.exec(txt);
      if (m) enhanced = m[1];
    }
  }

  let base = mapReplyCode(code);
  let enh = enhanced ? mapEnhancedCode(enhanced) : null;

  // Detect EHLO capability block
  let isMulti = lines.length > 1 && u8[3] === 45;
  let hasKnown = texts.some(function(t) { return RE_KNOWN_CAP.test(t); });

  let obj = {
    type: 'REPLY',
    code: code,
    class: base.class,
    meaning: base.meaning,
    enhanced: enh,
    replyLines: texts.slice(),
    isEhloCaps: (code === 250) && (isMulti || hasKnown),
    capabilities: undefined
  };

  // 334 — AUTH challenge
  if (code === 334) {
    obj.authChallenge = (texts[0] || '').trim() || null;
  }

  // 250 — EHLO capabilities
  if (code === 250 && obj.isEhloCaps) {
    obj.capabilities = extractEhloCapabilities(texts);
  }

  // 220 — banner domain
  if (code === 220) {
    let m = /^([^\s]+)\s+/.exec(texts[0] || '');
    if (m) obj.bannerDomain = m[1];
  }

  return obj;
}


// ============================================================
//  EHLO capabilities extraction
// ============================================================

function extractEhloCapabilities(lines) {
  let caps = {
    auth: { mechanisms: [], advertised: false },
    other: {}
  };

  function addAuthMechs(str) {
    caps.auth.advertised = true;
    let norm = str.replace(/^AUTH[=\s]+/i, '');
    let tokens = norm.split(/[,\s]+/).filter(Boolean);
    for (let i = 0; i < tokens.length; i++) {
      let up = tokens[i].toUpperCase();
      let canon = AUTH_CANON[up] || up;
      if (caps.auth.mechanisms.indexOf(canon) === -1) caps.auth.mechanisms.push(canon);
    }
  }

  function addOther(key, val) {
    let K = key.toUpperCase();
    let V = (typeof val === 'string' && val.trim().length) ? val.trim() : true;
    if (caps.other[K] === undefined) caps.other[K] = V;
  }

  for (let idx = 0; idx < lines.length; idx++) {
    let line = String(lines[idx]).trim();
    if (!line) continue;
    let upper = line.toUpperCase();

    if (upper.indexOf('SIZE') === 0) {
      let m = /^SIZE(?:\s+(\d+))?$/i.exec(line);
      if (m) { caps.size = m[1] ? parseInt(m[1], 10) : true; continue; }
    }

    if (/^AUTH(?:[=\s]+)/i.test(line)) { addAuthMechs(line); continue; }

    if (upper === 'STARTTLS')              { caps.starttls = true; continue; }
    if (upper === 'PIPELINING')            { caps.pipelining = true; continue; }
    if (upper === 'CHUNKING')              { caps.chunking = true; continue; }
    if (upper === '8BITMIME')              { caps.eightBitMime = true; continue; }
    if (upper === 'SMTPUTF8')              { caps.smtputf8 = true; continue; }
    if (upper === 'ENHANCEDSTATUSCODES')   { caps.enhancedStatusCodes = true; continue; }
    if (upper === 'DSN')                   { caps.dsn = true; continue; }
    if (upper === 'BINARYMIME')            { caps.binarymime = true; continue; }
    if (upper === 'DELIVERBY')             { caps.deliverby = true; continue; }
    if (upper === 'MT-PRIORITY')           { caps.mtPriority = true; continue; }
    if (upper === 'REQUIRETLS')            { caps.requiretls = true; continue; }
    if (upper === 'ETRN')                  { caps.etrn = true; continue; }
    if (upper === 'VRFY')                  { caps.vrfy = true; continue; }
    if (upper === 'HELP')                  { caps.help = true; continue; }
    if (upper === 'PRDR')                  { caps.prdr = true; continue; }
    if (upper === 'XCLIENT')               { caps.xclient = true; continue; }
    if (upper === 'XFORWARD')              { caps.xforward = true; continue; }

    // Greeting line (first line = server name)
    if (idx === 0) {
      caps.greeting = line;
      let m = /^([^\s]+)(?:\s|$)/.exec(line);
      if (m && !/^(?:SIZE|AUTH|STARTTLS|PIPELINING|CHUNKING|8BITMIME|SMTPUTF8|ENHANCEDSTATUSCODES)\b/i.test(m[1])) {
        caps.serverName = m[1];
      }
      continue;
    }

    // Unknown extensions — store as key/value
    let mKV = /^([A-Za-z0-9][A-Za-z0-9\-_.]*)(?:[=\s]+(.+))?$/.exec(line);
    if (mKV) {
      addOther(mKV[1], mKV[2] || true);
      continue;
    }
  }

  return caps;
}


// ============================================================
//  Command parsing
// ============================================================

const RE_COMMAND = /^([A-Za-z]{3,16})(?:\s+(.*))?$/;

function parseCommandLine(u8) {
  let line = u8ToStr(u8).trim();
  let m = RE_COMMAND.exec(line);
  if (!m) return { type: 'UNKNOWN', raw: line };
  let cmd = m[1].toUpperCase();
  let rest = (m[2] || '').trim();

  switch (cmd) {
    case 'HELO': return { type: 'HELO', host: rest || null };
    case 'EHLO': return { type: 'EHLO', host: rest || null };
    case 'LHLO': return { type: 'LHLO', host: rest || null };

    case 'MAIL': {
      let p = parsePathWithParams(rest, 'FROM');
      if (p.err) return { type: 'MAIL', error: 'SYNTAX' };
      return { type: 'MAIL', from: p.address, params: p.params };
    }
    case 'RCPT': {
      let p = parsePathWithParams(rest, 'TO');
      if (p.err) return { type: 'RCPT', error: 'SYNTAX' };
      return { type: 'RCPT', to: p.address, params: p.params };
    }

    case 'AUTH': {
      if (!rest) return { type: 'AUTH', error: 'SYNTAX' };
      let sp = rest.split(/\s+/);
      let mech = (sp[0] || '').toUpperCase();
      let initial = sp.length > 1 ? rest.slice(sp[0].length + 1) : null;
      return { type: 'AUTH', mechanism: mech, initial: initial };
    }

    case 'STARTTLS': return { type: 'STARTTLS' };
    case 'RSET':     return { type: 'RSET' };
    case 'NOOP':     return rest ? { type: 'NOOP', argument: rest } : { type: 'NOOP' };
    case 'QUIT':     return { type: 'QUIT' };
    case 'VRFY':     return { type: 'VRFY', target: rest || null };
    case 'EXPN':     return { type: 'EXPN', list: rest || null };
    case 'HELP':     return { type: 'HELP', argument: rest || null };

    case 'DATA':     return { type: 'DATA_START' };
    case 'BDAT':     return { type: 'BDAT_HEADER_ONLY', raw: line };

    default:         return { type: 'UNKNOWN', raw: line };
  }
}

// Pre-compiled patterns for MAIL FROM / RCPT TO (avoid new RegExp on every command)
const RE_PATH_FROM = /^(FROM)\s*:\s*<([^>]*)>\s*(.*)$/i;
const RE_PATH_TO = /^(TO)\s*:\s*<([^>]*)>\s*(.*)$/i;
const RE_PATH = { FROM: RE_PATH_FROM, TO: RE_PATH_TO };

function parsePathWithParams(rest, expectedKey) {
  let re = RE_PATH[expectedKey];
  if (!re) re = new RegExp('^(' + expectedKey + ')\\s*:\\s*<([^>]*)>\\s*(.*)$', 'i');
  let m = re.exec(rest);
  if (!m) return { err: true };
  let address = m[2];
  let tail = (m[3] || '').trim();
  let params = parseEsmtpParams(tail);
  return { address: address, params: params };
}

function parseEsmtpParams(tail) {
  let params = {};
  if (!tail) return params;
  let parts = tail.split(/\s+/);
  for (let i = 0; i < parts.length; i++) {
    let token = parts[i];
    if (!token) continue;
    let eq = token.indexOf('=');
    if (eq === -1) {
      let tk = token.toUpperCase();
      if (tk === 'SMTPUTF8') { params.smtputf8 = true; continue; }
      params[tk] = true;
      continue;
    }
    let k = token.slice(0, eq).toUpperCase();
    let v = token.slice(eq + 1);

    if (k === 'BODY') {
      let vv = v.toUpperCase();
      if (vv === '7BIT' || vv === '8BITMIME' || vv === 'BINARYMIME') params.body = vv;
      else params.BODY = v;
      continue;
    }
    if (k === 'SIZE') { params.size = parseInt(v, 10) || 0; continue; }
    if (k === 'SMTPUTF8') { params.smtputf8 = true; continue; }
    if (k === 'RET') {
      let vv = v.toUpperCase();
      if (vv === 'FULL' || vv === 'HDRS') params.ret = vv;
      else params.RET = v;
      continue;
    }
    if (k === 'ENVID') { params.envid = v; continue; }

    params[k] = v;
  }
  return params;
}


// ============================================================
//  DATA / BDAT frame parsing
// ============================================================

function startsWithDATA(u8) { return u8.length >= 4 && asciiEqCI(u8, 0, 'DATA'); }
function startsWithBDAT(u8) { return u8.length >= 4 && asciiEqCI(u8, 0, 'BDAT'); }

function parseDATAframe(u8) {
  if (u8.length === 4) return { type: 'DATA', body: new Uint8Array(0) };
  let body = u8.slice(4);

  // Un-dot-stuff: \r\n.. → \r\n.
  let out = new Uint8Array(body.length);
  let w = 0;
  for (let i = 0; i < body.length; i++) {
    if (i >= 2 && body[i - 2] === 13 && body[i - 1] === 10 && body[i] === 46 && i + 1 < body.length && body[i + 1] === 46) {
      out[w++] = 46;
      i++;
      continue;
    }
    out[w++] = body[i];
  }
  return { type: 'DATA', body: out.slice(0, w) };
}

function parseBDATframe(u8) {
  let headerEnd = findBdatHeaderEnd(u8);
  if (headerEnd < 4) return { type: 'BDAT', error: 'SYNTAX' };
  let headerStr = u8ToStr(u8.slice(0, headerEnd));
  let m = /^BDAT[\t ]+(\d+)(?:[\t ]+LAST)?$/i.exec(headerStr);
  if (!m) return { type: 'BDAT', error: 'SYNTAX' };
  let size = parseInt(m[1], 10) || 0;
  let hasLast = /\bLAST\b/i.test(headerStr);
  let payload = u8.slice(headerEnd);
  if (payload.length !== size) return { type: 'BDAT', error: 'SIZE_MISMATCH', declared: size, got: payload.length };
  return { type: 'BDAT', size: size, last: hasLast, chunk: payload };
}

function findBdatHeaderEnd(u8) {
  let n = Math.min(u8.length, 256);
  let s = u8ToStr(u8.slice(0, n));
  let m = /^BDAT[\t ]+\d+(?:[\t ]+LAST)?/i.exec(s);
  return m ? m[0].length : -1;
}

function parseBdatHeaderLine(lineStr) {
  let m = /^BDAT[\t ]+(\d+)(?:[\t ]+LAST)?$/i.exec(lineStr.trim());
  if (!m) return null;
  return { size: parseInt(m[1], 10) || 0, last: /\bLAST\b/i.test(lineStr) };
}


// ============================================================
//  Entry point: parseSmtpFrame
// ============================================================

function parseSmtpFrame(u8) {
  if (!(u8 instanceof Uint8Array)) u8 = toU8(u8);
  if (looksLikeReply(u8))    return parseReplyBlock(u8);
  if (startsWithDATA(u8))    return parseDATAframe(u8);
  if (startsWithBDAT(u8))    return parseBDATframe(u8);
  return parseCommandLine(u8);
}


// ============================================================
//  splitSmtpFrames — chunk reassembly
// ============================================================

function splitSmtpFrames(incoming_chunks) {
  // Unify input to one Uint8Array
  let parts = [];
  let total = 0;
  for (let i = 0; i < incoming_chunks.length; i++) {
    let c = incoming_chunks[i];
    if (typeof c === 'string') c = toU8(c);
    else if (typeof Buffer !== 'undefined' && Buffer.isBuffer(c)) c = new Uint8Array(c);
    else if (!(c instanceof Uint8Array)) c = new Uint8Array(0);
    parts.push(c);
    total += c.length;
  }
  let buf = new Uint8Array(total);
  let off = 0;
  for (let j = 0; j < parts.length; j++) { buf.set(parts[j], off); off += parts[j].length; }

  let frames = [];
  let pos = 0;
  let len = buf.length;

  function sliceBytes(s, e) { return buf.slice(s, e); }

  function findCRLF(from) {
    for (let k = from; k < len - 1; k++) {
      if (buf[k] === 13 && buf[k + 1] === 10) return k;
    }
    return -1;
  }

  function readLineRec() {
    let e = findCRLF(pos);
    if (e === -1) return null;
    let rec = { start: pos, endCRLF: e + 2 };
    pos = e + 2;
    return rec;
  }

  function sliceNoCRLF(rec) { return buf.slice(rec.start, rec.endCRLF - 2); }

  function isSp(b) { return b === 32; }
  function toUpper(b) { return (b >= 97 && b <= 122) ? (b - 32) : b; }

  function looksLikeReplyRec(rec) {
    let s = rec.start;
    let e = rec.endCRLF;
    if (e - s < 6) return false;
    return isDigit(buf[s]) && isDigit(buf[s + 1]) && isDigit(buf[s + 2]) && (isSp(buf[s + 3]) || buf[s + 3] === 45);
  }

  function readReplyBlock(rec0) {
    let start = rec0.start;
    let lastEnd = rec0.endCRLF;
    if (isSp(buf[rec0.start + 3])) return sliceBytes(start, lastEnd);
    while (true) {
      let n = readLineRec();
      if (!n) { pos = start; return null; }
      if (!looksLikeReplyRec(n)) { pos = start; return null; }
      lastEnd = n.endCRLF;
      if (isSp(buf[n.start + 3])) break;
    }
    return sliceBytes(start, lastEnd);
  }

  function isDATAline(rec) {
    let s = rec.start;
    return (rec.endCRLF - s === 6 &&
      toUpper(buf[s]) === 68 && toUpper(buf[s + 1]) === 65 &&
      toUpper(buf[s + 2]) === 84 && toUpper(buf[s + 3]) === 65 &&
      buf[s + 4] === 13 && buf[s + 5] === 10);
  }

  function findDataTerminator(from) {
    for (let q = from + 2; q < len - 2; q++) {
      if (buf[q - 2] === 13 && buf[q - 1] === 10 && buf[q] === 46 && buf[q + 1] === 13 && buf[q + 2] === 10) return q - 2;
    }
    return -1;
  }

  function parseBdatHeaderRec(rec) {
    let s = u8ToStr(sliceNoCRLF(rec));
    let m = /^BDAT[\t ]+(\d+)(?:[\t ]+LAST)?$/i.exec(s);
    return m ? { size: parseInt(m[1], 10) } : null;
  }

  // Main scan
  while (pos < len) {
    let L = readLineRec();
    if (!L) break;

    // 1) Reply block
    if (looksLikeReplyRec(L)) {
      let rep = readReplyBlock(L);
      if (!rep) break;
      frames.push(rep);
      continue;
    }

    // 2) DATA — frame = "DATA" + body (without terminator)
    if (isDATAline(L)) {
      let head = sliceNoCRLF(L);
      let bodyStart = L.endCRLF;
      let termAt = findDataTerminator(bodyStart);
      if (termAt === -1) { pos = L.start; break; }
      let body = sliceBytes(bodyStart, termAt);
      let out = new Uint8Array(head.length + body.length);
      out.set(head, 0);
      out.set(body, head.length);
      frames.push(out);
      pos = termAt + 5;
      continue;
    }

    // 3) BDAT — frame = header + payload
    let bd = parseBdatHeaderRec(L);
    if (bd) {
      let payloadEnd = pos + bd.size;
      if (payloadEnd > len) { pos = L.start; break; }
      let header = sliceNoCRLF(L);
      let payload = sliceBytes(pos, payloadEnd);
      let outB = new Uint8Array(header.length + payload.length);
      outB.set(header, 0);
      outB.set(payload, header.length);
      frames.push(outB);
      pos = payloadEnd;
      continue;
    }

    // 4) Regular command line
    frames.push(sliceNoCRLF(L));
  }

  return frames;
}


// ============================================================
//  Response building helpers
// ============================================================

function buildReply(code, message, options) {
  options = options || {};
  let enhanced = options.enhanced || null;
  let lines = Array.isArray(message) ? message : [message];
  let out = '';

  for (let i = 0; i < lines.length; i++) {
    let sep = (i < lines.length - 1) ? '-' : ' ';
    let prefix = String(code) + sep;
    if (enhanced) prefix += enhanced + ' ';
    out += prefix + lines[i] + '\r\n';
  }

  return out;
}

function buildEhloReply(hostname, capabilities) {
  let lines = [];
  lines.push(hostname);
  if (capabilities) {
    for (let i = 0; i < capabilities.length; i++) {
      lines.push(capabilities[i]);
    }
  }
  let out = '';
  for (let i = 0; i < lines.length; i++) {
    let sep = (i < lines.length - 1) ? '-' : ' ';
    out += '250' + sep + lines[i] + '\r\n';
  }
  return out;
}


// ============================================================
//  Exports
// ============================================================

export {
  // Constants
  SMTP_REPLY_CLASS,
  SMTP_REPLY_MEANING,
  ENHANCED_STATUS,
  ENHANCED_SUBJECT,
  CONTEXT_CODE,
  SKIP_ENHANCED,
  AUTH_CANON,

  // Reply parsing
  looksLikeReply,
  mapReplyCode,
  mapEnhancedCode,
  parseReplyBlock,

  // EHLO
  extractEhloCapabilities,

  // Command parsing
  parseCommandLine,
  parsePathWithParams,
  parseEsmtpParams,

  // DATA/BDAT
  parseDATAframe,
  parseBDATframe,
  parseBdatHeaderLine,

  // Entry point
  parseSmtpFrame,

  // Frame splitting
  splitSmtpFrames,

  // Response building
  buildReply,
  buildEhloReply
};
