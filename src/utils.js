
const TD = new TextDecoder('utf-8');
const TE = new TextEncoder();

function toU8(x) {
  if (x instanceof Uint8Array) return x;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(x)) return new Uint8Array(x);
  if (typeof x === 'string') return TE.encode(x);
  return new Uint8Array(0);
}

function u8ToStr(u8) {
  return TD.decode(u8 || new Uint8Array(0));
}

function concatU8(arrays) {
  let total = 0;
  for (let i = 0; i < arrays.length; i++) total += arrays[i].length;
  let out = new Uint8Array(total);
  let off = 0;
  for (let i = 0; i < arrays.length; i++) {
    out.set(arrays[i], off);
    off += arrays[i].length;
  }
  return out;
}

function u8Equal(a, b) {
  if (a === b) return true;
  if (a == null || b == null) return false;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function hasNonAscii(u8) {
  for (let i = 0; i < u8.length; i++) {
    if (u8[i] > 0x7F) return true;
  }
  return false;
}

function asciiEqCI(u8, pos, str) {
  for (let i = 0; i < str.length; i++) {
    let b = u8[pos + i];
    if (b === undefined) return false;
    let bu = (b >= 97 && b <= 122) ? (b - 32) : b;
    let cu = str.charCodeAt(i);
    cu = (cu >= 97 && cu <= 122) ? (cu - 32) : cu;
    if (bu !== cu) return false;
  }
  return true;
}

function isDigit(b) { return b >= 48 && b <= 57; }

function indexOfCRLF(buf, from) {
  for (let i = from; i + 1 < buf.length; i++) {
    if (buf[i] === 13 && buf[i + 1] === 10) return i;
  }
  return -1;
}


export {
  TD,
  TE,
  toU8,
  u8ToStr,
  concatU8,
  u8Equal,
  hasNonAscii,
  asciiEqCI,
  isDigit,
  indexOfCRLF,
  extractAddress,
  extractAddressList,
  parseTags,
  parseMailHeaders
};


// ============================================================
//  Address extraction (shared by server.js and client.js)
// ============================================================

function extractAddress(val) {
  if (!val) return null;
  if (typeof val === 'object' && val.address) return val.address;
  let s = String(val);
  let m = /<([^>]+)>/.exec(s);
  if (m) return m[1];
  if (s.indexOf('@') >= 0) return s.trim();
  return null;
}

function extractAddressList(arr) {
  let out = [];
  for (let i = 0; i < arr.length; i++) {
    let item = arr[i];
    if (typeof item === 'string') {
      let parts = item.split(',');
      for (let j = 0; j < parts.length; j++) {
        let a = extractAddress(parts[j].trim());
        if (a) out.push(a);
      }
    } else {
      let a = extractAddress(item);
      if (a) out.push(a);
    }
  }
  return out;
}


// ============================================================
//  Tag parsing (shared by dkim.js and dmarc.js)
//  Format: "k1=v1; k2=v2; k3=v3"
// ============================================================

function parseTags(value, lowercaseKeys) {
  let tags = {};
  let parts = value.split(';');
  for (let i = 0; i < parts.length; i++) {
    let p = parts[i].trim();
    let eq = p.indexOf('=');
    if (eq > 0) {
      let k = p.slice(0, eq).trim();
      if (lowercaseKeys) k = k.toLowerCase();
      tags[k] = p.slice(eq + 1).trim();
    }
  }
  return tags;
}


// ============================================================
//  Mail header parser (shared by dkim.js and session.js)
// ============================================================

function parseMailHeaders(raw) {
  let str = (raw instanceof Uint8Array || Buffer.isBuffer(raw)) ? u8ToStr(raw) : String(raw);
  let idx = str.indexOf('\r\n\r\n');
  let headStr = idx >= 0 ? str.slice(0, idx) : str;
  let bodyStr = idx >= 0 ? str.slice(idx + 4) : '';

  let headers = [];
  let lines = headStr.split('\r\n');
  let cur = null;

  for (let i = 0; i < lines.length; i++) {
    let L = lines[i];
    if (/^[ \t]/.test(L)) {
      if (cur) cur.raw += '\r\n' + L;
      continue;
    }
    let m = /^([^:]+):\s*(.*)$/.exec(L);
    if (m) {
      if (cur) headers.push(cur);
      cur = { name: m[1], value: m[2], raw: L };
    } else if (cur) {
      cur.raw += '\r\n' + L;
    }
  }
  if (cur) headers.push(cur);

  // Unfold values
  for (let j = 0; j < headers.length; j++) {
    headers[j].value = headers[j].raw.replace(/^[^:]+:\s*/, '').replace(/\r\n[ \t]+/g, ' ');
  }

  // Build convenience object
  let map = {};
  for (let k = 0; k < headers.length; k++) {
    let n = headers[k].name.toLowerCase();
    if (n === 'subject') map.subject = headers[k].value;
    else if (n === 'message-id') map.messageId = headers[k].value;
    else if (n === 'date') map.date = headers[k].value;
    else if (n === 'from') map.from = headers[k].value;
    else if (n === 'to') map.to = headers[k].value;
  }

  return { headers: headers, map: map, body: bodyStr };
}
