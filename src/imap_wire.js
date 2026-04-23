
import {
  toU8,
  u8ToStr,
  asciiEqCI,
  isDigit,
  indexOfCRLF
} from './utils.js';


// ============================================================
//  Constants
// ============================================================

// Byte constants
const CR    = 13;
const LF    = 10;
const SP    = 32;
const HTAB  = 9;
const DQUOTE = 34;
const BACKSLASH = 92;
const LPAREN = 40;
const RPAREN = 41;
const LBRACE = 123;
const RBRACE = 125;
const LBRACKET = 91;
const RBRACKET = 93;
const STAR   = 42;
const PLUS   = 43;
const PERCENT = 37;
const MINUS  = 45;
const DOT    = 46;
const UNDERSCORE = 95;
const PLUS_SIGN = 43;
const TILDE = 126;

// RFC 3501 CHAR: any 7-bit US-ASCII except NUL
// atom-char: any CHAR except atom-specials
// atom-specials: "(" / ")" / "{" / SP / CTL / list-wildcards / quoted-specials / resp-specials
// list-wildcards: "%" / "*"
// quoted-specials: DQUOTE / "\"
// resp-specials: "]"

// Token types returned by tokenizer
const TOK = {
  ATOM:         'atom',
  NUMBER:       'number',
  QUOTED:       'quoted',
  LITERAL:      'literal',
  LIST:         'list',
  NIL:          'nil',
  BRACKETED:    'bracketed'  // [...] used in FETCH item names like BODY[HEADER.FIELDS (...)]
};

// Parse result statuses
const PARSE = {
  OK:               'ok',
  INCOMPLETE:       'incomplete',
  NEED_CONTINUATION: 'needContinuation',
  ERROR:            'error'
};

// Response kinds (server → client)
const RESP = {
  UNTAGGED:     'untagged',     // * ...
  CONTINUATION: 'continuation', // + ...
  TAGGED:       'tagged'        // tag OK/NO/BAD ...
};

// IMAP known status values in tagged responses
const STATUS = {
  OK:  'OK',
  NO:  'NO',
  BAD: 'BAD',
  PREAUTH: 'PREAUTH',  // only as greeting (untagged)
  BYE: 'BYE'           // only as untagged
};


// ============================================================
//  Byte-level helpers
// ============================================================

function isCtl(b) {
  return (b >= 0 && b <= 31) || b === 127;
}

function isAtomChar(b) {
  // atom-char = any CHAR except atom-specials
  if (isCtl(b)) return false;
  if (b > 127) return false;          // 7-bit only per RFC
  switch (b) {
    case LPAREN: case RPAREN: case LBRACE:
    case SP: case HTAB:
    case DQUOTE:                      // only DQUOTE excluded here
    case RBRACKET:                    // resp-specials (NOT '[' — atom-char allows '[')
      return false;
  }
  // NOTE 1: BACKSLASH is technically atom-special per RFC 3501 ABNF, but all real
  // IMAP implementations (Dovecot, Cyrus, Gmail, Outlook, Thunderbird) tokenize
  // system flags like "\Seen", "\Flagged" as single atoms. We do the same.
  //
  // NOTE 2: '*' and '%' are list-wildcards and formally atom-special, BUT sequence
  // sets ("100:*") require them as atom chars in FETCH/STORE/COPY context. Real
  // servers resolve this by allowing these chars in tokens and disambiguating at
  // the command handler: in LIST/LSUB the arg is a pattern; in FETCH/STORE it's
  // a sequence set. We follow that pragma.
  return true;
}

// astring-char = atom-char plus ']'  (used for mailbox names etc.)
function isAstringChar(b) {
  if (b === RBRACKET) return true;
  return isAtomChar(b);
}

// Skip spaces (HTAB treated as space too, per lenient reading)
function skipSP(buf, pos) {
  while (pos < buf.length && (buf[pos] === SP || buf[pos] === HTAB)) pos++;
  return pos;
}

// Find CRLF from pos; returns index of CR (CRLF starts), or -1
function findCRLFfrom(buf, pos) {
  for (let i = pos; i + 1 < buf.length; i++) {
    if (buf[i] === CR && buf[i + 1] === LF) return i;
  }
  return -1;
}


// ============================================================
//  Tokenizer (SHARED by server + client parsing)
//  All functions: (buf, pos) → { type, value, end }  or null on incomplete
// ============================================================

// Pre-compiled patterns used on hot paths
const RE_NUMBER  = /^\d+$/;
const RE_PARTIAL = /^(\d+)(?:\.(\d+))?$/;

// --- Atom ---
// Reads a sequence of atom-chars. Returns null if no atom-char at pos.
function readAtom(buf, pos) {
  let start = pos;
  while (pos < buf.length && isAtomChar(buf[pos])) pos++;
  if (pos === start) return null;
  let str = u8ToStr(buf.subarray(start, pos));

  // NIL is atom syntactically, distinguish here
  if (str.length === 3 && asciiEqCI(buf, start, 'NIL')) {
    return { type: TOK.NIL, value: null, end: pos };
  }

  // Pure digits → number (but only if fits in JS safe integer range)
  if (RE_NUMBER.test(str)) {
    let n = parseInt(str, 10);
    if (String(n) === str) {
      return { type: TOK.NUMBER, value: n, end: pos };
    }
  }

  return { type: TOK.ATOM, value: str, end: pos };
}

// --- Astring atom (allows ']', used for mailbox names, AUTH mechanisms) ---
function readAstringAtom(buf, pos) {
  let start = pos;
  while (pos < buf.length && isAstringChar(buf[pos])) pos++;
  if (pos === start) return null;
  let str = u8ToStr(buf.subarray(start, pos));
  return { type: TOK.ATOM, value: str, end: pos };
}

// --- Quoted string ---
// Returns:
//   { type: 'quoted', value: string, end: N }  — complete
//   null                                        — not a quoted string at pos
//   { incomplete: true }                        — starts with " but no closing " yet
function readQuoted(buf, pos) {
  if (buf[pos] !== DQUOTE) return null;
  let out = '';
  let i = pos + 1;
  while (i < buf.length) {
    let b = buf[i];
    if (b === DQUOTE) {
      return { type: TOK.QUOTED, value: out, end: i + 1 };
    }
    if (b === BACKSLASH) {
      if (i + 1 >= buf.length) return { incomplete: true };
      let next = buf[i + 1];
      // RFC 3501: quoted-specials = DQUOTE / "\"
      if (next !== DQUOTE && next !== BACKSLASH) {
        // Lenient: allow other chars after backslash
      }
      out += String.fromCharCode(next);
      i += 2;
      continue;
    }
    if (b === CR || b === LF) {
      // Quoted strings cannot contain CR/LF
      return null;
    }
    out += String.fromCharCode(b);
    i++;
  }
  return { incomplete: true };
}

// --- Literal ---
// Literal syntax:
//    "{" number ["+"] "}" CRLF <bytes>
// If "+" present, it's a non-synchronizing literal (LITERAL+ extension):
//    sender does NOT wait for continuation, just sends immediately.
// Otherwise, server must respond with "+ ..." continuation before sender sends bytes.
//
// Returns:
//   null                                                — not a literal at pos
//   { incompleteHeader: true }                          — "{...}" not yet closed
//   { headerOnly: true, size, nonSync, headerEnd }      — header parsed, bytes not yet received
//   { type: 'literal', value: Uint8Array, nonSync, end } — fully read
//
// headerEnd points to the byte right after CRLF — where the literal bytes start.
function readLiteral(buf, pos) {
  if (buf[pos] !== LBRACE) return null;

  // Find closing '}'
  let i = pos + 1;
  let numStart = i;
  while (i < buf.length && isDigit(buf[i])) i++;
  if (i === numStart) {
    // Need at least one digit after '{'
    if (i >= buf.length) return { incompleteHeader: true };
    return null;  // '{' followed by non-digit — not a valid literal (syntax error)
  }

  let sizeStr = u8ToStr(buf.subarray(numStart, i));
  let size = parseInt(sizeStr, 10);

  let nonSync = false;
  if (i < buf.length && buf[i] === PLUS_SIGN) {
    nonSync = true;
    i++;
  }

  if (i >= buf.length) return { incompleteHeader: true };
  if (buf[i] !== RBRACE) return null;  // bad syntax — not a literal
  i++;

  // Must be followed by CRLF
  if (i >= buf.length) return { incompleteHeader: true };
  if (buf[i] !== CR) return null;
  if (i + 1 >= buf.length) return { incompleteHeader: true };
  if (buf[i + 1] !== LF) return null;
  i += 2;

  let headerEnd = i;  // first byte of literal content

  // Check if all bytes are available
  if (buf.length - headerEnd < size) {
    return { headerOnly: true, size: size, nonSync: nonSync, headerEnd: headerEnd };
  }

  let bytes = buf.subarray(headerEnd, headerEnd + size);
  return {
    type: TOK.LITERAL,
    value: bytes,
    nonSync: nonSync,
    end: headerEnd + size,
    size: size
  };
}

// --- Parenthesized list ---
// Returns:
//   null                           — not a list at pos
//   { incomplete: true }           — list not fully received
//   { needLiteral: {...}, ... }    — list contains an unreceived literal
//   { error: '...' }               — syntax error inside list
//   { type: 'list', value: [items], end: N }
function readList(buf, pos) {
  if (buf[pos] !== LPAREN) return null;
  let p = pos + 1;
  let items = [];

  // Empty list?
  p = skipSP(buf, p);
  if (p >= buf.length) return { incomplete: true };
  if (buf[p] === RPAREN) {
    return { type: TOK.LIST, value: items, end: p + 1 };
  }

  while (p < buf.length) {
    // Use readValue (not readAnyToken) so atom+section like BODY[TEXT] works
    // inside FETCH response attribute lists.
    let tok = readValue(buf, p);
    if (tok === null)            return { error: 'BAD_LIST_ITEM' };
    if (tok.incomplete)          return { incomplete: true };
    if (tok.needLiteral)         return tok;   // bubble up
    if (tok.error)               return tok;   // bubble up
    items.push(tok);
    p = tok.end;

    p = skipSP(buf, p);
    if (p >= buf.length) return { incomplete: true };

    if (buf[p] === RPAREN) {
      return { type: TOK.LIST, value: items, end: p + 1 };
    }
    // Otherwise continue (next token)
  }
  return { incomplete: true };
}

// --- Bracketed section — used in FETCH item names like BODY[HEADER] ---
// Returns the raw content between brackets as a string (unparsed — higher layer parses it).
// Used because BODY[HEADER.FIELDS (SUBJECT FROM)] has complex inner syntax that's specific to FETCH.
function readBracketed(buf, pos) {
  if (buf[pos] !== LBRACKET) return null;
  let depth = 1;
  let i = pos + 1;
  let start = i;
  while (i < buf.length) {
    if (buf[i] === LBRACKET) depth++;
    else if (buf[i] === RBRACKET) {
      depth--;
      if (depth === 0) {
        let inner = u8ToStr(buf.subarray(start, i));
        return { type: TOK.BRACKETED, value: inner, end: i + 1 };
      }
    }
    else if (buf[i] === CR || buf[i] === LF) return null;
    i++;
  }
  return { incomplete: true };
}

// --- Read any single value (atom/number/nil/quoted/literal/list/atom+section) ---
//
// This is the unified value reader used by:
//   - parseCommand (for command args)
//   - readList     (for list items)
//   - parseResponseTail (for response data tokens)
//
// Return types:
//   null                           — nothing valid starts at pos (not a value)
//   { incomplete: true }           — needs more data
//   { needLiteral: {...} }         — literal header seen, bytes not yet delivered
//   { error: '...' }               — something started but is syntactically invalid
//                                    (caller should treat as protocol error)
//   { type, value, end, ... }      — successful parse
function readValue(buf, pos) {
  if (pos >= buf.length) return { incomplete: true };
  let b = buf[pos];

  // Quoted string
  if (b === DQUOTE) {
    let q = readQuoted(buf, pos);
    if (q === null)      return { error: 'BAD_QUOTED' };  // malformed (e.g. CR/LF inside)
    if (q.incomplete)    return { incomplete: true };
    return q;
  }

  // List
  if (b === LPAREN) return readList(buf, pos);

  // Literal
  if (b === LBRACE) {
    let lit = readLiteral(buf, pos);
    if (lit === null)             return { error: 'BAD_LITERAL' };   // "{" without valid "{N}CRLF"
    if (lit.incompleteHeader)     return { incomplete: true };
    if (lit.headerOnly) {
      return {
        needLiteral: {
          size: lit.size,
          nonSync: lit.nonSync,
          headerEnd: lit.headerEnd
        }
      };
    }
    return lit;
  }

  // Atom (possibly followed by bracketed section like BODY[HEADER] and optional <0.1024> partial)
  // Scan atom-chars but stop at '[' so we can read the bracketed section separately.
  let start = pos;
  while (pos < buf.length && isAtomChar(buf[pos]) && buf[pos] !== LBRACKET) pos++;
  if (pos === start) return null;   // no atom-char at pos — not a value
  let atomStr = u8ToStr(buf.subarray(start, pos));
  let atomEnd = pos;

  // Followed by '[' — atom+section (FETCH item like BODY[HEADER], BODY[HEADER.FIELDS (SUBJECT)])
  if (atomEnd < buf.length && buf[atomEnd] === LBRACKET) {
    let bracket = readBracketed(buf, atomEnd);
    if (bracket === null)      return { error: 'BAD_BRACKETED' };
    if (bracket.incomplete)    return { incomplete: true };

    // Optional <offset.length> partial specifier after brackets
    let end = bracket.end;
    let partial = null;
    if (end < buf.length && buf[end] === 60 /* < */) {
      let close = end + 1;
      while (close < buf.length && buf[close] !== 62 /* > */) close++;
      if (close >= buf.length) return { incomplete: true };
      let pStr = u8ToStr(buf.subarray(end + 1, close));
      let m = RE_PARTIAL.exec(pStr);
      if (!m) return { error: 'BAD_PARTIAL' };
      partial = {
        offset: parseInt(m[1], 10),
        length: m[2] != null ? parseInt(m[2], 10) : null  // null = response form "<offset>"
      };
      end = close + 1;
    }

    return {
      type: TOK.ATOM,
      value: atomStr,
      section: bracket.value,
      partial: partial,
      end: end
    };
  }

  // Check for NIL (atom syntactically, but distinct type)
  if (atomStr === 'NIL') {
    return { type: TOK.NIL, value: null, end: atomEnd };
  }

  // Check for pure number
  if (RE_NUMBER.test(atomStr)) {
    let n = parseInt(atomStr, 10);
    if (String(n) === atomStr) {
      return { type: TOK.NUMBER, value: n, end: atomEnd };
    }
  }

  return { type: TOK.ATOM, value: atomStr, end: atomEnd };
}

// Backward-compatible alias — readAnyToken behaves identically to readValue now.
// Kept exported because external consumers may depend on the name.
const readAnyToken = readValue;


// ============================================================
//  Server-side: parseCommand (client → server)
// ============================================================

// parseCommand — parse a single command line starting at pos.
//
// Returns one of:
//   { status: 'ok', command: {tag, name, args}, end: N }
//   { status: 'incomplete' }
//   { status: 'needContinuation', tag, literalSize, nonSync, partial, after }
//       — caller must:
//           if !nonSync: send "+ ..." continuation to client
//           then wait for at least `literalSize` bytes after `after`
//           then call parseCommand again from same pos
//   { status: 'error', reason, tag?, end? }
//
// The "partial" field holds what was parsed so far so the session can show error context.
function parseCommand(buf, pos) {
  pos = pos || 0;
  let start = pos;

  // Read tag (atom — one or more tag-chars, actually astring-char minus '+')
  let tagTok = readAtom(buf, pos);
  if (!tagTok) {
    // Could be empty line or incomplete
    if (pos >= buf.length) return { status: PARSE.INCOMPLETE };
    // Find next CRLF and mark as error
    let cr = findCRLFfrom(buf, pos);
    if (cr < 0) return { status: PARSE.INCOMPLETE };
    return { status: PARSE.ERROR, reason: 'BAD_TAG', end: cr + 2 };
  }
  pos = tagTok.end;
  let tag = tagTok.value != null ? String(tagTok.value) : '';

  // Must be followed by space
  if (pos >= buf.length) return { status: PARSE.INCOMPLETE };
  if (buf[pos] !== SP) {
    let cr = findCRLFfrom(buf, pos);
    if (cr < 0) return { status: PARSE.INCOMPLETE };
    return { status: PARSE.ERROR, reason: 'BAD_TAG_SEP', tag: tag, end: cr + 2 };
  }
  pos = skipSP(buf, pos);

  // Read command name (atom)
  let cmdTok = readAtom(buf, pos);
  if (!cmdTok) {
    let cr = findCRLFfrom(buf, pos);
    if (cr < 0) return { status: PARSE.INCOMPLETE };
    return { status: PARSE.ERROR, reason: 'BAD_COMMAND', tag: tag, end: cr + 2 };
  }
  pos = cmdTok.end;
  let name = String(cmdTok.value).toUpperCase();

  // Read args until CRLF
  let args = [];
  while (true) {
    // Check for end of command (CRLF)
    if (pos >= buf.length) return { status: PARSE.INCOMPLETE };
    if (buf[pos] === CR) {
      if (pos + 1 >= buf.length) return { status: PARSE.INCOMPLETE };
      if (buf[pos + 1] === LF) {
        return { status: PARSE.OK, command: { tag: tag, name: name, args: args }, end: pos + 2 };
      }
      return { status: PARSE.ERROR, reason: 'BAD_EOL', tag: tag, end: pos + 1 };
    }

    // Must have space before next arg
    if (buf[pos] === SP || buf[pos] === HTAB) {
      pos = skipSP(buf, pos);
      if (pos >= buf.length) return { status: PARSE.INCOMPLETE };
      // Allow trailing space before CRLF (lenient)
      if (buf[pos] === CR) continue;
    }

    // Read next argument
    let tok = readValue(buf, pos);
    if (tok === null) {
      // readValue returned null only when there's no valid start byte —
      // in command context this means garbage between args. Treat as protocol error.
      let cr = findCRLFfrom(buf, pos);
      if (cr < 0) return { status: PARSE.INCOMPLETE };
      return { status: PARSE.ERROR, reason: 'BAD_ARG', tag: tag, end: cr + 2 };
    }
    if (tok.incomplete) return { status: PARSE.INCOMPLETE };
    if (tok.needLiteral) {
      // Client must send a literal; server needs to respond with continuation (unless LITERAL+)
      return {
        status: PARSE.NEED_CONTINUATION,
        tag: tag,
        command: name,
        literalSize: tok.needLiteral.size,
        nonSync: tok.needLiteral.nonSync,
        after: tok.needLiteral.headerEnd,
        partial: { tag: tag, name: name, argsParsed: args.slice() }
      };
    }
    if (tok.error) {
      // Syntax error inside a value (bad quoted, bad literal header, etc.)
      let cr = findCRLFfrom(buf, pos);
      return { status: PARSE.ERROR, reason: tok.error, tag: tag, end: cr >= 0 ? cr + 2 : undefined };
    }
    args.push(tok);
    pos = tok.end;
  }
}


// ============================================================
//  Client-side: parseResponse (server → client)
// ============================================================

// parseResponse — parse a single response from server.
//
// Returns:
//   { status: 'ok', response: {...}, end: N }
//   { status: 'incomplete' }
//   { status: 'error', reason, end? }
//
// response shape:
//   { kind: 'untagged',     data: [tokens]   }    — "* 42 EXISTS", "* CAPABILITY IMAP4rev1 ..."
//   { kind: 'continuation', text: string     }    — "+ Ready for literal"
//   { kind: 'tagged',       tag, status, code?, text }  — "A001 OK [READ-WRITE] Selected"
function parseResponse(buf, pos) {
  pos = pos || 0;
  if (pos >= buf.length) return { status: PARSE.INCOMPLETE };

  // Continuation: "+ ..."
  if (buf[pos] === PLUS) {
    let cr = findCRLFfrom(buf, pos);
    if (cr < 0) return { status: PARSE.INCOMPLETE };
    let afterPlus = pos + 1;
    if (afterPlus < cr && (buf[afterPlus] === SP || buf[afterPlus] === HTAB)) afterPlus++;
    let text = u8ToStr(buf.subarray(afterPlus, cr));
    return {
      status: PARSE.OK,
      response: { kind: RESP.CONTINUATION, text: text },
      end: cr + 2
    };
  }

  // Untagged: "* ..."
  if (buf[pos] === STAR) {
    let p = pos + 1;
    if (p >= buf.length) return { status: PARSE.INCOMPLETE };
    if (buf[p] !== SP) {
      let cr = findCRLFfrom(buf, p);
      if (cr < 0) return { status: PARSE.INCOMPLETE };
      return { status: PARSE.ERROR, reason: 'BAD_UNTAGGED_SEP', end: cr + 2 };
    }
    p = skipSP(buf, p);
    return parseResponseTail(buf, p, RESP.UNTAGGED, null);
  }

  // Tagged: tag SP status ...
  let tagTok = readAtom(buf, pos);
  if (!tagTok) return { status: PARSE.INCOMPLETE };
  let tag = String(tagTok.value);
  let p = tagTok.end;

  if (p >= buf.length) return { status: PARSE.INCOMPLETE };
  if (buf[p] !== SP) {
    let cr = findCRLFfrom(buf, p);
    if (cr < 0) return { status: PARSE.INCOMPLETE };
    return { status: PARSE.ERROR, reason: 'BAD_TAG_SEP', end: cr + 2 };
  }
  p = skipSP(buf, p);
  return parseResponseTail(buf, p, RESP.TAGGED, tag);
}

// Parse the tail of a response (after "* " or "tag ").
// For tagged, the first token is the status (OK/NO/BAD/PREAUTH/BYE).
// For untagged, it's any data — first token may be status (for status-responses like "* OK ..."),
// or a number followed by attribute (like "* 42 EXISTS"), or a keyword (like "* CAPABILITY ...").
function parseResponseTail(buf, pos, kind, tag) {
  // Collect tokens until CRLF
  let tokens = [];
  let p = pos;

  while (true) {
    if (p >= buf.length) return { status: PARSE.INCOMPLETE };
    if (buf[p] === CR) {
      if (p + 1 >= buf.length) return { status: PARSE.INCOMPLETE };
      if (buf[p + 1] === LF) {
        p += 2;
        break;
      }
      return { status: PARSE.ERROR, reason: 'BAD_EOL', end: p + 1 };
    }
    if (buf[p] === SP || buf[p] === HTAB) { p = skipSP(buf, p); continue; }

    // [response-code] — appears inside status responses
    // We collect it as a 'code' token with type 'bracketed-resp-code'
    if (buf[p] === LBRACKET && tokens.length > 0) {
      // Usually follows OK/NO/BAD token — read as bracketed
      let br = readBracketed(buf, p);
      if (!br) return { status: PARSE.ERROR, reason: 'BAD_BRACKETED' };
      if (br.incomplete) return { status: PARSE.INCOMPLETE };
      tokens.push({ type: 'respcode', value: br.value, end: br.end });
      p = br.end;
      continue;
    }

    let tok = readValue(buf, p);
    if (tok === null) {
      // Unknown byte — try to read until space/CRLF as atom
      let cr = findCRLFfrom(buf, p);
      if (cr < 0) return { status: PARSE.INCOMPLETE };
      // Lenient: treat remainder of line as text atom
      let textTok = { type: TOK.ATOM, value: u8ToStr(buf.subarray(p, cr)), end: cr };
      tokens.push(textTok);
      p = cr;
      continue;
    }
    if (tok.incomplete) return { status: PARSE.INCOMPLETE };
    if (tok.error) {
      let cr = findCRLFfrom(buf, p);
      return { status: PARSE.ERROR, reason: tok.error, end: cr >= 0 ? cr + 2 : undefined };
    }
    if (tok.needLiteral) {
      // Response contains a literal — client must wait for the bytes.
      // Unlike server-side (which might send continuation), client just reads more.
      return { status: PARSE.INCOMPLETE };
    }
    tokens.push(tok);
    p = tok.end;
  }

  // Build response object based on kind
  if (kind === RESP.TAGGED) {
    // First token should be status atom
    let statusTok = tokens[0];
    let statusVal = statusTok && statusTok.type === TOK.ATOM ? String(statusTok.value).toUpperCase() : '';

    // Optional response code [...] in tokens[1]
    let codeTok = null;
    let textStart = 1;
    if (tokens[1] && tokens[1].type === 'respcode') {
      codeTok = tokens[1].value;
      textStart = 2;
    }

    // Remaining tokens → text
    let textParts = [];
    for (let i = textStart; i < tokens.length; i++) {
      textParts.push(tokenToText(tokens[i]));
    }

    return {
      status: PARSE.OK,
      response: {
        kind: RESP.TAGGED,
        tag: tag,
        status: statusVal,
        code: codeTok,
        text: textParts.join(' '),
        tokens: tokens.slice(1)  // for advanced inspection
      },
      end: p
    };
  }

  // Untagged
  return {
    status: PARSE.OK,
    response: {
      kind: RESP.UNTAGGED,
      data: tokens
    },
    end: p
  };
}

function tokenToText(tok) {
  if (!tok) return '';
  if (tok.type === TOK.ATOM || tok.type === TOK.QUOTED) return String(tok.value);
  if (tok.type === TOK.NUMBER) return String(tok.value);
  if (tok.type === TOK.NIL) return 'NIL';
  if (tok.type === TOK.LITERAL) return u8ToStr(tok.value);
  if (tok.type === 'respcode') return '[' + tok.value + ']';
  return '';
}


// ============================================================
//  Serializers (SHARED by server responses + client commands)
// ============================================================

// Re-matched against atom-chars: decides whether a string can be sent as raw atom,
// needs quoting, or needs to be sent as a literal.
const RE_ATOM_SAFE = /^[A-Za-z0-9!#$&'+\-\.\/:;<=>?@\[\]^_`|~]+$/;

// quoteString — serialize a string, choosing the right encoding:
//   - Empty → ""
//   - Atom-safe ASCII → as-is (caller decides; usually we quote to be safe)
//   - Printable ASCII without CR/LF/backslash/quote → "..."
//   - Anything else (CR/LF, non-ASCII, long) → {N}\r\n<bytes>
//
// Returns a string suitable for direct concatenation into output.
function quoteString(str) {
  if (str === null || str === undefined) return 'NIL';
  str = String(str);
  if (str.length === 0) return '""';

  let needLiteral = false;
  let needQuote = false;
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    if (c === CR || c === LF || c === 0) { needLiteral = true; break; }
    if (c > 127) { needLiteral = true; break; }
    if (c < 32) { needLiteral = true; break; }
    if (c === DQUOTE || c === BACKSLASH) needQuote = true;
    if (c === SP || c === LPAREN || c === RPAREN || c === LBRACE || c === RBRACKET) needQuote = true;
  }

  if (needLiteral) {
    // Literal: compute byte length (UTF-8 safe)
    let u8 = toU8(str);
    return '{' + u8.length + '}\r\n' + u8ToStr(u8);
  }

  if (needQuote) {
    let escaped = str.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    return '"' + escaped + '"';
  }

  // Always quote for safety (atom vs quoted is semantically important)
  return '"' + str + '"';
}

// atomString — caller knows the value is atom-safe (flag names, keywords, etc.).
// No escaping done. If not atom-safe, caller should use quoteString.
function atomString(str) {
  return String(str);
}

// serializeValue — generic serializer for a value that might be string/number/null/array/Uint8Array.
function serializeValue(val) {
  if (val === null || val === undefined) return 'NIL';
  if (typeof val === 'number') return String(val);
  if (typeof val === 'string') return quoteString(val);
  if (Array.isArray(val)) return serializeList(val);
  if (val instanceof Uint8Array) {
    // Send as literal
    return '{' + val.length + '}\r\n' + u8ToStr(val);
  }
  // Object with explicit {type, value} — respect type
  if (val && typeof val === 'object' && val.type) {
    if (val.type === TOK.ATOM)   return atomString(val.value);
    if (val.type === TOK.QUOTED) return quoteString(val.value);
    if (val.type === TOK.NUMBER) return String(val.value);
    if (val.type === TOK.NIL)    return 'NIL';
    if (val.type === TOK.LITERAL) {
      let bytes = val.value instanceof Uint8Array ? val.value : toU8(String(val.value));
      return '{' + bytes.length + '}\r\n' + u8ToStr(bytes);
    }
    if (val.type === TOK.LIST) return serializeList(val.value);
  }
  return quoteString(String(val));
}

function serializeList(items) {
  let out = '(';
  for (let i = 0; i < items.length; i++) {
    if (i > 0) out += ' ';
    out += serializeValue(items[i]);
  }
  return out + ')';
}


// ============================================================
//  Server response builders (server → client)
// ============================================================

// buildTagged — final response to a tagged command.
//   status: 'OK' | 'NO' | 'BAD'
//   code:   optional response code (string, rendered as [CODE])
function buildTagged(tag, status, text, code) {
  let out = tag + ' ' + status + ' ';
  if (code) out += '[' + code + '] ';
  out += (text || '') + '\r\n';
  return out;
}

// buildUntagged — untagged response. data is a raw string (caller pre-serializes it).
// For commonly-used responses, see helpers below.
function buildUntagged(data) {
  return '* ' + data + '\r\n';
}

// buildContinuation — "+ ..." to tell sender to proceed with literal or authentication step.
function buildContinuation(text) {
  return '+ ' + (text || 'Ready') + '\r\n';
}

// --- Convenience builders for common untagged responses ---

function buildCapability(capabilities) {
  return buildUntagged('CAPABILITY ' + capabilities.join(' '));
}

function buildExists(count) {
  return buildUntagged(count + ' EXISTS');
}

function buildRecent(count) {
  return buildUntagged(count + ' RECENT');
}

function buildExpunge(seq) {
  return buildUntagged(seq + ' EXPUNGE');
}

function buildFlags(flags) {
  return buildUntagged('FLAGS ' + serializeList(flags.map(function(f) {
    return { type: TOK.ATOM, value: f };
  })));
}

// FETCH response: "* N FETCH (attr1 val1 attr2 val2 ...)"
// attrs is an array of [name, value] pairs.
function buildFetch(seq, attrs) {
  let parts = [];
  for (let i = 0; i < attrs.length; i++) {
    parts.push(attrs[i][0] + ' ' + serializeValue(attrs[i][1]));
  }
  return buildUntagged(seq + ' FETCH (' + parts.join(' ') + ')');
}

// LIST response: "* LIST (\HasNoChildren) "/" "INBOX""
function buildList(attrs, delimiter, name) {
  let attrList = '(' + attrs.join(' ') + ')';
  let delim = delimiter === null ? 'NIL' : quoteString(delimiter);
  return buildUntagged('LIST ' + attrList + ' ' + delim + ' ' + quoteString(name));
}


// ============================================================
//  Client command builders (client → server)
// ============================================================

// buildCommand — serialize a command from client to server.
//
// args may contain:
//   - strings         → quoteString
//   - numbers         → atom
//   - arrays          → list
//   - Uint8Array      → literal (used for APPEND body)
//   - { type, value } → explicit type (atom/quoted/literal/list)
//
// Returns the full command line including CRLF.
// If any arg serializes to a literal, the caller (session) handles the continuation dance.
function buildCommand(tag, command, args) {
  let out = tag + ' ' + command;
  if (args && args.length > 0) {
    for (let i = 0; i < args.length; i++) {
      out += ' ' + serializeValue(args[i]);
    }
  }
  out += '\r\n';
  return out;
}

// buildCommandRaw — for commands that need specific formatting that buildCommand doesn't support.
// Caller passes the fully-formatted tail after "tag command ". CRLF is added.
function buildCommandRaw(tag, command, rawTail) {
  return tag + ' ' + command + (rawTail ? ' ' + rawTail : '') + '\r\n';
}


// ============================================================
//  Tag generation helper (for client sessions)
// ============================================================

function makeTagGenerator(prefix) {
  let n = 0;
  prefix = prefix || 'A';
  return function() {
    n++;
    // Format as prefix + zero-padded 4-digit number (A0001, A0002, ...)
    let s = String(n);
    while (s.length < 4) s = '0' + s;
    return prefix + s;
  };
}


// ============================================================
//  Exports
// ============================================================

export {
  // Constants
  TOK,
  PARSE,
  RESP,
  STATUS,

  // Byte helpers
  isAtomChar,
  isAstringChar,
  skipSP,
  findCRLFfrom,

  // Tokenizer primitives (shared)
  readAtom,
  readAstringAtom,
  readQuoted,
  readLiteral,
  readList,
  readBracketed,
  readValue,       // primary value reader (atom/quoted/literal/list/atom+section)
  readAnyToken,    // alias for readValue (kept for semantic clarity)

  // High-level parsers
  parseCommand,    // server-side
  parseResponse,   // client-side

  // Serializers (shared)
  quoteString,
  atomString,
  serializeValue,
  serializeList,

  // Server response builders
  buildTagged,
  buildUntagged,
  buildContinuation,
  buildCapability,
  buildExists,
  buildRecent,
  buildExpunge,
  buildFlags,
  buildFetch,
  buildList,

  // Client command builders
  buildCommand,
  buildCommandRaw,
  makeTagGenerator
};
