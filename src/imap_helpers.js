// ============================================================================
//  imap_helpers.js
// ----------------------------------------------------------------------------
//  Pure, stateless helpers for IMAP. Everything here is:
//    • module-level (no instance state, no closures over sessions)
//    • free of I/O (no sockets, no timers, no DNS)
//    • unit-testable in isolation
//
//  Contains: public constants (SPECIAL_USE, FLAGS), flag/special-use
//  normalization, LIST wildcard matching, sequence-set parsing/formatting,
//  UID compression, INTERNALDATE formatting, BODY[section] parsing, SEARCH
//  criteria parsing, ENVELOPE/BODYSTRUCTURE builders (from MIME trees and
//  from cached JSON), and raw-message → JSON extractors.
//
//  The IMAPSession class (in imap_session.js) imports the functions it needs
//  from here. Developers using the library can also import selected helpers
//  (e.g. `extractEnvelope`, `compressUids`) directly.
// ============================================================================

import { parseMessageTree, parseAddressList } from './message.js';
import flatRanges from 'flat-ranges';


// ============================================================
//  Constants
// ============================================================

// Public constants for special-use folder attributes (RFC 6154).
// Developers can use these to avoid typos and get IDE autocomplete.
const SPECIAL_USE = {
  ALL:     '\\All',
  ARCHIVE: '\\Archive',
  DRAFTS:  '\\Drafts',
  FLAGGED: '\\Flagged',
  JUNK:    '\\Junk',
  SENT:    '\\Sent',
  TRASH:   '\\Trash'
};

// Internal: map of lowercase bare name → canonical wire form.
// Used to normalize whatever the developer provides (`'Sent'`, `'sent'`, `'\\Sent'`, etc.).
const SPECIAL_USE_CANONICAL = {
  'all':     '\\All',
  'archive': '\\Archive',
  'drafts':  '\\Drafts',
  'flagged': '\\Flagged',
  'junk':    '\\Junk',
  'sent':    '\\Sent',
  'trash':   '\\Trash'
};

// Public constants for standard message flags (RFC 3501 §2.3.2).
const FLAGS = {
  ANSWERED: 'Answered',
  FLAGGED:  'Flagged',
  DELETED:  'Deleted',
  SEEN:     'Seen',
  DRAFT:    'Draft',
  RECENT:   'Recent'  // server-set only; clients cannot change
};

// Internal: set of bare names that are system flags (must have '\' prefix on wire).
const SYSTEM_FLAG_NAMES = {
  'answered': true, 'flagged': true, 'deleted': true,
  'seen': true, 'draft': true, 'recent': true
};

// Default flag list returned in SELECT/EXAMINE responses when developer doesn't supply one.
const DEFAULT_FLAGS = ['Seen', 'Answered', 'Flagged', 'Deleted', 'Draft'];


function normalizeSpecialUse(input) {
  if (!input) return null;
  let clean = String(input).replace(/^\\/, '').toLowerCase();
  return SPECIAL_USE_CANONICAL[clean] || null;
}

// Normalize a flag from developer input → bare name (no backslash).
// 'Seen' → 'Seen', '\\Seen' → 'Seen', '\\seen' → 'Seen' (canonical case).
// For non-system flags (keywords), preserves developer's exact string.
function normalizeFlag(input) {
  if (input === null || input === undefined) return null;
  let s = String(input);
  let bare = s.replace(/^\\/, '');
  let lower = bare.toLowerCase();
  if (SYSTEM_FLAG_NAMES[lower]) {
    // Canonical capitalization for system flags
    return bare.charAt(0).toUpperCase() + lower.slice(1);
  }
  return bare;  // keyword — keep as-is
}

// Serialize a flag for wire output — adds backslash for system flags.
// 'Seen' → '\\Seen'. 'Important' → 'Important'. '*' → '\\*' (permanent-flags wildcard).
function serializeFlag(flag) {
  if (flag === null || flag === undefined) return '';
  let s = String(flag);
  // Already has backslash (e.g. developer passed '\\Sent')
  if (s.charAt(0) === '\\') return s;
  // Wildcard for PERMANENTFLAGS
  if (s === '*') return '\\*';
  // System flag?
  if (SYSTEM_FLAG_NAMES[s.toLowerCase()]) {
    return '\\' + s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();
  }
  return s;  // keyword — no prefix
}

// Warn (once) if the developer returned flags with a leading backslash in a
// storage-handler callback. The library accepts both forms, but clean names
// ('Seen', 'Flagged') are idiomatic — they make the developer's code read
// like a data contract, not an IMAP dump. Backslashed values work but
// suggest confusion about the direction of normalization.
//
// The warning fires at most once per process to avoid log-spam; after that
// the flags still work, just silently. We check equality of the backslashed
// form to avoid false positives on legitimate custom keywords that happen
// to start with a backslash.
let _flagHygieneWarned = false;
function checkFlagsHygiene(flags, source) {
  if (_flagHygieneWarned) return;
  if (!Array.isArray(flags)) return;
  for (let i = 0; i < flags.length; i++) {
    let f = flags[i];
    if (typeof f !== 'string' || f.charAt(0) !== '\\') continue;
    let bare = f.slice(1).toLowerCase();
    if (!SYSTEM_FLAG_NAMES[bare]) continue;   // custom keyword — leave alone
    _flagHygieneWarned = true;
    try {
      // eslint-disable-next-line no-console
      console.warn(
        '[email-server] ' + (source || 'handler') + ' returned system flag ' +
        JSON.stringify(f) + ' with a leading backslash. Use the clean name ' +
        JSON.stringify(f.slice(1)) + ' instead — the library adds the ' +
        'backslash on the wire. Both forms work, but clean names are ' +
        'idiomatic. (This warning fires once per process.)'
      );
    } catch (e) { /* best-effort */ }
    return;
  }
}

// Serialize a list of flags as an IMAP parenthesized list.
// ['Seen', 'Flagged']  →  '(\\Seen \\Flagged)'
function serializeFlagList(flags) {
  if (!flags || flags.length === 0) return '()';
  let parts = [];
  for (let i = 0; i < flags.length; i++) parts.push(serializeFlag(flags[i]));
  return '(' + parts.join(' ') + ')';
}

// Build a matcher function from an IMAP LIST pattern.
// Wildcards: '*' matches any sequence (incl. delimiter), '%' matches any sequence
// except delimiter. All other chars are literal.
// Reference is prepended to pattern before matching (per RFC 3501 §6.3.8).
const RE_REGEX_META = /[\\^$.+?()[\]{}|]/g;

function makeWildcardMatcher(reference, pattern, delimiter) {
  let full = (reference || '') + (pattern || '');
  let delimEsc = delimiter.replace(RE_REGEX_META, '\\$&');
  let re = '^';
  for (let i = 0; i < full.length; i++) {
    let c = full.charAt(i);
    if (c === '*')      re += '.*';
    else if (c === '%') re += '(?:(?!' + delimEsc + ').)*';
    else                re += c.replace(RE_REGEX_META, '\\$&');
  }
  re += '$';
  let rx = new RegExp(re);
  return function(name) { return rx.test(name); };
}

// Decide whether a folder has hierarchical children, given the full list of folder names
// and the delimiter. Returns true if any other name starts with `<this>+<delimiter>`.
function hasChildren(folderName, allNames, delimiter) {
  let prefix = folderName + delimiter;
  for (let i = 0; i < allNames.length; i++) {
    if (allNames[i] !== folderName && allNames[i].indexOf(prefix) === 0) return true;
  }
  return false;
}

// Parse an IMAP sequence set like "1:10,15,20:*" into normalized ranges.
// `context` provides:
//   - isUid: boolean — if true, '*' stays as Infinity (caller's storage knows max UID)
//            if false, '*' resolves to `total` immediately (since we know total from openFolder)
//   - total: number — used when isUid is false
//
// Returns { ranges: [{from, to}], error: null } or { ranges: null, error: 'reason' }
// Parse an IMAP sequence-set string into a flat half-open ranges array.
//
// Returns {ranges: [from1, to1, from2, to2, ...], error}.
//
// The format matches flat-ranges exactly:
//   • flat array (no {from,to} objects)
//   • half-open [from, to) — `to` is exclusive
//   • "1:10" (inclusive) becomes [1, 11]
//   • "5" becomes [5, 6]
//   • Overlapping/adjacent ranges are merged automatically (via flatRanges.add)
//
// Special cases:
//   • "*" in UID context with unknown max → Infinity (upper bound)
//   • "*" in seq context with known `total` → total (resolved immediately)
//   • Reversed ranges like "5:1" are normalized to "1:5"
function parseSequenceSet(str, ctx) {
  if (!str) return { ranges: [], error: 'empty' };
  let isUid = !!(ctx && ctx.isUid);
  let total = ctx && ctx.total != null ? ctx.total : 0;

  let parts = String(str).split(',');
  let ranges = [];
  for (let i = 0; i < parts.length; i++) {
    let p = parts[i].trim();
    if (!p) return { ranges: [], error: 'empty range' };

    let from, to;
    let colon = p.indexOf(':');
    if (colon < 0) {
      // Single number or "*"
      let n = parseOne(p, isUid, total);
      if (n === null) return { ranges: [], error: 'bad number: ' + p };
      from = n;
      to   = n === Infinity ? Infinity : n + 1;
    } else {
      let a = parseOne(p.slice(0, colon), isUid, total);
      let b = parseOne(p.slice(colon + 1), isUid, total);
      if (a === null || b === null) return { ranges: [], error: 'bad range: ' + p };
      // Normalize: "5:1" == "1:5"; Infinity is always the upper bound.
      if (b !== Infinity && a !== Infinity && a > b) { let tmp = a; a = b; b = tmp; }
      if (a === Infinity) { a = b; b = Infinity; }
      from = a;
      to   = b === Infinity ? Infinity : b + 1;
    }

    // flatRanges.add merges overlapping/adjacent ranges automatically.
    // So "FETCH 1:10,5:15" produces [1, 16] instead of [1, 11, 5, 16].
    flatRanges.add(ranges, [from, to]);
  }
  return { ranges: ranges, error: null };
}

function parseOne(str, isUid, total) {
  str = str.trim();
  if (str === '*') return isUid ? Infinity : total;
  if (!/^\d+$/.test(str)) return null;
  let n = parseInt(str, 10);
  return n > 0 ? n : null;
}

// Test whether a number falls within any range of a flat half-open array.
// Delegates to flatRanges.contains (binary search, O(log n), zero allocation).
//   rangesContain([1, 11, 20, 26], 5)  → true
//   rangesContain([1, 11, 20, 26], 11) → false  (exclusive upper)
//   rangesContain([1, 11, 20, 26], 22) → true
function rangesContain(ranges, n) {
  return flatRanges.contains(ranges, n);
}

// Compress a list of UIDs (or seq numbers) into an IMAP sequence-set string.
//
// By default sorts + merges all adjacent numbers into minimal ranges:
//   compressUids([1, 2, 3, 5, 7, 8])          → "1:3,5,7:8"
//   compressUids([105, 101])                  → "101,105"
//
// With {preserveOrder: true}, keeps the input order. Only strictly increasing
// consecutive runs are collapsed into ranges. Required for COPYUID responses
// (RFC 4315) where src[i] ↔ dst[i] positional correspondence must survive the
// round-trip through sequence-set encoding:
//   compressUids([101, 102, 103], {preserveOrder: true})  → "101:103"
//   compressUids([503, 501, 502], {preserveOrder: true})  → "503,501:502"
//   compressUids([105, 101],      {preserveOrder: true})  → "105,101"
function compressUids(uids, opts) {
  if (!uids || uids.length === 0) return '';

  if (opts && opts.preserveOrder) {
    let parts = [];
    let i = 0;
    while (i < uids.length) {
      let start = uids[i];
      let j = i + 1;
      while (j < uids.length && uids[j] === uids[j - 1] + 1) j++;
      let end = uids[j - 1];
      parts.push(start === end ? String(start) : start + ':' + end);
      i = j;
    }
    return parts.join(',');
  }

  // Sorted + merged path — uses flatRanges.add for automatic merging
  let ranges = [];
  for (let i = 0; i < uids.length; i++) {
    let u = uids[i];
    flatRanges.add(ranges, [u, u + 1]);
  }
  return formatRanges(ranges);
}

// Build an [COPYUID <uidValidity> <srcSet> <dstSet>] response code from a
// developer-supplied mapping. Returns null if there's nothing to advertise.
//
// Accepts two input shapes (backward-compatible):
//   • Array: [{srcUid, dstUid}, ...]   — COPYUID omitted (no uidValidity)
//   • Object: { dstUidValidity, mapping: [{srcUid, dstUid}, ...] }
//
// Sorts mapping by srcUid so the src set is naturally compressed, then
// emits the dst set in that same order using {preserveOrder:true} to preserve
// the positional correspondence required by RFC 4315.
function buildCopyUidCode(result) {
  if (!result) return null;
  let mapping, dstUidValidity;
  if (Array.isArray(result)) {
    mapping = result;
    dstUidValidity = null;
  } else {
    mapping = result.mapping;
    dstUidValidity = result.dstUidValidity;
  }
  if (!dstUidValidity || !mapping || mapping.length === 0) return null;

  // Sort by srcUid — src compresses to clean ranges, dst follows the new order
  let sorted = mapping.slice().sort(function(a, b) { return a.srcUid - b.srcUid; });
  let srcList = sorted.map(function(m) { return m.srcUid; });
  let dstList = sorted.map(function(m) { return m.dstUid; });

  return 'COPYUID ' + dstUidValidity + ' ' +
         compressUids(srcList, { preserveOrder: true }) + ' ' +
         compressUids(dstList, { preserveOrder: true });
}

// Format a Date object as IMAP INTERNALDATE: "14-Jul-2026 10:30:00 +0200"
const MONTH_NAMES = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
function formatInternalDate(date) {
  if (!(date instanceof Date)) date = new Date(date || Date.now());
  let pad = function(n) { return n < 10 ? '0' + n : '' + n; };
  let tzMin = -date.getTimezoneOffset();
  let tzSign = tzMin < 0 ? '-' : '+';
  let tzAbs = Math.abs(tzMin);
  let tzStr = tzSign + pad(Math.floor(tzAbs / 60)) + pad(tzAbs % 60);
  return pad(date.getDate()) + '-' + MONTH_NAMES[date.getMonth()] + '-' + date.getFullYear() + ' ' +
    pad(date.getHours()) + ':' + pad(date.getMinutes()) + ':' + pad(date.getSeconds()) + ' ' + tzStr;
}

// Parse IMAP INTERNALDATE (or similar) to Date object. Lenient.
function parseInternalDate(str) {
  if (!str) return null;
  let m = /^(\d{1,2})-([A-Za-z]{3})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?$/.exec(String(str).trim());
  if (!m) return null;
  let month = MONTH_NAMES.indexOf(m[2]);
  if (month < 0) return null;
  let d = new Date(Date.UTC(parseInt(m[3]), month, parseInt(m[1]), parseInt(m[4]), parseInt(m[5]), parseInt(m[6])));
  if (m[7]) {
    let sign = m[7].charAt(0) === '-' ? 1 : -1;  // invert: "+0200" means 2h ahead, so UTC is 2h earlier
    let h = parseInt(m[7].slice(1, 3), 10);
    let mn = parseInt(m[7].slice(3, 5), 10);
    d = new Date(d.getTime() + sign * (h * 60 + mn) * 60000);
  }
  return d;
}


// Parse the contents of a BODY[...] section specifier into a structured form.
// Input is whatever appeared between '[' and ']' (possibly empty string).
// Returns { part, type, fields } or null on parse failure.
//
// Examples:
//   ""                                  → { part: null, type: null, fields: null }     // whole body
//   "HEADER"                            → { part: null, type: 'HEADER', fields: null }
//   "TEXT"                              → { part: null, type: 'TEXT', fields: null }
//   "HEADER.FIELDS (FROM SUBJECT)"      → { part: null, type: 'HEADER.FIELDS', fields: ['FROM','SUBJECT'] }
//   "HEADER.FIELDS.NOT (X-FOO)"         → { part: null, type: 'HEADER.FIELDS.NOT', fields: ['X-FOO'] }
//   "1"                                 → { part: [1], type: null, fields: null }       // whole part
//   "1.2.HEADER"                        → { part: [1,2], type: 'HEADER' }
//   "1.2.MIME"                          → { part: [1,2], type: 'MIME' }
//   "1.TEXT"                            → { part: [1], type: 'TEXT' }
function parseBodySection(str) {
  let result = { part: null, type: null, fields: null };
  if (!str) return result;

  let s = String(str).trim();

  // Try to consume a leading part path: "1", "1.2", "1.2.3"
  let partPath = [];
  while (s.length) {
    let m = /^(\d+)(\.|$)/.exec(s);
    if (!m) break;
    partPath.push(parseInt(m[1], 10));
    s = s.slice(m[1].length + (m[2] === '.' ? 1 : 0));
    if (m[2] === '') break;
  }
  if (partPath.length > 0) result.part = partPath;

  // Remainder is the text type (if any)
  if (!s) return result;

  let m;
  if ((m = /^HEADER\.FIELDS\.NOT\s*\((.*)\)$/i.exec(s))) {
    result.type = 'HEADER.FIELDS.NOT';
    result.fields = m[1].trim().split(/\s+/).filter(Boolean).map(function(f) { return f.toUpperCase(); });
  } else if ((m = /^HEADER\.FIELDS\s*\((.*)\)$/i.exec(s))) {
    result.type = 'HEADER.FIELDS';
    result.fields = m[1].trim().split(/\s+/).filter(Boolean).map(function(f) { return f.toUpperCase(); });
  } else if (/^HEADER$/i.test(s)) {
    result.type = 'HEADER';
  } else if (/^TEXT$/i.test(s)) {
    result.type = 'TEXT';
  } else if (/^MIME$/i.test(s)) {
    result.type = 'MIME';
  } else {
    return null;  // parse error
  }
  return result;
}

// Build the response form of a BODY[...] data-item name.
// Per RFC 3501 §7.4.2: PEEK is stripped, partial length is stripped (offset kept).
function buildBodyResponseName(section, partial) {
  let name = 'BODY[' + (section || '') + ']';
  if (partial) name += '<' + partial.offset + '>';
  return name;
}


// ============================================================
//  SEARCH criteria parsing (Phase 3d)
//
//  Parses the IMAP SEARCH keyword/operator stream into a JS tree. Top-level
//  always wrapped in {op:'and', children:[...]} so developer's matcher loop
//  is uniform. NOT/OR handled recursively; UNSEEN etc. are normalized to
//  {op:'not', child:{op:'seen'}} so developer handles fewer cases.
// ============================================================

const SEARCH_MONTHS = { JAN:0,FEB:1,MAR:2,APR:3,MAY:4,JUN:5,JUL:6,AUG:7,SEP:8,OCT:9,NOV:10,DEC:11 };
const SEARCH_MONTH_NAMES = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

// Parse IMAP SEARCH date format "1-Feb-2026" → JS Date (UTC). Returns null on fail.
function parseSearchDate(str) {
  if (!str) return null;
  let m = /^(\d{1,2})-([A-Za-z]{3})-(\d{4})$/.exec(String(str).trim());
  if (!m) return null;
  let mo = SEARCH_MONTHS[m[2].toUpperCase()];
  if (mo === undefined) return null;
  let d = parseInt(m[1], 10), y = parseInt(m[3], 10);
  return new Date(Date.UTC(y, mo, d));
}

// Format JS Date → IMAP SEARCH date "1-Feb-2026"
function formatSearchDate(date) {
  if (!(date instanceof Date)) date = new Date(date);
  return date.getUTCDate() + '-' + SEARCH_MONTH_NAMES[date.getUTCMonth()] + '-' + date.getUTCFullYear();
}

// Parse a sequence-set string used inside SEARCH criteria (e.g. "1:10,15").
// Returns a flat half-open array, or null on parse error.
function parseSearchRanges(str, isUid, total) {
  let r = parseSequenceSet(str, { isUid: isUid, total: total || 0 });
  return r.error ? null : r.ranges;
}

// Format a flat half-open ranges array back to an IMAP sequence-set string.
//   formatRanges([1, 11])            → "1:10"
//   formatRanges([5, 6, 10, 11])     → "5,10"
//   formatRanges([1, 11, 20, 26])    → "1:10,20:25"
//   formatRanges([100, Infinity])    → "100:*"
function formatRanges(ranges) {
  if (!ranges || ranges.length === 0) return '';
  let parts = [];
  for (let i = 0; i < ranges.length; i += 2) {
    let from = ranges[i];
    let toExcl = ranges[i + 1];
    if (toExcl === Infinity) {
      parts.push(from + ':*');
    } else {
      let toIncl = toExcl - 1;
      parts.push(from === toIncl ? String(from) : from + ':' + toIncl);
    }
  }
  return parts.join(',');
}

// Extract a string value from a token, handling atom/quoted/literal/number uniformly.
function tokenToString(tok) {
  if (!tok) return '';
  if (tok.type === 'literal') return typeof tok.value === 'string' ? tok.value : Buffer.from(tok.value).toString('utf-8');
  if (tok.value === null || tok.value === undefined) return '';
  return String(tok.value);
}

// Parse zero-or-more SEARCH criteria (implicitly AND'd) starting at tokens[start].
// Returns { node, end } where node is the AND-wrapped tree and end is the consumed position.
function parseSearchCriteria(tokens, start, total) {
  let children = [];
  let pos = start;
  while (pos < tokens.length) {
    let r = parseOneCriterion(tokens, pos, total);
    if (!r) break;
    children.push(r.node);
    pos = r.end;
  }
  return { node: { op: 'and', children: children }, end: pos };
}

// Parse exactly one criterion (which may itself be complex: parens, NOT, OR).
function parseOneCriterion(tokens, pos, total) {
  if (pos >= tokens.length) return null;
  let tok = tokens[pos];

  // Parenthesized group: treat inner tokens as a sub-criteria list (implicit AND inside)
  if (tok.type === 'list') {
    let inner = parseSearchCriteria(tok.value, 0, total);
    return { node: inner.node, end: pos + 1 };
  }

  let key = String(tok.value || '').toUpperCase();

  // Simple flag predicates (no args)
  switch (key) {
    case 'ALL':        return { node: { op: 'all' },      end: pos + 1 };
    case 'ANSWERED':   return { node: { op: 'answered' }, end: pos + 1 };
    case 'DELETED':    return { node: { op: 'deleted' },  end: pos + 1 };
    case 'DRAFT':      return { node: { op: 'draft' },    end: pos + 1 };
    case 'FLAGGED':    return { node: { op: 'flagged' },  end: pos + 1 };
    case 'NEW':        return { node: { op: 'new' },      end: pos + 1 };
    case 'OLD':        return { node: { op: 'old' },      end: pos + 1 };
    case 'RECENT':     return { node: { op: 'recent' },   end: pos + 1 };
    case 'SEEN':       return { node: { op: 'seen' },     end: pos + 1 };
    // Negations — normalize to NOT(x) so developer handles fewer cases
    case 'UNANSWERED': return { node: { op: 'not', child: { op: 'answered' } }, end: pos + 1 };
    case 'UNDELETED':  return { node: { op: 'not', child: { op: 'deleted' } },  end: pos + 1 };
    case 'UNDRAFT':    return { node: { op: 'not', child: { op: 'draft' } },    end: pos + 1 };
    case 'UNFLAGGED':  return { node: { op: 'not', child: { op: 'flagged' } },  end: pos + 1 };
    case 'UNSEEN':     return { node: { op: 'not', child: { op: 'seen' } },     end: pos + 1 };
  }

  // Single-arg string predicates
  let strKeys = { BCC:'bcc', BODY:'body', CC:'cc', FROM:'from', SUBJECT:'subject', TEXT:'text', TO:'to' };
  if (strKeys[key] && pos + 1 < tokens.length) {
    return { node: { op: strKeys[key], value: tokenToString(tokens[pos + 1]) }, end: pos + 2 };
  }

  // Keyword / UNKEYWORD — flag value (bare name, no backslash)
  if (key === 'KEYWORD' && pos + 1 < tokens.length) {
    return { node: { op: 'keyword', value: normalizeFlag(tokens[pos + 1].value) }, end: pos + 2 };
  }
  if (key === 'UNKEYWORD' && pos + 1 < tokens.length) {
    return { node: { op: 'not', child: { op: 'keyword', value: normalizeFlag(tokens[pos + 1].value) } }, end: pos + 2 };
  }

  // HEADER <name> <value>
  if (key === 'HEADER' && pos + 2 < tokens.length) {
    return { node: { op: 'header', name: tokenToString(tokens[pos + 1]), value: tokenToString(tokens[pos + 2]) }, end: pos + 3 };
  }

  // Date predicates
  let dateKeys = {
    BEFORE:'before', ON:'on', SINCE:'since',
    SENTBEFORE:'sentBefore', SENTON:'sentOn', SENTSINCE:'sentSince'
  };
  if (dateKeys[key] && pos + 1 < tokens.length) {
    return { node: { op: dateKeys[key], date: parseSearchDate(tokenToString(tokens[pos + 1])) }, end: pos + 2 };
  }

  // Size predicates
  if ((key === 'LARGER' || key === 'SMALLER') && pos + 1 < tokens.length) {
    let n = tokens[pos + 1].type === 'number' ? tokens[pos + 1].value : parseInt(tokenToString(tokens[pos + 1]), 10);
    return { node: { op: key.toLowerCase(), value: n }, end: pos + 2 };
  }

  // WITHIN extension (RFC 5032): YOUNGER <n> and OLDER <n>, with n = seconds.
  // Semantics: YOUNGER 604800 = delivered within the last 7 days.
  // These are internaldate-relative; we compute the cutoff at search time so
  // the evaluator matches against internalDate, same as SINCE/BEFORE.
  if ((key === 'YOUNGER' || key === 'OLDER') && pos + 1 < tokens.length) {
    let seconds = tokens[pos + 1].type === 'number' ?
                  tokens[pos + 1].value :
                  parseInt(tokenToString(tokens[pos + 1]), 10);
    if (isNaN(seconds) || seconds < 0) return null;
    return { node: { op: key.toLowerCase(), seconds: seconds }, end: pos + 2 };
  }

  // CONDSTORE (RFC 7162 §3.1.5): "SEARCH MODSEQ <mod-sequence>" — bare form.
  // We also accept the "SEARCH MODSEQ <entry-name> <entry-type> <mod-sequence>"
  // form for forward-compatibility by skipping the entry-name/type tokens.
  if (key === 'MODSEQ' && pos + 1 < tokens.length) {
    let nxt = tokens[pos + 1];
    // Detect the 3-arg form: entry-name is a quoted "/flags/..." string
    if (nxt.type === 'quoted' && pos + 3 < tokens.length) {
      let val = tokens[pos + 3];
      let n = val.type === 'number' ? val.value : parseInt(tokenToString(val), 10);
      return { node: { op: 'modseq', value: n }, end: pos + 4 };
    }
    let n = nxt.type === 'number' ? nxt.value : parseInt(tokenToString(nxt), 10);
    return { node: { op: 'modseq', value: n }, end: pos + 2 };
  }

  // UID set
  if (key === 'UID' && pos + 1 < tokens.length) {
    let r = parseSearchRanges(tokenToString(tokens[pos + 1]), true, total);
    if (r === null) return null;
    return { node: { op: 'uid', ranges: r }, end: pos + 2 };
  }

  // Boolean operators
  if (key === 'NOT') {
    let inner = parseOneCriterion(tokens, pos + 1, total);
    if (!inner) return null;
    return { node: { op: 'not', child: inner.node }, end: inner.end };
  }
  if (key === 'OR') {
    let left = parseOneCriterion(tokens, pos + 1, total);
    if (!left) return null;
    let right = parseOneCriterion(tokens, left.end, total);
    if (!right) return null;
    return { node: { op: 'or', children: [left.node, right.node] }, end: right.end };
  }

  // Implicit sequence-set: bare token that's all digits/colons/commas/asterisks
  if (/^[\d*,:]+$/.test(key)) {
    let r = parseSearchRanges(key, false, total);
    if (r === null) return null;
    return { node: { op: 'seq', ranges: r }, end: pos + 1 };
  }

  // Unknown criterion — signal end of parsing (caller decides what to do)
  return null;
}


// ============================================================
//  ENVELOPE and BODYSTRUCTURE builders (Phase 3c)
//
//  These take a parsed tree (from parseMessageTree) and produce IMAP token trees
//  that serialize to the RFC 3501 §7.4.2 ENVELOPE / BODYSTRUCTURE forms.
//
//  Strings are sent raw (unprocessed) — encoded-words in Subject / display names
//  are preserved exactly as they appear in the source message, matching the
//  behaviour of Dovecot/Cyrus/Gmail. Clients decode on their side.
// ============================================================

// Small factories for IMAP tokens (the wire serializer understands these)
function tStr(s)    { return s === null || s === undefined ? { type: 'nil' } : { type: 'quoted', value: String(s) }; }
function tNum(n)    { return { type: 'number', value: n }; }
function tList(arr) { return { type: 'list',   value: arr }; }
function tNil()     { return { type: 'nil' }; }

// Find the first occurrence of a header by name (case-insensitive). Returns value or null.
function headerOrNull(headers, name) {
  let low = String(name).toLowerCase();
  for (let i = 0; i < headers.length; i++) {
    if (headers[i].name.toLowerCase() === low) return headers[i].value;
  }
  return null;
}

// Build the 4-tuple (name, adl, mailbox, host) for one address
function addrTuple(name, adl, mailbox, host) {
  return tList([tStr(name), tStr(adl), tStr(mailbox), tStr(host)]);
}

// Convert an address-header value string into an IMAP address list token, or NIL
// if the header is absent / empty.
// Groups are expanded into the RFC 3501 form: a (NIL NIL "group" NIL) start-marker,
// followed by the member tuples, followed by a (NIL NIL NIL NIL) end-marker.
function addrListOrNil(headerValue) {
  if (!headerValue) return tNil();
  let addrs = parseAddressList(headerValue);
  if (!addrs || addrs.length === 0) return tNil();

  let list = [];
  for (let i = 0; i < addrs.length; i++) {
    let a = addrs[i];
    if (a.group !== undefined) {
      list.push(addrTuple(null, null, a.group, null));
      for (let j = 0; j < a.members.length; j++) {
        let m = a.members[j];
        list.push(addrTuple(m.name, null, m.mailbox, m.host));
      }
      list.push(addrTuple(null, null, null, null));
    } else {
      list.push(addrTuple(a.name, null, a.mailbox, a.host));
    }
  }
  return tList(list);
}

// Build the ENVELOPE list from a parsed tree node. Per RFC 3501 §7.4.2, the 10 fields are:
//   date, subject, from, sender, reply-to, to, cc, bcc, in-reply-to, message-id
// Sender and reply-to default to from when the corresponding header is absent.
function buildEnvelope(tree) {
  let headers  = tree.headers || [];
  let fromRaw  = headerOrNull(headers, 'From');

  return tList([
    tStr(headerOrNull(headers, 'Date')),
    tStr(headerOrNull(headers, 'Subject')),
    addrListOrNil(fromRaw),
    addrListOrNil(headerOrNull(headers, 'Sender')   || fromRaw),
    addrListOrNil(headerOrNull(headers, 'Reply-To') || fromRaw),
    addrListOrNil(headerOrNull(headers, 'To')),
    addrListOrNil(headerOrNull(headers, 'Cc')),
    addrListOrNil(headerOrNull(headers, 'Bcc')),
    tStr(headerOrNull(headers, 'In-Reply-To')),
    tStr(headerOrNull(headers, 'Message-ID'))
  ]);
}

// Turn a {k: v, ...} params map into an IMAP body-fld-param list: (K V K V ...).
// Empty map → NIL.
function paramsOrNil(params) {
  if (!params) return tNil();
  let keys = Object.keys(params);
  if (keys.length === 0) return tNil();
  let flat = [];
  for (let i = 0; i < keys.length; i++) {
    flat.push(tStr(keys[i].toUpperCase()));
    flat.push(tStr(params[keys[i]]));
  }
  return tList(flat);
}

// body-fld-dsp: NIL or (disposition-string disposition-params)
function dispositionOrNil(type, params) {
  if (!type) return tNil();
  return tList([tStr(type.toUpperCase()), paramsOrNil(params)]);
}

// Build BODYSTRUCTURE (if extended=true) or BODY (if extended=false) for a tree node.
// Recursive for multipart and message/rfc822.
function buildBodyStructure(tree, extended) {
  if (tree.contentType && tree.contentType.indexOf('multipart/') === 0 && tree.parts) {
    return buildMultipartBs(tree, extended);
  }
  return buildSinglePartBs(tree, extended);
}

function buildMultipartBs(tree, extended) {
  let list = [];
  for (let i = 0; i < tree.parts.length; i++) {
    list.push(buildBodyStructure(tree.parts[i], extended));
  }
  let subtype = tree.contentType.slice(tree.contentType.indexOf('/') + 1);
  list.push(tStr(subtype.toUpperCase()));

  if (extended) {
    // body-ext-mpart: body-fld-param [SP body-fld-dsp [SP body-fld-lang [SP body-fld-loc]]]
    list.push(paramsOrNil(tree.contentTypeParams));
    list.push(dispositionOrNil(tree.contentDisposition, tree.contentDispositionParams));
    list.push(tStr(tree.contentLanguage));
    list.push(tStr(tree.contentLocation));
  }
  return tList(list);
}

function buildSinglePartBs(tree, extended) {
  let ct       = tree.contentType || 'text/plain';
  let slash    = ct.indexOf('/');
  let type     = slash > 0 ? ct.slice(0, slash) : 'text';
  let subtype  = slash > 0 ? ct.slice(slash + 1) : 'plain';
  let size     = tree.bodyEnd - tree.bodyStart;
  let encoding = (tree.contentTransferEncoding || '7bit').toUpperCase();

  // The seven mandatory fields for any non-multipart body (body-type-basic / text / message)
  let list = [
    tStr(type.toUpperCase()),
    tStr(subtype.toUpperCase()),
    paramsOrNil(tree.contentTypeParams),
    tStr(tree.contentId),
    tStr(tree.contentDescription),
    tStr(encoding),
    tNum(size)
  ];

  // Type-specific additions
  let typeLow = type.toLowerCase();
  let subtypeLow = subtype.toLowerCase();
  if (typeLow === 'text') {
    // body-fld-lines
    list.push(tNum(tree.bodyLines || 0));
  } else if (typeLow === 'message' && subtypeLow === 'rfc822' && tree.parts && tree.parts[0]) {
    // envelope, body-structure, body-fld-lines
    list.push(buildEnvelope(tree.parts[0]));
    list.push(buildBodyStructure(tree.parts[0], extended));
    list.push(tNum(tree.bodyLines || 0));
  }

  if (extended) {
    // body-ext-1part: body-fld-md5 [SP body-fld-dsp [SP body-fld-lang [SP body-fld-loc]]]
    list.push(tStr(tree.contentMd5));
    list.push(dispositionOrNil(tree.contentDisposition, tree.contentDispositionParams));
    list.push(tStr(tree.contentLanguage));
    list.push(tStr(tree.contentLocation));
  }

  return tList(list);
}


// ============================================================
//  JSON → IMAP converters (for cached envelope/bodyStructure)
// ============================================================
//
// These accept plain JSON-serializable objects (the shape returned by
// `extractEnvelope` / `extractBodyStructure`) and produce IMAP tokens.
// The developer stores the JSON shape in their DB once, then returns it
// from `messageEnvelope` / `messageBodyStructure` events — avoiding a
// per-message body fetch.

// Convert an array of { name, email } (or { name, mailbox, host }) address
// objects into an IMAP address-list token. Groups use the RFC 3501 form:
// (NIL NIL "group" NIL) start + members + (NIL NIL NIL NIL) end marker.
function addrListFromJson(addrs) {
  if (!addrs || !Array.isArray(addrs) || addrs.length === 0) return tNil();
  let list = [];
  for (let i = 0; i < addrs.length; i++) {
    let a = addrs[i];
    if (a.group !== undefined) {
      list.push(addrTuple(null, null, a.group, null));
      if (Array.isArray(a.members)) {
        for (let j = 0; j < a.members.length; j++) {
          let m = a.members[j];
          let mailbox = m.mailbox !== undefined ? m.mailbox : splitEmailLocal(m.email);
          let host    = m.host    !== undefined ? m.host    : splitEmailDomain(m.email);
          list.push(addrTuple(m.name || null, null, mailbox, host));
        }
      }
      list.push(addrTuple(null, null, null, null));
    } else {
      // Accept both {name, email} (developer-friendly) and {name, mailbox, host}
      let mailbox = a.mailbox !== undefined ? a.mailbox : splitEmailLocal(a.email);
      let host    = a.host    !== undefined ? a.host    : splitEmailDomain(a.email);
      list.push(addrTuple(a.name || null, null, mailbox, host));
    }
  }
  return tList(list);
}

function splitEmailLocal(email) {
  if (!email) return null;
  let at = String(email).indexOf('@');
  return at >= 0 ? email.slice(0, at) : email;
}
function splitEmailDomain(email) {
  if (!email) return null;
  let at = String(email).indexOf('@');
  return at >= 0 ? email.slice(at + 1) : null;
}

// Convert a cached envelope JSON object to an IMAP ENVELOPE token.
// Missing fields become NIL.
function buildEnvelopeFromJson(env) {
  if (!env) return tNil();
  let dateStr = env.date;
  if (dateStr instanceof Date) dateStr = dateStr.toUTCString();

  return tList([
    tStr(dateStr || null),
    tStr(env.subject || null),
    addrListFromJson(env.from),
    addrListFromJson(env.sender   || env.from),
    addrListFromJson(env.replyTo  || env.from),
    addrListFromJson(env.to),
    addrListFromJson(env.cc),
    addrListFromJson(env.bcc),
    tStr(env.inReplyTo || null),
    tStr(env.messageId || null)
  ]);
}

// Convert a cached bodyStructure JSON object to an IMAP BODYSTRUCTURE token.
// Recursive for multipart / message-rfc822 nodes.
function buildBodyStructureFromJson(bs, extended) {
  if (!bs) return tNil();

  if (bs.parts && Array.isArray(bs.parts) && bs.type && bs.type.toLowerCase() === 'multipart') {
    // Multipart
    let list = [];
    for (let i = 0; i < bs.parts.length; i++) {
      list.push(buildBodyStructureFromJson(bs.parts[i], extended));
    }
    list.push(tStr((bs.subtype || 'mixed').toUpperCase()));
    if (extended) {
      list.push(paramsFromJson(bs.params));
      list.push(dispositionFromJson(bs.disposition));
      list.push(tStr(bs.language || null));
      list.push(tStr(bs.location || null));
    }
    return tList(list);
  }

  // Single part
  let type     = (bs.type    || 'text').toUpperCase();
  let subtype  = (bs.subtype || 'plain').toUpperCase();
  let encoding = (bs.encoding || '7bit').toUpperCase();

  let list = [
    tStr(type),
    tStr(subtype),
    paramsFromJson(bs.params),
    tStr(bs.id || null),
    tStr(bs.description || null),
    tStr(encoding),
    tNum(bs.size != null ? bs.size : 0)
  ];

  let typeLow = type.toLowerCase();
  let subtypeLow = subtype.toLowerCase();
  if (typeLow === 'text') {
    list.push(tNum(bs.lines || 0));
  } else if (typeLow === 'message' && subtypeLow === 'rfc822') {
    list.push(buildEnvelopeFromJson(bs.envelope));
    list.push(buildBodyStructureFromJson(bs.innerBodyStructure, extended));
    list.push(tNum(bs.innerLines || 0));
  }

  if (extended) {
    list.push(tStr(bs.md5 || null));
    list.push(dispositionFromJson(bs.disposition));
    list.push(tStr(bs.language || null));
    list.push(tStr(bs.location || null));
  }
  return tList(list);
}

function paramsFromJson(params) {
  if (!params || typeof params !== 'object') return tNil();
  let keys = Object.keys(params);
  if (keys.length === 0) return tNil();
  let flat = [];
  for (let i = 0; i < keys.length; i++) {
    flat.push(tStr(keys[i].toUpperCase()));
    flat.push(tStr(String(params[keys[i]])));
  }
  return tList(flat);
}

function dispositionFromJson(d) {
  if (!d || !d.type) return tNil();
  return tList([tStr(String(d.type).toUpperCase()), paramsFromJson(d.params)]);
}


// ============================================================
//  Extraction helpers (exposed on the module)
// ============================================================
//
// Developers call these ONCE when a new message arrives, store the result
// in their DB, and return it from `messageEnvelope` / `messageBodyStructure`
// events later — avoiding per-FETCH body parsing.

// Parse a raw message and return a JSON-serializable envelope.
function extractEnvelope(rawBytes) {
  if (!Buffer.isBuffer(rawBytes)) rawBytes = Buffer.from(rawBytes);
  let tree = parseMessageTree(rawBytes);
  return treeToEnvelopeJson(tree);
}

// Parse a raw message and return a JSON-serializable body structure.
function extractBodyStructure(rawBytes) {
  if (!Buffer.isBuffer(rawBytes)) rawBytes = Buffer.from(rawBytes);
  let tree = parseMessageTree(rawBytes);
  return treeToBodyStructureJson(tree);
}

// Convenience — both at once, avoiding double parsing.
function extractMessageMetadata(rawBytes) {
  if (!Buffer.isBuffer(rawBytes)) rawBytes = Buffer.from(rawBytes);
  let tree = parseMessageTree(rawBytes);
  return {
    envelope:      treeToEnvelopeJson(tree),
    bodyStructure: treeToBodyStructureJson(tree)
  };
}

function treeToEnvelopeJson(tree) {
  let headers = tree.headers || [];
  let fromAddrs = addrListToJson(headerOrNull(headers, 'From'));
  return {
    date:      headerOrNull(headers, 'Date'),
    subject:   headerOrNull(headers, 'Subject'),
    from:      fromAddrs,
    sender:    addrListToJson(headerOrNull(headers, 'Sender'))   || fromAddrs,
    replyTo:   addrListToJson(headerOrNull(headers, 'Reply-To')) || fromAddrs,
    to:        addrListToJson(headerOrNull(headers, 'To')),
    cc:        addrListToJson(headerOrNull(headers, 'Cc')),
    bcc:       addrListToJson(headerOrNull(headers, 'Bcc')),
    inReplyTo: headerOrNull(headers, 'In-Reply-To'),
    messageId: headerOrNull(headers, 'Message-ID')
  };
}

function addrListToJson(headerValue) {
  if (!headerValue) return null;
  let addrs = parseAddressList(headerValue);
  if (!addrs || addrs.length === 0) return null;
  let out = [];
  for (let i = 0; i < addrs.length; i++) {
    let a = addrs[i];
    if (a.group !== undefined) {
      let members = [];
      for (let j = 0; j < (a.members || []).length; j++) {
        let m = a.members[j];
        members.push({
          name:  m.name || null,
          email: m.host ? (m.mailbox + '@' + m.host) : (m.mailbox || null)
        });
      }
      out.push({ group: a.group, members: members });
    } else {
      out.push({
        name:  a.name || null,
        email: a.host ? (a.mailbox + '@' + a.host) : (a.mailbox || null)
      });
    }
  }
  return out;
}

function treeToBodyStructureJson(tree) {
  if (!tree) return null;

  // Multipart
  if (tree.contentType && tree.contentType.toLowerCase().indexOf('multipart/') === 0 && tree.parts) {
    let subtype = tree.contentType.slice(tree.contentType.indexOf('/') + 1);
    let parts = [];
    for (let i = 0; i < tree.parts.length; i++) {
      parts.push(treeToBodyStructureJson(tree.parts[i]));
    }
    let out = { type: 'multipart', subtype: subtype, parts: parts };
    if (tree.contentTypeParams && Object.keys(tree.contentTypeParams).length > 0) out.params = tree.contentTypeParams;
    if (tree.contentDisposition) out.disposition = { type: tree.contentDisposition, params: tree.contentDispositionParams || null };
    if (tree.contentLanguage)    out.language = tree.contentLanguage;
    if (tree.contentLocation)    out.location = tree.contentLocation;
    return out;
  }

  // Single part
  let ct      = tree.contentType || 'text/plain';
  let slash   = ct.indexOf('/');
  let type    = slash > 0 ? ct.slice(0, slash) : 'text';
  let subtype = slash > 0 ? ct.slice(slash + 1) : 'plain';

  let out = {
    type:        type,
    subtype:     subtype,
    params:      (tree.contentTypeParams && Object.keys(tree.contentTypeParams).length > 0) ? tree.contentTypeParams : null,
    id:          tree.contentId || null,
    description: tree.contentDescription || null,
    encoding:    tree.contentTransferEncoding || '7bit',
    size:        (tree.bodyEnd || 0) - (tree.bodyStart || 0)
  };

  let typeLow = type.toLowerCase();
  if (typeLow === 'text') {
    out.lines = tree.bodyLines || 0;
  } else if (typeLow === 'message' && subtype.toLowerCase() === 'rfc822' && tree.parts && tree.parts[0]) {
    out.envelope           = treeToEnvelopeJson(tree.parts[0]);
    out.innerBodyStructure = treeToBodyStructureJson(tree.parts[0]);
    out.innerLines         = tree.bodyLines || 0;
  }

  if (tree.contentMd5)         out.md5 = tree.contentMd5;
  if (tree.contentDisposition) out.disposition = { type: tree.contentDisposition, params: tree.contentDispositionParams || null };
  if (tree.contentLanguage)    out.language = tree.contentLanguage;
  if (tree.contentLocation)    out.location = tree.contentLocation;

  return out;
}



// ============================================================
//  Exports
// ============================================================

export {
  // Constants
  SPECIAL_USE,
  FLAGS,
  DEFAULT_FLAGS,

  // Flag / special-use normalization
  normalizeSpecialUse,
  normalizeFlag,
  serializeFlag,
  serializeFlagList,
  checkFlagsHygiene,

  // LIST / hierarchy
  makeWildcardMatcher,
  hasChildren,

  // Sequence sets / UID compression
  parseSequenceSet,
  rangesContain,
  compressUids,
  formatRanges,
  buildCopyUidCode,

  // INTERNALDATE
  formatInternalDate,
  parseInternalDate,

  // BODY[...] section
  parseBodySection,
  buildBodyResponseName,

  // SEARCH
  parseSearchDate,
  formatSearchDate,
  parseSearchRanges,
  parseSearchCriteria,

  // Token helper
  tokenToString,

  // ENVELOPE / BODYSTRUCTURE builders (from MIME tree)
  buildEnvelope,
  buildBodyStructure,

  // ENVELOPE / BODYSTRUCTURE builders (from cached JSON)
  buildEnvelopeFromJson,
  buildBodyStructureFromJson,

  // Raw message → JSON extractors (developer stores result in DB)
  extractEnvelope,
  extractBodyStructure,
  extractMessageMetadata
};
