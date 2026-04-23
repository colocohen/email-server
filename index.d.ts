// ============================================================================
//  email-server — TypeScript declarations
// ----------------------------------------------------------------------------
//  Complete type surface for the public API:
//    • createServer — unified SMTP + IMAP + POP3 server
//    • SMTPSession, IMAPSession, POP3Session — session classes (server + client)
//    • sendMail — standalone outbound
//    • buildDsn, buildDomainMailMaterial — helpers
//    • 24 mailboxSession events fully typed
// ============================================================================

/// <reference types="node" />

import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { IncomingMessage, ServerResponse } from 'node:http';


// ============================================================================
//  Top-level exports
// ============================================================================

export function createServer(options?: ServerOptions): Server;

export function buildDomainMailMaterial(
  domain: string,
  options?: DomainOptions
): DomainMaterial;

export function composeMessage(options: ComposeOptions): ComposedMessage;
export function parseMessage(raw: Uint8Array | Buffer | string): ParsedMessage;

export function sendMail(
  options: SendOptions,
  callback: (err: Error | null, info?: SendInfo) => void
): void;

export function resolveMX(
  domain: string,
  callback: (err: Error | null, records?: MXRecord[]) => void
): void;

export function buildDsn(options: DsnOptions): Buffer;

export function dkimSign(
  raw: Uint8Array | Buffer | string,
  options: DKIMSignOptions
): DKIMSignResult;

export function dkimVerify(
  raw: Uint8Array | Buffer | string,
  callback: (err: Error | null, result?: DKIMVerifyResult) => void
): void;

export function checkSPF(
  ip: string,
  domain: string,
  callback: (err: Error | null, result?: SPFResult) => void
): void;

export function checkDMARC(
  options: DMARCOptions,
  callback: (err: Error | null, result?: DMARCResult) => void
): void;

// IDN / address utilities
export function domainToAscii(domain: string): string;
export function domainToUnicode(domain: string): string;
export function splitAddress(addr: string): { local: string; domain: string } | null;
export function isAscii(s: string): boolean;
export function addressNeedsSmtputf8(addr: string): boolean;
export function addressForAsciiOnlyPeer(addr: string): string | null;

// Constants
export const SPECIAL_USE: {
  readonly All:      'All';
  readonly Archive:  'Archive';
  readonly Drafts:   'Drafts';
  readonly Flagged:  'Flagged';
  readonly Junk:     'Junk';
  readonly Sent:     'Sent';
  readonly Trash:    'Trash';
  readonly Important:'Important';
};

export const FLAGS: {
  readonly Seen:     'Seen';
  readonly Answered: 'Answered';
  readonly Flagged:  'Flagged';
  readonly Deleted:  'Deleted';
  readonly Draft:    'Draft';
  readonly Recent:   'Recent';
};

// Metadata extraction helpers (cache optimization for IMAP)
export function extractEnvelope(raw: Uint8Array | Buffer | string): MessageEnvelope;
export function extractBodyStructure(raw: Uint8Array | Buffer | string): MessageBodyStructure;
export function extractMessageMetadata(
  raw: Uint8Array | Buffer | string
): { envelope: MessageEnvelope; bodyStructure: MessageBodyStructure };

export { Server, SMTPSession, IMAPSession, POP3Session };
export * as wire from './src/smtp_wire.js';


// ============================================================================
//  Server — createServer() + the Server class
// ============================================================================

export interface ServerOptions {
  /** Server hostname used for EHLO, banner, STS identity. */
  hostname?: string;

  /** Ports to bind. Omit any port you don't want to serve. */
  ports?: {
    inbound?:    number;    // SMTP inbound on 25 (no auth)
    submission?: number;    // SMTP submission on 587 (STARTTLS required)
    secure?:     number;    // SMTP implicit TLS on 465
    imap?:       number;    // IMAP on 143 (STARTTLS)
    imaps?:      number;    // IMAP implicit TLS on 993
    pop3?:       number;    // POP3 on 110 (STARTTLS)
    pop3s?:      number;    // POP3 implicit TLS on 995
  };

  /** Base TLS context. SNI overrides per-domain. */
  tlsOptions?: {
    cert?: string | Buffer;
    key?:  string | Buffer;
    ca?:   string | Buffer;
    [k: string]: unknown;
  };

  /** Max message size in bytes (default 25 MB). */
  maxSize?: number;

  /** Max recipients per envelope (default 100). */
  maxRecipients?: number;

  /** Default relay / smarthost for outbound. */
  relay?: RelayOptions;

  /** Outbound connection-pool settings. */
  pool?: PoolOptions;

  /** Auth session timeout in ms (default 30 s). */
  authTimeout?: number;

  /** Timeout for the accept() callback in the `mail` handler (ms). */
  acceptTimeout?: number;

  /** Graceful shutdown timeout (ms). */
  closeTimeout?: number;

  /** Enable HAProxy PROXY protocol v1. */
  useProxy?: boolean;

  /** SNI callback — dynamic TLS context per servername. */
  SNICallback?: (
    servername: string,
    cb: (err: Error | null, ctx?: unknown) => void
  ) => void;

  /** Dynamic DKIM key per outbound domain. */
  dkimCallback?: (
    domain: string,
    cb: (err: Error | null, dkim?: DKIMKeyInfo) => void
  ) => void;

  /** Post-TLS handshake callback. */
  onSecure?: (socket: unknown, session: unknown, cb: () => void) => void;

  /** Per-IP rate limiting. */
  rateLimit?: RateLimitOptions;
}

export interface PoolOptions {
  maxPerDomain?:       number;
  maxMessagesPerConn?: number;
  idleTimeout?:        number;
  rateLimitPerMinute?: number;
  reconnectDelay?:     number;
}

export interface RelayOptions {
  host: string;
  port?: number;
  auth?: { user: string; pass: string } | { user: string; accessToken: string };
  localHostname?: string;
  timeout?:   number;
  ignoreTLS?: boolean;
}

export interface RateLimitOptions {
  perMinute?:    number;
  perHour?:      number;
  banDuration?:  number;
}


// ---- the Server class ----

export class Server extends EventEmitter {
  // Core lifecycle
  listen(callback?: (err?: Error) => void): void;
  close(callback?: () => void): void;

  // Domain management
  addDomain(material: DomainMaterial): void;
  removeDomain(domain: string): void;

  // DSN — build and dispatch
  sendDsn(options: DsnOptions, callback?: (err: Error | null, info?: SendInfo) => void): void;
  buildDsn(options: DsnOptions): Buffer;

  // Direct outbound (uses the server's pool + domain DKIM keys)
  send(options: SendOptions, callback?: (err: Error | null, info?: SendInfo) => void): void;

  // TLS cache management (use after Let's Encrypt rotation)
  clearTlsCache(servername?: string): void;

  // Push notifications — iterate live mailboxSessions to call notifyExists etc.
  forEachMailboxSession(fn: (session: MailboxSession) => void): void;
  forEachSmtpSession(fn: (session: SmtpSession) => void): void;

  // Rate-limit hooks
  ban(ip: string, durationMs?: number): void;
  unban(ip: string): void;

  // Events
  on(event: 'auth',           listener: (info: AuthInfo) => void): this;
  on(event: 'smtpSession',    listener: (session: SmtpSession) => void): this;
  on(event: 'mailboxSession', listener: (session: MailboxSession) => void): this;
  on(event: 'connection',     listener: (info: ConnectionInfo) => void): this;
  on(event: 'ready',          listener: () => void): this;
  on(event: 'close',          listener: () => void): this;
  on(event: 'error',          listener: (err: Error) => void): this;
  on(event: 'tlsError',       listener: (err: Error) => void): this;
  on(event: 'rateLimit',      listener: (info: RateLimitInfo) => void): this;
  on(event: 'sending',        listener: (options: unknown) => void): this;
  on(event: 'sent',           listener: (info: unknown) => void): this;
  on(event: 'bounce',         listener: (info: BounceInfo) => void): this;
  on(event: 'retry',          listener: (info: RetryInfo) => void): this;
  on(event: 'sendError',      listener: (err: Error, options: unknown) => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
}


// ============================================================================
//  Auth — unified across SMTP submission, IMAP, POP3
// ============================================================================

export interface AuthInfo {
  protocol:      'smtp' | 'imap' | 'pop3';
  authMethod:    'plain' | 'login' | 'xoauth2' | 'apop';
  username:      string;
  /** Password for plain/login/apop, bearer token for xoauth2. */
  password:      string;
  remoteAddress: string;
  isTLS:         boolean;

  accept(): void;
  reject(message?: string): void;
}

export interface ConnectionInfo {
  id:            string;
  protocol:      'smtp' | 'imap' | 'pop3';
  remoteAddress: string;
  isTLS:         boolean;
  reject(): void;
}

export interface RateLimitInfo {
  protocol:      'smtp' | 'imap' | 'pop3';
  remoteAddress: string;
  reason:        'rate' | 'banned';
  bannedUntil?:  number;
}


// ============================================================================
//  SMTP session (server-side facade)
// ============================================================================

export interface SmtpSession extends EventEmitter {
  readonly protocol:      'smtp';
  readonly isSubmission:  boolean;
  readonly username:      string | null;
  readonly remoteAddress: string;
  readonly isTLS:         boolean;
  readonly authenticated: boolean;

  on(event: 'mail',  listener: (mail: InboundMail) => void): this;
  on(event: 'rcpt',  listener: (address: string, params: RcptParams, ctx: RcptContext) => void): this;
  on(event: 'close', listener: () => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
}

export interface MailParams {
  size?:       number;
  body?:       '7BIT' | '8BITMIME' | 'BINARYMIME';
  smtputf8?:   boolean;      // RFC 6531
  requiretls?: boolean;      // RFC 8689
  ret?:        'FULL' | 'HDRS';   // RFC 3461 DSN
  envid?:      string;       // RFC 3461 DSN (xtext-decoded)
  [k: string]: unknown;
}

export interface RcptParams {
  notify?: {
    never:   boolean;
    success: boolean;
    failure: boolean;
    delay:   boolean;
  };
  orcpt?: {
    addrType: string;
    addr:     string;
  };
  [k: string]: unknown;
}

export interface RcptContext {
  reject(code?: number, msg?: string): void;
}

export interface InboundMail extends EventEmitter {
  from:    string;
  to:      string[];
  params:  MailParams;

  subject:    string | null;
  messageId:  string | null;
  date:       string | null;
  headerFrom: string | null;
  headerTo:   string | null;
  headers:    Record<string, string | string[]>;

  /** Authentication results (inbound only; null on submission). */
  auth: AuthResults | null;

  /** Raw message bytes (set when accumulated; use the `data` event for streams). */
  rawBytes:   Uint8Array | null;
  size:       number;

  /** Parsed content — available in the `end` listener. */
  text:        string | null;
  html:        string | null;
  attachments: Attachment[];

  on(event: 'data', listener: (chunk: Uint8Array) => void): this;
  on(event: 'end',  listener: () => void): this;

  accept(): void;
  reject(code?: number, message?: string): void;
  /** Submission mode only — library signs + delivers. */
  deliver(callback?: (err: Error | null, info?: SendInfo) => void): void;
}

export interface AuthResults {
  dkim:         'pass' | 'fail' | 'none' | 'temperror' | 'permerror' | null;
  dkimDomain:   string | null;
  spf:          'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | null;
  dmarc:        'pass' | 'fail' | 'none' | null;
  dmarcPolicy:  'none' | 'quarantine' | 'reject' | null;
  rdns:         'pass' | 'fail' | 'none' | null;
  rdnsHostname: string | null;
}


// ============================================================================
//  Mailbox session (IMAP + POP3 unified)
// ============================================================================

export interface MailboxSession extends EventEmitter {
  readonly protocol:       'imap' | 'pop3';
  readonly username:       string;
  readonly remoteAddress:  string;
  readonly isTLS:          boolean;
  readonly currentFolder:  string | null;
  readonly idling:         boolean;

  // ---- IDLE push primitives (call these from your storage layer) ----
  notifyExists(total: number): void;
  notifyRecent(recent: number): void;
  notifyExpunge(seqNum: number): void;
  /** QRESYNC (RFC 7162) — tell the client a UID has vanished. */
  notifyVanished(uid: number | number[]): void;
  notifyFlags(seqNum: number, uid: number, flags: string[]): void;

  // ---- Storage events (register the ones your backend supports) ----

  on(event: 'folders',        listener: (cb: Callback<FolderInfo[]>) => void): this;
  on(event: 'openFolder',     listener: (name: string, cb: Callback<FolderOpenInfo>) => void): this;
  on(event: 'status',         listener: (name: string, items: string[], cb: Callback<FolderStatus>) => void): this;

  on(event: 'resolveMessages', listener: (range: MessageRange, cb: Callback<number[]>) => void): this;
  on(event: 'messageMeta',     listener: (ids: number[], cb: Callback<MessageMeta[]>) => void): this;
  on(event: 'messageEnvelope', listener: (ids: number[], cb: Callback<(MessageEnvelope | null)[]>) => void): this;
  on(event: 'messageBodyStructure', listener: (ids: number[], cb: Callback<(MessageBodyStructure | null)[]>) => void): this;
  on(event: 'messageBody',     listener: (id: number, responder: BodyResponder) => void): this;

  on(event: 'setFlags',     listener: (ids: number[], flags: string[], cb: Callback<void>) => void): this;
  on(event: 'append',       listener: (folder: string, raw: Uint8Array, flags: string[], cb: Callback<AppendInfo>) => void): this;
  on(event: 'copyMessages', listener: (ids: number[], dest: string, cb: Callback<CopyInfo>) => void): this;
  on(event: 'move',         listener: (ids: number[], dest: string, cb: Callback<CopyInfo>) => void): this;
  on(event: 'expunge',      listener: (ids: number[], cb: Callback<void>) => void): this;

  on(event: 'createFolder',    listener: (name: string, cb: Callback<void>) => void): this;
  on(event: 'deleteFolder',    listener: (name: string, cb: Callback<void>) => void): this;
  on(event: 'renameFolder',    listener: (oldName: string, newName: string, cb: Callback<void>) => void): this;
  on(event: 'subscribe',       listener: (name: string, cb: Callback<void>) => void): this;
  on(event: 'unsubscribe',     listener: (name: string, cb: Callback<void>) => void): this;

  on(event: 'search',   listener: (criteria: SearchCriteria, cb: Callback<number[]>) => void): this;
  on(event: 'sort',     listener: (keys: string[], charset: string, criteria: SearchCriteria, cb: Callback<number[]>) => void): this;
  on(event: 'thread',   listener: (algo: 'ORDEREDSUBJECT' | 'REFERENCES', charset: string, criteria: SearchCriteria, cb: Callback<ThreadNode[]>) => void): this;

  on(event: 'namespace', listener: (cb: Callback<NamespaceReply>) => void): this;
  on(event: 'qresync',   listener: (params: QresyncParams, cb: Callback<QresyncResult>) => void): this;
  on(event: 'resolveVanished', listener: (sinceModseq: number, uids: number[] | null, cb: Callback<number[]>) => void): this;

  // Opt-in (listener presence advertises the IMAP capability)
  on(event: 'quota',      listener: (root: string, cb: Callback<QuotaResources>) => void): this;
  on(event: 'quotaRoot',  listener: (mailbox: string, cb: Callback<string[]>) => void): this;
  on(event: 'getMetadata', listener: (mailbox: string, paths: string[], cb: Callback<Record<string, string | null>>) => void): this;
  on(event: 'setMetadata', listener: (mailbox: string, entries: Record<string, string | null>, cb: Callback<void>) => void): this;

  on(event: 'close', listener: () => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
}

export type Callback<T> = (err: Error | null, result?: T) => void;

export type MessageRange = Array<
  { type: 'uid' | 'seq'; from: number; to: number }   // inclusive range
  | { type: 'uid' | 'seq'; value: number }             // single
>;

export interface FolderInfo {
  name:        string;
  specialUse?: keyof typeof SPECIAL_USE | null;
  flags?:      string[];
  delimiter?:  string;
  subscribed?: boolean;
}

export interface FolderOpenInfo {
  uidValidity:    number;
  total:          number;
  unread?:        number;
  uidNext?:       number;
  highestModseq?: number;
  flags?:         string[];
  permanentFlags?: string[];
}

export interface FolderStatus {
  messages?:      number;
  recent?:        number;
  uidNext?:       number;
  uidValidity?:   number;
  unseen?:        number;
  highestModseq?: number;
  size?:          number;
}

export interface MessageMeta {
  id:            number;
  uid:           number;
  size:          number;
  internalDate:  Date | string;
  flags:         string[];
  modseq?:       number;
}

export interface BodyResponder {
  /** Stream mode — pass a Readable and its total byte length. */
  send(opts: { length: number; stream: Readable }): void;
  /** Buffer mode — pass raw bytes. */
  send(opts: { bytes: Uint8Array | Buffer }): void;
  /** Reject — message not available. */
  reject(reason?: string): void;
}

export interface AppendInfo {
  uid?:         number;
  uidValidity?: number;
}

export interface CopyInfo {
  uidValidity?: number;
  sourceUids?:  number[];
  destUids?:    number[];
}

export interface SearchCriteria {
  op: string;
  args?: unknown[];
  [k: string]: unknown;
}

export interface ThreadNode {
  id?:       number;
  children?: ThreadNode[];
}

export interface NamespaceReply {
  personal?: Array<{ prefix: string; delimiter: string }>;
  other?:    Array<{ prefix: string; delimiter: string }>;
  shared?:   Array<{ prefix: string; delimiter: string }>;
}

export interface QresyncParams {
  uidValidity:    number;
  modseq:         number;
  knownUids?:     number[];
  knownSeqSet?:   number[];
  knownUidSet?:   number[];
}

export interface QresyncResult {
  vanished?: number[];
  changed?:  MessageMeta[];
}

export interface QuotaResources {
  root: string;
  resources: Array<{ name: 'STORAGE' | 'MESSAGE' | string; usage: number; limit: number }>;
}


// ============================================================================
//  Message envelope / body structure (IMAP cache shapes)
// ============================================================================

export interface MessageEnvelope {
  date:       string | null;
  subject:    string | null;
  from:       EnvelopeAddress[];
  sender:     EnvelopeAddress[];
  replyTo:    EnvelopeAddress[];
  to:         EnvelopeAddress[];
  cc:         EnvelopeAddress[];
  bcc:        EnvelopeAddress[];
  inReplyTo:  string | null;
  messageId:  string | null;
}

export interface EnvelopeAddress {
  name:    string | null;
  adl:     string | null;
  mailbox: string | null;
  host:    string | null;
}

export interface MessageBodyStructure {
  type:        string;
  subtype:     string;
  parameters:  Record<string, string>;
  id:          string | null;
  description: string | null;
  encoding:    string | null;
  size:        number | null;
  disposition: { type: string; parameters: Record<string, string> } | null;
  language:    string | null;
  location:    string | null;
  parts?:      MessageBodyStructure[];
  lines?:      number;
  md5?:        string | null;
  envelope?:   MessageEnvelope;
  bodyStructure?: MessageBodyStructure;
}


// ============================================================================
//  IMAPSession — low-level constructor (server or client mode)
// ============================================================================

export interface IMAPSessionOptions {
  isServer?:        boolean;
  hostname?:        string;
  authMethods?:     string[];
  tlsOptions?:      Record<string, unknown>;
  isTLS?:           boolean;
  remoteAddress?:   string;
  maxCommandSize?:  number;
  authTimeout?:     number;
}

export class IMAPSession extends EventEmitter {
  constructor(options?: IMAPSessionOptions);

  // Transport glue
  feed(chunk: Uint8Array | Buffer): void;
  greet(): void;
  tlsUpgraded(): void;
  close(): void;

  // State
  readonly isServer:       boolean;
  readonly state:          string;
  readonly authenticated:  boolean;
  readonly username:       string | null;
  readonly currentFolder:  string | null;
  readonly idling:         boolean;
  /** Remote CAPABILITY list (client mode) — refreshed after LOGIN/STARTTLS. */
  readonly capabilities:   string[];

  // ---- Client-mode methods ----
  login(user: string, pass: string, cb?: Callback<unknown>): void;
  xoauth2(user: string, token: string, cb?: Callback<unknown>): void;
  logout(cb?: Callback<void>): void;
  capability(cb?: Callback<string[]>): void;
  enable(caps: string[], cb?: Callback<string[]>): void;
  namespace(cb?: Callback<NamespaceReply>): void;
  list(reference: string, pattern: string, cb?: Callback<FolderInfo[]>): void;
  listExtended(opts: {
    reference?: string;
    patterns?:  string[];
    selection?: string[];
    return?:    string[];
  }, cb?: Callback<{ folders: FolderInfo[]; statuses: Record<string, FolderStatus> }>): void;
  lsub(reference: string, pattern: string, cb?: Callback<FolderInfo[]>): void;
  select(folder: string, cb?: Callback<FolderOpenInfo>): void;
  examine(folder: string, cb?: Callback<FolderOpenInfo>): void;
  status(folder: string, items: string[], cb?: Callback<FolderStatus>): void;
  create(folder: string, cb?: Callback<void>): void;
  delete(folder: string, cb?: Callback<void>): void;
  rename(oldName: string, newName: string, cb?: Callback<void>): void;
  subscribe(folder: string, cb?: Callback<void>): void;
  unsubscribe(folder: string, cb?: Callback<void>): void;
  search(criteria: unknown, cb?: Callback<number[]>): void;
  sort(keys: string[], charset: string, criteria: unknown, cb?: Callback<number[]>): void;
  thread(algo: 'ORDEREDSUBJECT' | 'REFERENCES', charset: string, criteria: unknown, cb?: Callback<ThreadNode[]>): void;
  fetch(ids: number[] | string, items: string[], cb?: Callback<unknown[]>): void;
  store(ids: number[] | string, flags: string[], mode: '+' | '-' | '', cb?: Callback<unknown>): void;
  copy(ids: number[] | string, dest: string, cb?: Callback<unknown>): void;
  move(ids: number[] | string, dest: string, cb?: Callback<unknown>): void;
  append(folder: string, raw: Uint8Array | Buffer | string, flags?: string[], cb?: Callback<AppendInfo>): void;
  expunge(cb?: Callback<void>): void;
  uidExpunge(uids: number[], cb?: Callback<void>): void;
  idle(cb?: Callback<void>): void;
  done(cb?: Callback<void>): void;
  noop(cb?: Callback<void>): void;
  getQuota(root: string, cb?: Callback<QuotaResources>): void;
  getQuotaRoot(mailbox: string, cb?: Callback<{ roots: string[]; quotas: Record<string, QuotaResources> }>): void;
  getMetadata(mailbox: string, paths: string | string[], cb?: Callback<Record<string, string | null>>): void;
  setMetadata(mailbox: string, entries: Record<string, string | null>, cb?: Callback<unknown>): void;
  compress(cb?: Callback<void>): void;
  starttls(cb?: Callback<void>): void;

  // Events — mirror MailboxSession events (server mode) + client lifecycle
  on(event: 'send',    listener: (data: string | Uint8Array) => void): this;
  on(event: 'ready',   listener: () => void): this;
  on(event: 'starttls', listener: () => void): this;
  on(event: 'compress', listener: (streams: { inflate: unknown; deflate: unknown }) => void): this;
  on(event: 'error',   listener: (err: Error) => void): this;
  on(event: 'close',   listener: () => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
}


// ============================================================================
//  POP3Session — server or client mode
// ============================================================================

export interface POP3SessionOptions {
  isServer?:      boolean;
  hostname?:      string;
  authMethods?:   string[];
  tlsOptions?:    Record<string, unknown>;
  isTLS?:         boolean;
  remoteAddress?: string;
  authTimeout?:   number;
}

export interface POP3ListEntry {
  index: number;
  size:  number;
}

export class POP3Session extends EventEmitter {
  constructor(options?: POP3SessionOptions);

  feed(chunk: Uint8Array | Buffer): void;
  greet(): void;
  tlsUpgraded(): void;
  close(): void;

  readonly isServer:      boolean;
  readonly state:         string;
  readonly authenticated: boolean;
  readonly username:      string | null;
  readonly capabilities:  string[];

  // ---- Client-mode methods ----
  user(name: string, cb?: Callback<void>): void;
  pass(password: string, cb?: Callback<void>): void;
  apop(user: string, password: string, cb?: Callback<void>): void;
  xoauth2(user: string, token: string, cb?: Callback<void>): void;
  capa(cb?: Callback<string[]>): void;
  stls(cb?: Callback<void>): void;
  stat(cb?: Callback<{ count: number; size: number }>): void;
  list(which?: number, cb?: Callback<POP3ListEntry[]>): void;
  uidl(which?: number, cb?: Callback<Array<{ index: number; uid: string }>>): void;
  retr(index: number, cb?: Callback<Uint8Array>): void;
  top(index: number, lines: number, cb?: Callback<Uint8Array>): void;
  dele(index: number, cb?: Callback<void>): void;
  rset(cb?: Callback<void>): void;
  noop(cb?: Callback<void>): void;
  quit(cb?: Callback<void>): void;

  on(event: 'send',  listener: (data: string | Uint8Array) => void): this;
  on(event: 'ready', listener: () => void): this;
  on(event: 'error', listener: (err: Error) => void): this;
  on(event: 'close', listener: () => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
}


// ============================================================================
//  SMTPSession — low-level constructor (server or client mode)
// ============================================================================

export interface SMTPSessionOptions {
  isServer?:        boolean;
  isSubmission?:    boolean;
  hostname?:        string;
  maxSize?:         number;
  maxRecipients?:   number;
  acceptTimeout?:   number;
  remoteAddress?:   string;
  localAddress?:    string;
  isTLS?:           boolean;
  tlsOptions?:      Record<string, unknown>;
  authMethods?:     string[];
  extraCapabilities?: string[];
}

export class SMTPSession extends EventEmitter {
  constructor(options?: SMTPSessionOptions);

  feed(chunk: Uint8Array | Buffer): void;
  greet(): void;
  tlsUpgraded(): void;
  close(): void;
  setParseMessage(fn: (raw: Uint8Array) => ParsedMessage | null): void;

  readonly isServer:       boolean;
  readonly state:          string;
  readonly authenticated:  boolean;
  readonly username:       string | null;
  readonly clientHostname: string | null;
  readonly remoteAddress:  string | null;
  readonly isTLS:          boolean;
  readonly messageCount:   number;
  readonly capabilities:   Record<string, unknown> | null;

  // ---- Client-mode methods ----
  mailFrom(address: string, params: MailParams, callback: Callback<void>): void;
  rcptTo(address: string, callback: Callback<void>): void;
  data(rawMessage: Uint8Array | Buffer | string, callback: Callback<unknown>): void;
  authPlain(user: string, pass: string, callback: Callback<void>): void;
  authLogin(user: string, pass: string, callback: Callback<void>): void;
  authXoauth2(user: string, token: string, callback: Callback<void>): void;
  startTLS(callback: Callback<void>): void;
  ehlo(callback: Callback<void>): void;
  rset(callback?: Callback<void>): void;
  noop(callback?: Callback<void>): void;
  quit(callback?: Callback<void>): void;

  on(event: 'send',     listener: (data: string) => void): this;
  on(event: 'message',  listener: (mail: InboundMail) => void): this;
  on(event: 'auth',     listener: (username: string, password: string, cb: AuthCallback, authMethod: string) => void): this;
  on(event: 'mail',     listener: (from: string, params: MailParams) => void): this;
  on(event: 'rcpt',     listener: (to: string, params: RcptParams, ctx: RcptContext) => void): this;
  on(event: 'ehlo',     listener: (hostname: string) => void): this;
  on(event: 'starttls', listener: () => void): this;
  on(event: 'ready',    listener: () => void): this;
  on(event: 'error',    listener: (err: Error) => void): this;
  on(event: 'close',    listener: () => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
}

export interface AuthCallback {
  accept(): void;
  reject(message?: string): void;
}


// ============================================================================
//  Message compose / parse
// ============================================================================

export interface ComposeOptions {
  from:    string | { name?: string; address: string };
  to:      string | string[] | Array<{ name?: string; address: string }>;
  cc?:     string | string[];
  bcc?:    string | string[];
  subject?: string;
  text?:    string;
  html?:    string;
  attachments?: AttachmentInput[];
  headers?: Record<string, string>;
  messageId?: string;
  date?:      Date | string;
  replyTo?:   string;
  priority?:  'high' | 'normal' | 'low';
}

export interface AttachmentInput {
  filename:     string;
  content:      string | Buffer | Uint8Array;
  contentType?: string;
  cid?:         string;
  encoding?:    'base64' | 'utf-8' | '7bit' | '8bit';
}

export interface ComposedMessage {
  raw:         Uint8Array;
  messageId:   string;
  smtpProfile: {
    smtpUtf8Needed: boolean;
    bodyIs8bit:     boolean;
    size:           number;
  };
}

export interface ParsedMessage {
  subject:    string | null;
  from:       string | null;
  to:         string | null;
  cc?:        string | null;
  bcc?:       string | null;
  date:       string | null;
  messageId:  string | null;
  text:       string | null;
  html:       string | null;
  headers?:   Record<string, string | string[]>;
  attachments: Attachment[];
}

export interface Attachment {
  filename:     string;
  contentType:  string;
  content:      Uint8Array;
  size:         number;
  cid:          string | null;
  disposition?: string;
}


// ============================================================================
//  Domain material (DKIM + DNS + MTA-STS + TLS-RPT)
// ============================================================================

export interface DomainOptions {
  dkim?: {
    selector?:   string;
    algo?:       'rsa-sha256' | 'ed25519-sha256';
    privateKey?: string;
  };
  tls?: {
    cert: string | Buffer;
    key:  string | Buffer;
    ca?:  string | Buffer;
  };
  policy?: {
    spfTxt?:   string;
    dmarcTxt?: string;
  };
  /** Enable MTA-STS (RFC 8461). */
  mtaSts?: {
    mode?:          'enforce' | 'testing' | 'none';
    mx?:            string | string[];
    maxAgeSeconds?: number;
    id?:            string;
  };
  /** Enable TLS-RPT (RFC 8460). */
  tlsRpt?: {
    /** Short form — just the reporting email address. */
    ruaEmail?: string;
    /** Full URI form — 'mailto:...' or 'https://...'. */
    rua?:      string;
  };
}

export interface DomainMaterial {
  domain: string;
  dkim: {
    selector:   string;
    algo:       string;
    privateKey: string;
    publicKey:  string;
    dnsName:    string;
    dnsValue:   string;
  };
  tls: { cert?: string | Buffer; key?: string | Buffer; ca?: string | Buffer } | null;
  mtaSts: MtaStsMaterial | null;
  tlsRpt: TlsRptMaterial | null;
  requiredDNS: DNSRecord[];
  verifyDNS(callback: (err: Error | null, results?: Record<string, boolean>) => void): void;
}

export interface MtaStsMaterial {
  id:        string;
  mode:      'enforce' | 'testing' | 'none';
  mx:        string[];
  maxAge:    number;
  /** Full policy file contents — serve this at the policy URL. */
  policy:    string;
  policyUrl: string;
  policyHost: string;
  /** HTTP handler — mount on (req, res) of any node:http / node:https server. */
  serve: (req: IncomingMessage, res: ServerResponse) => void;
}

export interface TlsRptMaterial {
  rua:   string;
  value: string;
}

export interface DNSRecord {
  type:   string;
  name:   string;
  value:  string;
  /** Extra guidance for operator-only actions (e.g. HTTPS cert for mta-sts). */
  note?:  string;
}

export interface DKIMKeyInfo {
  selector:   string;
  algo:       string;
  privateKey: string;
}


// ============================================================================
//  DSN (RFC 3461/3464)
// ============================================================================

export interface DsnOptions {
  /** Our hostname — appears in the Reporting-MTA field. */
  reportingMta?:       string;
  /** Echoes the sender's ENVID (RFC 3461). */
  originalEnvelopeId?: string;
  /** When we first accepted the message. */
  arrivalDate?:        Date | string;
  /** The message that couldn't be delivered. */
  originalMessage:     Buffer | Uint8Array;
  /** Match the sender's RET= preference. Default 'headers'. */
  returnContent?:      'full' | 'headers';
  /** From address of the DSN itself. Default 'postmaster@<reportingMta>'. */
  from?:               string;
  /** Original envelope sender — receives the DSN. */
  to:                  string;
  recipients: Array<{
    finalRecipient:      string;
    originalRecipient?:  string;
    action:              'failed' | 'delayed' | 'delivered' | 'relayed' | 'expanded';
    status:              string;
    diagnostic?:         string;
    remoteMta?:          string;
    lastAttempt?:        Date | string;
    willRetryUntil?:     Date | string;
  }>;
}


// ============================================================================
//  DKIM / SPF / DMARC
// ============================================================================

export interface DKIMSignOptions {
  domain:       string;
  selector:     string;
  privateKey:   string;
  algo?:        'rsa-sha256' | 'ed25519-sha256';
  signHeaders?: string[];
}

export interface DKIMSignResult {
  header:         string;
  signature:      string;
  bodyHash:       string;
  signedHeaders:  string[];
  message:        string;
}

export interface DKIMVerifyResult {
  result:    'pass' | 'fail' | 'none' | 'temperror' | 'permerror';
  domain?:   string;
  selector?: string;
  algo?:     string;
  reason?:   string;
}

export interface SPFResult {
  result:     'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror';
  domain:     string;
  mechanism?: string;
  reason?:    string;
}

export interface DMARCOptions {
  fromDomain:  string;
  dkimResult:  string;
  dkimDomain?: string;
  spfResult:   string;
  spfDomain?:  string;
}

export interface DMARCResult {
  result:        'pass' | 'fail' | 'none';
  domain:        string;
  policy?:       'none' | 'quarantine' | 'reject';
  dkimAligned?:  boolean;
  spfAligned?:   boolean;
}


// ============================================================================
//  Outbound send
// ============================================================================

export interface SendOptions extends Partial<ComposeOptions> {
  /** Pre-built raw message — skips compose. */
  raw?:           Uint8Array | Buffer | string;
  from?:          string | { name?: string; address: string };
  to?:            string | string[] | Array<{ name?: string; address: string }>;
  relay?:         RelayOptions;
  pool?:          unknown;
  localHostname?: string;
  timeout?:       number;
  ignoreTLS?:     boolean;
}

export interface SendInfo {
  messageId: string;
  accepted?: Array<{ host: string; accepted: string[]; rejected: string[] }>;
  rejected?: Array<{ domain: string; error: Error }>;
  host?:     string;
}

export interface BounceInfo {
  id:    number;
  from:  string;
  to:    string[];
  error: string;
}

export interface RetryInfo {
  id:        number;
  attempts:  number;
  error:     string;
  nextRetry: number;
}

export interface MXRecord {
  exchange: string;
  priority: number;
}


// ============================================================================
//  Default export
// ============================================================================

declare const _default: {
  createServer:            typeof createServer;
  Server:                  typeof Server;
  SMTPSession:             typeof SMTPSession;
  IMAPSession:             typeof IMAPSession;
  POP3Session:             typeof POP3Session;
  buildDomainMailMaterial: typeof buildDomainMailMaterial;
  composeMessage:          typeof composeMessage;
  parseMessage:            typeof parseMessage;
  sendMail:                typeof sendMail;
  resolveMX:               typeof resolveMX;
  buildDsn:                typeof buildDsn;
  dkimSign:                typeof dkimSign;
  dkimVerify:              typeof dkimVerify;
  checkSPF:                typeof checkSPF;
  checkDMARC:              typeof checkDMARC;
  SPECIAL_USE:             typeof SPECIAL_USE;
  FLAGS:                   typeof FLAGS;
  extractEnvelope:         typeof extractEnvelope;
  extractBodyStructure:    typeof extractBodyStructure;
  extractMessageMetadata:  typeof extractMessageMetadata;
  domainToAscii:           typeof domainToAscii;
  domainToUnicode:         typeof domainToUnicode;
  splitAddress:            typeof splitAddress;
  isAscii:                 typeof isAscii;
  addressNeedsSmtputf8:    typeof addressNeedsSmtputf8;
  addressForAsciiOnlyPeer: typeof addressForAsciiOnlyPeer;
  wire:                    typeof wire;
};

export default _default;
