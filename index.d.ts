
// TypeScript declarations for email-server

/// <reference types="node" />

import { EventEmitter } from 'node:events';

// ============================================================
//  Main exports
// ============================================================

export function createServer(options?: ServerOptions): Server;
export function buildDomainMailMaterial(domain: string, options?: DomainOptions): DomainMaterial;
export function composeMessage(options: ComposeOptions): ComposedMessage;
export function parseMessage(raw: Uint8Array | Buffer | string): ParsedMessage;
export function sendMail(options: SendOptions, callback: (err: Error | null, info?: SendInfo) => void): void;
export function resolveMX(domain: string, callback: (err: Error | null, records?: MXRecord[]) => void): void;
export function dkimSign(raw: Uint8Array | Buffer | string, options: DKIMSignOptions): DKIMSignResult;
export function dkimVerify(raw: Uint8Array | Buffer | string, callback: (err: Error | null, result?: DKIMVerifyResult) => void): void;
export function checkSPF(ip: string, domain: string, callback: (err: Error | null, result?: SPFResult) => void): void;
export function checkDMARC(options: DMARCOptions, callback: (err: Error | null, result?: DMARCResult) => void): void;

export { SMTPSession, Server };
export * as wire from './src/wire.js';

// ============================================================
//  Server
// ============================================================

interface ServerOptions {
  hostname?: string;
  ports?: {
    inbound?: number;
    submission?: number;
    secure?: number;
  };
  maxSize?: number;
  maxRecipients?: number;
  acceptTimeout?: number;
  closeTimeout?: number;
  relay?: RelayOptions;
  pool?: PoolOptions;
  useProxy?: boolean;
  SNICallback?: (servername: string, cb: (err: Error | null, ctx?: any) => void) => void;
  dkimCallback?: (domain: string, cb: (err: Error | null, dkim?: DKIMKeyInfo) => void) => void;
  onSecure?: (socket: any, session: any, cb: () => void) => void;
}

interface PoolOptions {
  maxPerDomain?: number;
  maxMessagesPerConn?: number;
  idleTimeout?: number;
  rateLimitPerMinute?: number;
  reconnectDelay?: number;
}

interface RelayOptions {
  host: string;
  port?: number;
  auth?: { user: string; pass: string };
  localHostname?: string;
  timeout?: number;
  ignoreTLS?: boolean;
}

declare class Server {
  on(event: 'inboundMail', listener: (mail: InboundMail) => void): this;
  on(event: 'submissionMail', listener: (mail: InboundMail, session: SessionInfo) => void): this;
  on(event: 'auth', listener: (session: AuthSession) => void): this;
  on(event: 'connection', listener: (info: ConnectionInfo) => void): this;
  on(event: 'sending', listener: (options: any) => void): this;
  on(event: 'sent', listener: (info: any) => void): this;
  on(event: 'bounce', listener: (info: BounceInfo) => void): this;
  on(event: 'retry', listener: (info: RetryInfo) => void): this;
  on(event: 'sendError', listener: (err: Error, options: any) => void): this;
  on(event: 'ready', listener: () => void): this;
  on(event: 'error', listener: (err: Error) => void): this;
  on(event: 'tlsError', listener: (err: Error) => void): this;
  on(event: string, listener: (...args: any[]) => void): this;

  addDomain(material: DomainMaterial): void;
  removeDomain(domain: string): void;
  send(options: SendOptions, callback?: (err: Error | null, info?: SendInfo) => void): void;
  listen(callback?: (err?: Error) => void): void;
  close(callback?: () => void): void;
}

// ============================================================
//  SMTPSession
// ============================================================

interface SMTPSessionOptions {
  isServer?: boolean;
  isSubmission?: boolean;
  hostname?: string;
  maxSize?: number;
  maxRecipients?: number;
  acceptTimeout?: number;
  remoteAddress?: string;
  localAddress?: string;
  isTLS?: boolean;
  tlsOptions?: any;
  authMethods?: string[];
  extraCapabilities?: string[];
}

declare class SMTPSession {
  constructor(options?: SMTPSessionOptions);

  // Both modes
  feed(chunk: Buffer | Uint8Array): void;
  greet(): void;
  tlsUpgraded(): void;
  close(): void;
  setParseMessage(fn: (raw: Uint8Array) => ParsedMessage | null): void;

  on(event: 'send', listener: (data: string) => void): void;
  on(event: 'message', listener: (mail: InboundMail) => void): void;
  on(event: 'auth', listener: (username: string, password: string, cb: AuthCallback) => void): void;
  on(event: 'ehlo', listener: (hostname: string) => void): void;
  on(event: 'starttls', listener: () => void): void;
  on(event: 'ready', listener: () => void): void;
  on(event: 'error', listener: (err: Error) => void): void;
  on(event: 'close', listener: () => void): void;
  on(event: string, listener: (...args: any[]) => void): void;
  off(event: string, listener: (...args: any[]) => void): void;

  // Client mode methods
  mailFrom(address: string, params: any, callback: (err: Error | null) => void): void;
  rcptTo(address: string, callback: (err: Error | null) => void): void;
  data(rawMessage: Uint8Array | Buffer | string, callback: (err: Error | null, reply?: any) => void): void;
  authPlain(user: string, pass: string, callback: (err: Error | null) => void): void;
  startTLS(callback: (err: Error | null) => void): void;
  quit(): void;
  sendLine(line: string): void;
  readReply(callback: (reply: any) => void): void;

  // Getters
  readonly isServer: boolean;
  readonly state: string;
  readonly authenticated: boolean;
  readonly username: string | null;
  readonly clientHostname: string | null;
  readonly remoteAddress: string | null;
  readonly isTLS: boolean;
  readonly messageCount: number;
  readonly capabilities: Record<string, any> | null;
}

// ============================================================
//  Mail objects
// ============================================================

interface InboundMail {
  from: string;
  to: string[];
  params: Record<string, any>;

  subject: string | null;
  messageId: string | null;
  date: string | null;
  headerFrom: string | null;
  headerTo: string | null;

  auth: AuthResults;

  raw: Uint8Array;
  size: number;

  text: string | null;
  html: string | null;
  attachments: Attachment[] | null;

  on(event: 'data', listener: (chunk: Uint8Array) => void): void;
  on(event: 'end', listener: () => void): void;

  accept(): void;
  reject(code?: number, message?: string): void;
}

interface AuthResults {
  dkim: 'pass' | 'fail' | 'none' | 'temperror' | 'permerror' | null;
  dkimDomain: string | null;
  spf: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | null;
  dmarc: 'pass' | 'fail' | 'none' | null;
  dmarcPolicy: 'none' | 'quarantine' | 'reject' | null;
  rdns: 'pass' | 'fail' | 'none' | null;
  rdnsHostname: string | null;
}

interface AuthSession {
  username: string;
  password: string;
  remoteAddress: string;
  isTLS: boolean;
  accept(): void;
  reject(): void;
}

interface AuthCallback {
  accept(): void;
  reject(): void;
}

interface SessionInfo {
  username: string;
  remoteAddress: string;
  isTLS: boolean;
  authenticated: boolean;
}

interface ConnectionInfo {
  id: string;
  remoteAddress: string;
  reject(): void;
}

// ============================================================
//  Message compose/parse
// ============================================================

interface ComposeOptions {
  from: string | { name?: string; address: string };
  to: string | string[] | { name?: string; address: string }[];
  cc?: string | string[];
  bcc?: string | string[];
  subject?: string;
  text?: string;
  html?: string;
  attachments?: AttachmentInput[];
  headers?: Record<string, string>;
  messageId?: string;
  date?: Date;
  replyTo?: string;
  priority?: 'high' | 'normal' | 'low';
}

interface AttachmentInput {
  filename: string;
  content: string | Buffer | Uint8Array;
  contentType?: string;
  cid?: string;
}

interface ComposedMessage {
  raw: Uint8Array;
  messageId: string;
  smtpProfile: {
    smtpUtf8Needed: boolean;
    bodyIs8bit: boolean;
    size: number;
  };
}

interface ParsedMessage {
  subject: string | null;
  from: string | null;
  to: string | null;
  date: string | null;
  messageId: string | null;
  text: string | null;
  html: string | null;
  attachments: Attachment[];
}

interface Attachment {
  filename: string;
  contentType: string;
  content: Uint8Array;
  size: number;
  cid: string | null;
}

// ============================================================
//  Domain material
// ============================================================

interface DomainOptions {
  dkim?: {
    selector?: string;
    algo?: 'rsa-sha256' | 'ed25519-sha256';
    privateKey?: string;
  };
  tls?: {
    key: string | Buffer;
    cert: string | Buffer;
    ca?: string | Buffer;
  };
}

interface DomainMaterial {
  domain: string;
  dkim: {
    selector: string;
    algo: string;
    privateKey: string;
    publicKey: string;
    dnsValue: string;
  };
  tls?: {
    key: string | Buffer;
    cert: string | Buffer;
    ca?: string | Buffer;
  };
  requiredDNS: DNSRecord[];
  verifyDNS(callback: (err: Error | null, results?: any) => void): void;
}

interface DNSRecord {
  type: string;
  name: string;
  value: string;
}

interface DKIMKeyInfo {
  selector: string;
  algo: string;
  privateKey: string;
}

// ============================================================
//  DKIM
// ============================================================

interface DKIMSignOptions {
  domain: string;
  selector: string;
  privateKey: string;
  algo?: 'rsa-sha256' | 'ed25519-sha256';
  signHeaders?: string[];
}

interface DKIMSignResult {
  header: string;
  signature: string;
  bodyHash: string;
  signedHeaders: string[];
  message: string;
}

interface DKIMVerifyResult {
  result: 'pass' | 'fail' | 'none' | 'temperror' | 'permerror';
  domain?: string;
  selector?: string;
  algo?: string;
  reason?: string;
}

// ============================================================
//  SPF / DMARC
// ============================================================

interface SPFResult {
  result: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror';
  domain: string;
  mechanism?: string;
  reason?: string;
}

interface DMARCOptions {
  fromDomain: string;
  dkimResult: string;
  dkimDomain?: string;
  spfResult: string;
  spfDomain?: string;
}

interface DMARCResult {
  result: 'pass' | 'fail' | 'none';
  domain: string;
  policy?: string;
  dkimAligned?: boolean;
  spfAligned?: boolean;
}

// ============================================================
//  Send
// ============================================================

interface SendOptions extends ComposeOptions {
  relay?: RelayOptions;
  raw?: Uint8Array | Buffer | string;
  localHostname?: string;
  timeout?: number;
  ignoreTLS?: boolean;
}

interface SendInfo {
  messageId: string;
  accepted?: any[];
  rejected?: any[];
  host?: string;
}

interface BounceInfo {
  id: number;
  from: string;
  to: string[];
  error: string;
}

interface RetryInfo {
  id: number;
  attempts: number;
  error: string;
  nextRetry: number;
}

interface MXRecord {
  exchange: string;
  priority: number;
}

// ============================================================
//  Default export
// ============================================================

declare const _default: {
  createServer: typeof createServer;
  buildDomainMailMaterial: typeof buildDomainMailMaterial;
  composeMessage: typeof composeMessage;
  parseMessage: typeof parseMessage;
  sendMail: typeof sendMail;
  resolveMX: typeof resolveMX;
  dkimSign: typeof dkimSign;
  dkimVerify: typeof dkimVerify;
  checkSPF: typeof checkSPF;
  checkDMARC: typeof checkDMARC;
  Server: typeof Server;
  SMTPSession: typeof SMTPSession;
  wire: typeof wire;
};

export default _default;
