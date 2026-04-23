
// ============================================================================
//  email-server — main entry point (ESM)
// ----------------------------------------------------------------------------
//  Re-exports the public API. Each module's internal helpers stay internal;
//  this file is what users see when they `import from 'email-server'`.
// ============================================================================

import * as wire from './src/smtp_wire.js';

// Server + session classes
import { SMTPSession } from './src/smtp_session.js';
import {
  IMAPSession,
  SPECIAL_USE,
  FLAGS,
  extractEnvelope,
  extractBodyStructure,
  extractMessageMetadata
} from './src/imap_session.js';
import { POP3Session } from './src/pop3_session.js';
import { Server, createServer } from './src/server.js';

// Domain / DNS / MTA-STS material
import { buildDomainMailMaterial } from './src/domain.js';

// Message compose / parse
import { composeMessage, parseMessage } from './src/message.js';

// Outbound
import { sendMail, resolveMX } from './src/smtp_client.js';

// DSN (RFC 3461/3464)
import { buildDsn } from './src/dsn.js';

// Auth checks
import { sign as dkimSign, verify as dkimVerify } from './src/dkim.js';
import { checkSPF } from './src/spf.js';
import { checkDMARC } from './src/dmarc.js';

// IDN / address helpers (for app code that needs to pre-process addresses)
import {
  domainToAscii,
  domainToUnicode,
  splitAddress,
  isAscii,
  addressNeedsSmtputf8,
  addressForAsciiOnlyPeer
} from './src/utils.js';


export {
  // Server
  createServer,
  Server,

  // Sessions (for custom transports)
  SMTPSession,
  IMAPSession,
  POP3Session,

  // Domain material
  buildDomainMailMaterial,

  // Message compose/parse
  composeMessage,
  parseMessage,

  // Outbound SMTP
  sendMail,
  resolveMX,

  // DSN
  buildDsn,

  // Auth checks (standalone)
  dkimSign,
  dkimVerify,
  checkSPF,
  checkDMARC,

  // IMAP constants + metadata helpers
  SPECIAL_USE,
  FLAGS,
  extractEnvelope,
  extractBodyStructure,
  extractMessageMetadata,

  // IDN + address utilities
  domainToAscii,
  domainToUnicode,
  splitAddress,
  isAscii,
  addressNeedsSmtputf8,
  addressForAsciiOnlyPeer,

  // Low-level wire utilities
  wire
};


export default {
  createServer,
  Server,
  SMTPSession,
  IMAPSession,
  POP3Session,
  buildDomainMailMaterial,
  composeMessage,
  parseMessage,
  sendMail,
  resolveMX,
  buildDsn,
  dkimSign,
  dkimVerify,
  checkSPF,
  checkDMARC,
  SPECIAL_USE,
  FLAGS,
  extractEnvelope,
  extractBodyStructure,
  extractMessageMetadata,
  domainToAscii,
  domainToUnicode,
  splitAddress,
  isAscii,
  addressNeedsSmtputf8,
  addressForAsciiOnlyPeer,
  wire
};
