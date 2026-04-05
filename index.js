
import * as wire from './src/wire.js';
import { SMTPSession } from './src/session.js';
import { Server, createServer } from './src/server.js';
import { buildDomainMailMaterial } from './src/domain.js';
import { composeMessage, parseMessage } from './src/message.js';
import { sendMail, resolveMX } from './src/client.js';
import { sign as dkimSign, verify as dkimVerify } from './src/dkim.js';
import { checkSPF } from './src/spf.js';
import { checkDMARC } from './src/dmarc.js';

export {
  createServer,
  buildDomainMailMaterial,
  composeMessage,
  parseMessage,
  sendMail,
  resolveMX,
  dkimSign,
  dkimVerify,
  checkSPF,
  checkDMARC,
  Server,
  SMTPSession,
  wire,
};

export default {
  createServer,
  buildDomainMailMaterial,
  composeMessage,
  parseMessage,
  sendMail,
  resolveMX,
  dkimSign,
  dkimVerify,
  checkSPF,
  checkDMARC,
  Server,
  SMTPSession,
  wire,
};
