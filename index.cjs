
// ============================================================================
//  email-server — CommonJS wrapper
// ----------------------------------------------------------------------------
//  Node ESM modules can't be loaded synchronously from CommonJS. This wrapper
//  provides an async `.init()` entry point; once it resolves, every named
//  export is attached to module.exports and accessible via require().
//
//  Usage from CommonJS:
//
//     const mail = require('email-server');
//     await mail.init();
//     mail.createServer({ ... });
//
//  Usage from ESM: skip this entirely — use index.js directly via
//     import mail from 'email-server';
// ============================================================================

async function load() {
  const mod = await import('./index.js');
  return mod.default || mod;
}

let cached = null;
let pending = null;

function getSync() {
  if (cached) return cached;
  throw new Error(
    'email-server: CommonJS require() needs async init.\n' +
    'Use: const mail = require("email-server"); await mail.init();\n' +
    'Or switch to: import mail from "email-server"'
  );
}

module.exports = {
  init: function() {
    if (cached) return Promise.resolve(cached);
    if (pending) return pending;
    pending = load().then(function(mod) {
      cached = mod;
      // Copy all exports to module.exports for subsequent require() calls
      Object.keys(mod).forEach(function(k) {
        module.exports[k] = mod[k];
      });
      return mod;
    });
    return pending;
  },

  // ---- Lazy getters — throw before init(), work after ----

  // Server
  get createServer() { return getSync().createServer; },
  get Server()       { return getSync().Server; },

  // Sessions (custom transports)
  get SMTPSession()  { return getSync().SMTPSession; },
  get IMAPSession()  { return getSync().IMAPSession; },
  get POP3Session()  { return getSync().POP3Session; },

  // Domain material (DKIM + DNS + MTA-STS + TLS-RPT)
  get buildDomainMailMaterial() { return getSync().buildDomainMailMaterial; },

  // Message compose / parse
  get composeMessage() { return getSync().composeMessage; },
  get parseMessage()   { return getSync().parseMessage; },

  // Outbound SMTP
  get sendMail()   { return getSync().sendMail; },
  get resolveMX()  { return getSync().resolveMX; },

  // DSN (RFC 3461/3464)
  get buildDsn()   { return getSync().buildDsn; },

  // Standalone auth checks
  get dkimSign()   { return getSync().dkimSign; },
  get dkimVerify() { return getSync().dkimVerify; },
  get checkSPF()   { return getSync().checkSPF; },
  get checkDMARC() { return getSync().checkDMARC; },

  // IMAP constants + metadata helpers
  get SPECIAL_USE()             { return getSync().SPECIAL_USE; },
  get FLAGS()                   { return getSync().FLAGS; },
  get extractEnvelope()         { return getSync().extractEnvelope; },
  get extractBodyStructure()    { return getSync().extractBodyStructure; },
  get extractMessageMetadata()  { return getSync().extractMessageMetadata; },

  // IDN + address utilities
  get domainToAscii()            { return getSync().domainToAscii; },
  get domainToUnicode()          { return getSync().domainToUnicode; },
  get splitAddress()             { return getSync().splitAddress; },
  get isAscii()                  { return getSync().isAscii; },
  get addressNeedsSmtputf8()     { return getSync().addressNeedsSmtputf8; },
  get addressForAsciiOnlyPeer()  { return getSync().addressForAsciiOnlyPeer; },

  // Low-level wire utilities
  get wire() { return getSync().wire; }
};
