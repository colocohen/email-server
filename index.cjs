
// CommonJS wrapper — for require('email-server')
// Loads the ESM module and re-exports all named exports.

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
    'Use: const mail = await require("email-server").init()\n' +
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

  // Lazy getters — work after init() resolves
  get createServer() { return getSync().createServer; },
  get buildDomainMailMaterial() { return getSync().buildDomainMailMaterial; },
  get composeMessage() { return getSync().composeMessage; },
  get parseMessage() { return getSync().parseMessage; },
  get sendMail() { return getSync().sendMail; },
  get resolveMX() { return getSync().resolveMX; },
  get dkimSign() { return getSync().dkimSign; },
  get dkimVerify() { return getSync().dkimVerify; },
  get checkSPF() { return getSync().checkSPF; },
  get checkDMARC() { return getSync().checkDMARC; },
  get Server() { return getSync().Server; },
  get SMTPSession() { return getSync().SMTPSession; },
  get wire() { return getSync().wire; }
};
