<p align="center">
  <img src="https://github.com/colocohen/email-server/raw/main/email-server.svg" width="450" alt="email-server"/>
</p>

<h1 align="center">email-server</h1>
<p align="center">
  <em>📧 Easily run your own mail server — complete email infrastructure with full control, in a single Node.js package with zero dependencies.</em>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/email-server">
    <img src="https://img.shields.io/npm/v/email-server?color=blue" alt="npm">
  </a>
  <img src="https://img.shields.io/badge/status-in%20development-yellow" alt="status">
  <img src="https://img.shields.io/github/license/colocohen/email-server?color=brightgreen" alt="license">
</p>

---

> **⚠️ Project status: *Active development*.**  
> APIs may change without notice until we reach v1.0.  
> Use at your own risk and please report issues!

## ✨ Features

* 📬 **Full SMTP Server** – inbound (port 25), submission (port 587), implicit TLS (port 465).
* 📤 **Full SMTP Client** – send mail directly via MX lookup or through a relay/smarthost.
* 🔑 **DKIM Sign & Verify** – RSA-SHA256 and Ed25519-SHA256, automatic on send/receive.
* 🛡 **SPF, DMARC, rDNS** – all inbound auth checks run automatically in parallel.
* 📦 **MIME Compose & Parse** – text, HTML, attachments, inline images, UTF-8 — cross-compatible with nodemailer.
* 🔁 **Connection Pooling** – per-domain pools with RSET reuse, rate limiting, retry with backoff, idle cleanup.
* 🔒 **STARTTLS + Implicit TLS** – both server and client, SNI support, multi-domain.
* 🧩 **One Session, Two Modes** – `SMTPSession({ isServer: false })` for client mode — one unified API for both server and client.
* 🏗 **Domain Management** – `buildDomainMailMaterial()` auto-generates DKIM keys and DNS records.
* 🛡 **Security Hardened** – SMTP smuggling protection, backpressure handling, graceful shutdown, PROXY protocol.
* ⚡ **Zero Dependencies** – only `node:` builtins. ~5,500 lines of code.

## 📦 Installation

```
npm i email-server
```

## 🚀 Quick Start

### Receive Email

```js
import mail from 'email-server';

var mat = mail.buildDomainMailMaterial('example.com');
console.log(mat.requiredDNS); // DNS records to configure

var server = mail.createServer({
  hostname: 'mx.example.com',
  ports: { inbound: 25, submission: 587, secure: 465 }
});

server.addDomain(mat);

server.on('inboundMail', function(mail) {
  // Available immediately: envelope, headers, all auth checks
  console.log(mail.from);          // 'sender@other.com'
  console.log(mail.to);            // ['user@example.com']
  console.log(mail.subject);       // 'Hello!'
  console.log(mail.auth.dkim);     // 'pass'
  console.log(mail.auth.spf);      // 'pass'
  console.log(mail.auth.dmarc);    // 'pass'
  console.log(mail.auth.rdns);     // 'pass'

  // Reject early based on auth (before processing body)
  if (mail.auth.dkim === 'fail') {
    mail.reject(550, 'DKIM verification failed');
    return;
  }

  // Process body
  mail.on('end', function() {
    console.log(mail.text);
    console.log(mail.html);
    console.log(mail.attachments);
    mail.accept();
  });
});

server.listen(function() {
  console.log('SMTP server ready');
});
```

### Send Email

```js
import mail from 'email-server';

// Direct delivery (MX lookup)
mail.sendMail({
  from: 'alice@example.com',
  to: 'bob@other.net',
  subject: 'Hello from email-server!',
  text: 'This is a test email.',
  html: '<p>This is a <b>test</b> email.</p>',
  attachments: [{
    filename: 'report.pdf',
    content: pdfBuffer
  }]
}, function(err, info) {
  console.log(info.messageId);
});

// Via relay/smarthost
mail.sendMail({
  from: 'alice@example.com',
  to: 'bob@other.net',
  subject: 'Via relay',
  text: 'Sent through a relay server.',
  relay: {
    host: 'smtp.relay.com',
    port: 587,
    auth: { user: 'alice', pass: 'secret' }
  }
}, function(err, info) {
  console.log('Sent:', info.messageId);
});
```

### Server with DKIM Signing + Submission Auth

```js
import mail from 'email-server';

var mat = mail.buildDomainMailMaterial('mycompany.com', {
  dkim: { selector: 's2025', algo: 'rsa-sha256' }
});

var server = mail.createServer({
  hostname: 'mx.mycompany.com',
  ports: { inbound: 25, submission: 587 },
  pool: {
    maxPerDomain: 5,
    maxMessagesPerConn: 100,
    rateLimitPerMinute: 60
  }
});

server.addDomain(mat);

// Authenticate submission users
server.on('auth', function(session) {
  if (session.username === 'alice' && session.password === 'secret') {
    session.accept();
  } else {
    session.reject();
  }
});

// Handle submitted mail — sign with DKIM and send
server.on('submissionMail', function(mail, session) {
  server.send({
    from: mail.from,
    to: mail.to,
    subject: mail.subject,
    text: mail.text,
    html: mail.html,
    attachments: mail.attachments
  }, function(err) {
    if (err) mail.reject(451, 'Send failed');
    else mail.accept();
  });
});

server.listen();
```

### Domain Setup with Auto DKIM Keys

```js
import mail from 'email-server';

// Auto-generates RSA-2048 DKIM keypair
var mat = mail.buildDomainMailMaterial('example.com');

// Or Ed25519
var mat = mail.buildDomainMailMaterial('example.com', {
  dkim: { algo: 'ed25519-sha256', selector: 'ed2025' }
});

// Get DNS records to configure
for (var rec of mat.requiredDNS) {
  console.log(rec.type, rec.name, '→', rec.value);
}
// TXT s2025._domainkey.example.com → v=DKIM1; k=rsa; p=MIIBIjAN...
// TXT example.com → v=spf1 mx a ~all
// TXT _dmarc.example.com → v=DMARC1; p=quarantine; adkim=s; aspf=s
// MX  example.com → 10 mx.example.com

// Verify DNS is configured correctly
mat.verifyDNS(function(err, results) {
  console.log(results);
});
```

## 📚 API

### Module Exports

```js
import mail from 'email-server';

mail.createServer(options)                  // Create SMTP server
mail.buildDomainMailMaterial(domain, opts)   // Generate DKIM keys + DNS records
mail.composeMessage(options)                // Build RFC 5322 message
mail.parseMessage(raw)                      // Parse raw email → { text, html, attachments }
mail.sendMail(options, callback)            // Send mail (direct or relay)
mail.resolveMX(domain, callback)            // MX lookup
mail.dkimSign(raw, options)                 // Sign message with DKIM
mail.dkimVerify(raw, callback)             // Verify DKIM signature
mail.checkSPF(ip, domain, callback)         // SPF check
mail.checkDMARC(options, callback)          // DMARC check
mail.SMTPSession                            // Low-level session constructor
mail.wire                                   // SMTP wire protocol utilities
```

### `createServer(options)`

| Option | Type | Default | Description |
|---|---|---|---|
| `hostname` | string | `'localhost'` | Server hostname for EHLO/banner |
| `ports` | object | `{ inbound: 25 }` | `{ inbound, submission, secure }` |
| `maxSize` | number | 25 MB | Maximum message size in bytes |
| `maxRecipients` | number | 100 | Maximum RCPT TO per message |
| `relay` | object | null | `{ host, port, auth }` smarthost |
| `pool` | object | defaults | Connection pool settings |
| `useProxy` | boolean | false | Enable HAProxy PROXY protocol |
| `closeTimeout` | number | 30000 | Graceful shutdown timeout (ms) |
| `SNICallback` | function | null | `(servername, cb)` for dynamic TLS |
| `dkimCallback` | function | null | `(domain, cb)` for dynamic DKIM |
| `onSecure` | function | null | Post-TLS handshake callback |

#### Pool Options

| Option | Type | Default | Description |
|---|---|---|---|
| `maxPerDomain` | number | 3 | Max simultaneous connections per domain |
| `maxMessagesPerConn` | number | 100 | Close connection after N messages |
| `idleTimeout` | number | 30000 | Close idle connection after (ms) |
| `rateLimitPerMinute` | number | 60 | Max messages per domain per minute |
| `reconnectDelay` | number | 1000 | Min time between connections to same domain |

#### Server Events

| Event | Callback | Description |
|---|---|---|
| `inboundMail` | `(mail)` | Incoming email with auth results |
| `submissionMail` | `(mail, session)` | Authenticated submission |
| `auth` | `(session)` | Authentication request |
| `connection` | `(info)` | New connection (can reject) |
| `sending` | `(options)` | Outbound mail queued |
| `sent` | `(info)` | Outbound mail delivered |
| `bounce` | `(info)` | Permanent delivery failure |
| `retry` | `(info)` | Temporary failure, will retry |
| `sendError` | `(err, options)` | Send error |
| `ready` | `()` | Server listening |
| `error` | `(err)` | Server error |
| `tlsError` | `(err)` | TLS handshake error |

#### Mail Object (inboundMail)

```js
server.on('inboundMail', function(mail) {
  // Envelope
  mail.from              // string — MAIL FROM address
  mail.to                // string[] — RCPT TO addresses

  // Headers (parsed)
  mail.subject           // string
  mail.messageId         // string
  mail.date              // string
  mail.headerFrom        // string — From header value
  mail.headerTo          // string — To header value

  // Auth results (all checks completed before this event)
  mail.auth.dkim         // 'pass' | 'fail' | 'none' | 'temperror' | 'permerror'
  mail.auth.dkimDomain   // string — signing domain
  mail.auth.spf          // 'pass' | 'fail' | 'softfail' | 'neutral' | 'none'
  mail.auth.dmarc        // 'pass' | 'fail' | 'none'
  mail.auth.dmarcPolicy  // 'none' | 'quarantine' | 'reject'
  mail.auth.rdns         // 'pass' | 'fail' | 'none'
  mail.auth.rdnsHostname // string — PTR hostname

  // Raw
  mail.raw               // Uint8Array — full message
  mail.size              // number — bytes

  // Body (available after 'end' event)
  mail.on('data', function(chunk) { })
  mail.on('end', function() {
    mail.text            // string
    mail.html            // string
    mail.attachments     // [{ filename, contentType, content, size, cid }]
  })

  // Response
  mail.accept()                     // 250 Ok
  mail.reject(code, message)        // e.g. 550, 'User unknown'
});
```

### `SMTPSession(options)`

Low-level SMTP session — works in both server and client mode:

```js
import { SMTPSession } from 'email-server';

// Server mode
var session = new SMTPSession({ isServer: true, hostname: 'mx.local' });
session.on('send', function(data) { socket.write(data); });
session.on('message', function(mail) { mail.accept(); });
socket.on('data', function(chunk) { session.feed(chunk); });
session.greet();

// Client mode
var session = new SMTPSession({ isServer: false, hostname: 'client.local' });
session.on('send', function(data) { socket.write(data); });
session.on('ready', function() {
  session.mailFrom('alice@example.com', {}, function(err) {
    session.rcptTo('bob@other.net', function(err) {
      session.data(rawMessage, function(err) {
        session.quit();
      });
    });
  });
});
socket.on('data', function(chunk) { session.feed(chunk); });
session.greet();
```

### `buildDomainMailMaterial(domain, options)`

```js
var mat = mail.buildDomainMailMaterial('example.com', {
  dkim: {
    selector: 's2025',           // default: 's' + YYYYMM
    algo: 'rsa-sha256',          // or 'ed25519-sha256'
    privateKey: '...',           // optional — auto-generates if not provided
  },
  tls: {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt')
  }
});

mat.domain             // 'example.com'
mat.dkim.selector      // 's2025'
mat.dkim.privateKey    // PEM string
mat.dkim.publicKey     // PEM string
mat.dkim.dnsValue      // 'v=DKIM1; k=rsa; p=MIIBIjAN...'
mat.requiredDNS        // [{ type, name, value }]
mat.verifyDNS(cb)      // check DNS configuration
```

## 🔐 Security

### Inbound Auth Flow

Every inbound email is automatically verified before `inboundMail` fires:

```
Message received
  ↓ parallel (all DNS-cached)
  ├── DKIM verify   → mail.auth.dkim
  ├── SPF check     → mail.auth.spf
  └── rDNS (FCrDNS) → mail.auth.rdns
  ↓ after all three
  └── DMARC check   → mail.auth.dmarc
  ↓
  emit('inboundMail')
```

### Outbound DKIM Signing

`server.send()` automatically signs with DKIM if the domain has been registered via `addDomain()`:

```
server.send({ from, to, subject, text })
  ↓
  compose message → DKIM sign → connection pool → deliver
```

### Built-in Protections

* **SMTP Smuggling** — bare `\n` normalized to `\r\n` in DATA body
* **Backpressure** — `socket.write()` return value respected, pause/resume on both sides
* **Graceful Shutdown** — `421` sent to all connections, timeout before force close
* **PROXY Protocol** — HAProxy v1 support for load-balanced deployments
* **Connection ID** — unique ID per connection for logging and tracking
* **Timer Cleanup** — all timers and callbacks cleaned on connection close
* **DNS Cache** — shared cache across DKIM/SPF/DMARC/rDNS (5-minute TTL)

## 🧪 Testing

```bash
npm test                                    # all tests

# Individual test suites
node tests/test_wire.js                     # 57 tests — SMTP wire protocol
node tests/test_session.js                  # 64 tests — session state machine
node tests/test_message.js                  # 70 tests — MIME compose/parse
node tests/test_dkim.js                     # 44 tests — DKIM sign/verify
node tests/test_server.js                   # 39 tests — server API
node tests/test_session_integration.js      # 13 tests — session vs nodemailer
node tests/test_client.js                   # 28 tests — client + relay
node tests/test_e2e.js                      # 12 tests — end-to-end DKIM flow
node tests/test_message_integration.js      # 44 tests — compose/parse vs nodemailer
node tests/test_integration.js              # 45 tests — wire parser vs real SMTP
```

**327 tests, 0 failures.** Cross-compatible with nodemailer/smtp-server/mailparser.

## 📁 Project Structure

```
index.js                — ESM exports
index.cjs               — CommonJS wrapper
index.d.ts              — TypeScript declarations
src/
  utils.js              — binary helpers, shared utilities
  dns-cache.js          — shared DNS cache (used by dkim, spf, dmarc, rdns, pool)
  wire.js               — SMTP wire protocol parse/serialize
  session.js            — SMTPSession (isServer: true/false)
  server.js             — createServer, domain management, auth flow
  client.js             — SMTPConnection, sendMail, MX lookup
  pool.js               — OutboundPool (connection reuse, rate limiting, retry)
  message.js            — MIME compose/parse (RFC 5322)
  domain.js             — buildDomainMailMaterial, DKIM key generation
  dkim.js               — DKIM sign/verify (RFC 6376)
  spf.js                — SPF check (RFC 7208)
  dmarc.js              — DMARC check (RFC 7489)
  rdns.js               — FCrDNS + EHLO hostname verification
tests/                  — 327 tests
```

## 🛣 Roadmap

✅ = Completed  ⏳ = Planned

### ✅ Completed

| Status | Item |
|---|---|
| ✅ | SMTP Server — inbound, submission, implicit TLS |
| ✅ | SMTP Client — direct (MX) and relay delivery |
| ✅ | SMTPSession — unified server/client (isServer flag) |
| ✅ | STARTTLS — both server and client |
| ✅ | AUTH PLAIN / LOGIN |
| ✅ | MIME Compose — text, HTML, attachments, inline CID, UTF-8 |
| ✅ | MIME Parse — cross-compatible with nodemailer/mailparser |
| ✅ | DKIM Sign — RSA-SHA256 + Ed25519-SHA256, auto on send |
| ✅ | DKIM Verify — DNS lookup with cache, auto on receive |
| ✅ | SPF Check — ip4, ip6, a, mx, include, redirect (RFC 7208) |
| ✅ | DMARC Check — alignment, organizational domain fallback |
| ✅ | Reverse DNS — FCrDNS + EHLO hostname verification |
| ✅ | Connection Pooling — RSET reuse, rate limit, retry, backoff |
| ✅ | Domain Management — auto DKIM key generation, DNS records |
| ✅ | PROXY Protocol — HAProxy v1 support |
| ✅ | SMTP Smuggling Protection — bare LF normalization |
| ✅ | 8BITMIME, SMTPUTF8, PIPELINING, ENHANCEDSTATUSCODES |
| ✅ | Zero dependencies — `node:` builtins only |
| ✅ | 327 automated tests |

### ⏳ Planned

| Status | Item | Notes |
|---|---|---|
| ⏳ | POP3 Server | Receive mail via POP3 |
| ⏳ | IMAP Server | Full mailbox access |
| ⏳ | OAuth2 / XOAUTH2 | Gmail, Outlook auth |
| ⏳ | DSN (RFC 3461) | Delivery Status Notifications |
| ⏳ | REQUIRETLS (RFC 8689) | End-to-end TLS enforcement |
| ⏳ | Well-known services | `{ service: 'gmail' }` presets |
| ⏳ | Rate limit per IP | Inbound connection protection |
| ⏳ | Punycode/IDN | Internationalized domain names |
| ⏳ | Benchmarks | Throughput, memory, connections |

## 🤝 Contributing

Pull requests are welcome!  
Please open an issue before submitting major changes.

## 💖 Sponsors

This project is part of the [colocohen](https://github.com/colocohen) Node.js infrastructure stack (QUIC, WebRTC, DNSSEC, TLS, and more).  
You can support ongoing development via [GitHub Sponsors](https://github.com/sponsors/colocohen).

## 📚 References

* [RFC 5321 – SMTP](https://datatracker.ietf.org/doc/html/rfc5321)
* [RFC 5322 – Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322)
* [RFC 6376 – DKIM Signatures](https://datatracker.ietf.org/doc/html/rfc6376)
* [RFC 7208 – SPF](https://datatracker.ietf.org/doc/html/rfc7208)
* [RFC 7489 – DMARC](https://datatracker.ietf.org/doc/html/rfc7489)
* [RFC 8463 – Ed25519 for DKIM](https://datatracker.ietf.org/doc/html/rfc8463)

## 📜 License

**Apache License 2.0**

```
Copyright © 2025 colocohen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
