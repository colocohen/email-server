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

### Protocols — full server and client for all three

* 📬 **SMTP Server** — inbound (port 25), submission (port 587), implicit TLS (465). STARTTLS, AUTH PLAIN/LOGIN, XOAUTH2, PROXY protocol.
* 📤 **SMTP Client** — direct delivery via MX lookup or via relay/smarthost. Connection pooling, retry with backoff, per-domain rate limiting.
* 📥 **IMAP Server** — RFC 3501 + UIDPLUS, CONDSTORE, QRESYNC, SORT, THREAD, IDLE, MOVE, NAMESPACE, SPECIAL-USE, LITERAL+, ENABLE, COMPRESS=DEFLATE, LIST-EXTENDED, LIST-STATUS, WITHIN, QUOTA, METADATA.
* 📫 **IMAP Client** — full client-mode `IMAPSession` with LOGIN / XOAUTH2, FETCH, SEARCH, STORE, COPY, MOVE, IDLE, LIST-EXTENDED, QUOTA, METADATA, COMPRESS.
* 📭 **POP3 Server** — RFC 1939 + RFC 2449 CAPA, UIDL, TOP, STLS, SASL, XOAUTH2. Same `mailboxSession` event model as IMAP.
* 📮 **POP3 Client** — connect, authenticate (USER/PASS/APOP/XOAUTH2), LIST, RETR, DELE, TOP.

### Authentication and message security

* 🔑 **DKIM** — RSA-SHA256 and Ed25519-SHA256, automatic sign on send and verify on receive.
* 🛡 **SPF, DMARC, rDNS** — all inbound auth checks run automatically in parallel before `mail` fires.
* 🔐 **XOAUTH2 everywhere** — SMTP submission, IMAP, and POP3 — both server and client directions.
* 🛡 **REQUIRETLS (RFC 8689)** — enforce TLS end-to-end on sensitive mail.
* 🌐 **MTA-STS (RFC 8461) + TLS-RPT (RFC 8460)** — policy generation, DNS records, and HTTP handler all included.

### Message handling

* 📦 **MIME compose & parse** — text, HTML, attachments, inline images, UTF-8 — cross-compatible with nodemailer / mailparser.
* 🌍 **SMTPUTF8 + IDN (RFC 6531 + 5890)** — international addresses with automatic Punycode fallback when the peer doesn't support UTF-8.
* 📣 **DSN (RFC 3461/3464)** — parse NOTIFY / ORCPT / RET / ENVID; generate multipart/report delivery status notifications; `server.sendDsn()` API.
* 🏷 **Clean flag names** — use `'Seen'` not `'\\Seen'` — the library handles the protocol details.

### API and architecture

* 🧩 **Unified event model** — one pattern across SMTP, IMAP, and POP3: `server.on('auth')` + `server.on('smtpSession' | 'mailboxSession')`, then `session.on(...)` for storage handlers.
* 💾 **Bring your own storage** — the library is a protocol layer; it never holds or persists messages. You wire up any backend (SQLite, Postgres, S3, memory).
* 🔄 **IDLE push primitives** — `session.notifyExists / notifyRecent / notifyExpunge / notifyVanished / notifyFlags` wake IDLE clients the moment your backend changes.
* 🏗 **Domain management** — `buildDomainMailMaterial()` auto-generates DKIM keys and every DNS record you need (DKIM, SPF, DMARC, MX, MTA-STS, TLS-RPT).
* 🔒 **Multi-domain TLS** — SNI context caching with `server.clearTlsCache()` for Let's Encrypt rotation.
* 🎯 **Listener-gated capabilities** — advanced extensions (MOVE, QUOTA, METADATA) are advertised only when you wire up their handlers, so clients never attempt something that would return NO.
* ⚡ **Zero dependencies** — only `node:` builtins and the tiny `flat-ranges` library.


## 📦 Installation

```bash
npm install email-server
```

**Requirements:** Node.js 18+ (uses `node:crypto`, `node:url` IDN, `node:zlib` deflate-raw).


## 🚀 Quick Start

The Quick Start covers three scenarios that together show the whole surface: receiving mail, sending mail, and letting users retrieve it over IMAP. A full combined server comes at the end.

### 1. Receive Email

Inbound SMTP on port 25 — other mail servers delivering to your users. No auth; SPF/DKIM/DMARC/rDNS checks run automatically before the `mail` event fires.

```js
import { createServer, buildDomainMailMaterial } from 'email-server';

// Generate DKIM keys + every DNS record you need
const mat = buildDomainMailMaterial('example.com', {
  // Optional: opt in to MTA-STS enforcement
  mtaSts: { mode: 'enforce', mx: ['mx.example.com'] },
  tlsRpt: { ruaEmail: 'tls-reports@example.com' }
});
console.log(mat.requiredDNS);    // Add these to your DNS provider

const server = createServer({
  hostname: 'mx.example.com',
  ports: { inbound: 25 }
});
server.addDomain(mat);

server.on('smtpSession', session => {
  session.on('mail', mail => {
    // Envelope + auth results available immediately
    console.log(mail.from, '→', mail.to);
    console.log('DKIM:', mail.auth.dkim, 'SPF:', mail.auth.spf, 'DMARC:', mail.auth.dmarc);

    // Reject on DMARC policy
    if (mail.auth.dmarc === 'fail' && mail.auth.dmarcPolicy === 'reject') {
      return mail.reject(550, 'DMARC policy rejection');
    }

    // Stream body, then commit
    mail.on('data', chunk => { /* bytes arriving (Uint8Array) */ });
    mail.on('end', () => {
      console.log(mail.subject, mail.text, mail.html);
      console.log(mail.attachments.length, 'attachments');

      // Save to your storage here (DB, filesystem, S3, ...)
      // saveMessage(mail.to, rawBytes);

      mail.accept();                 // → 250 OK
    });
  });
});

server.listen(() => console.log('SMTP MX on port 25'));
```

### 2. Submission and Send

Authenticated submission on port 587 — your users sending outbound. Library signs with DKIM and delivers via the outbound pool.

```js
import { createServer, buildDomainMailMaterial } from 'email-server';

const mat = buildDomainMailMaterial('example.com');
const server = createServer({
  hostname: 'mail.example.com',
  ports: { submission: 587 },
  tlsOptions: {
    cert: await fs.readFile('cert.pem'),
    key:  await fs.readFile('key.pem')
  }
});
server.addDomain(mat);

// Unified auth event — fires on SMTP submission, IMAP, and POP3.
server.on('auth', async info => {
  // info.protocol: 'smtp' | 'imap' | 'pop3'
  // info.authMethod: 'plain' | 'login' | 'xoauth2'
  const ok = await checkCredentials(info.username, info.password);
  ok ? info.accept() : info.reject('Invalid credentials');
});

server.on('smtpSession', session => {
  session.on('mail', mail => {
    mail.on('end', () => {
      // Library signs + delivers on your behalf
      mail.deliver((err, info) => {
        if (err) return mail.reject(451, 'Temporary failure');
        mail.accept();
      });
    });
  });
});

server.listen();
```

Or send standalone, without a server running:

```js
import { sendMail } from 'email-server';

// Direct delivery via MX lookup — no relay needed
sendMail({
  from: 'alice@example.com',
  to:   'bob@other.com',       // Unicode addresses work — SMTPUTF8 with IDN fallback
  subject: 'Hi',
  text: 'Body text',
  html: '<p>HTML body</p>',
  attachments: [
    { filename: 'report.pdf', content: pdfBuffer }
  ]
}, (err, info) => {
  console.log(info.accepted, info.rejected);
});

// Or via a relay/smarthost:
sendMail({
  relay: { host: 'smtp.sendgrid.net', port: 587, auth: { user: '...', pass: '...' } },
  from: 'alice@example.com',
  to: 'bob@other.com',
  subject: 'Hi', text: 'Body'
}, callback);
```

### 3. IMAP + POP3 Server

Both IMAP and POP3 share one event model — `mailboxSession`. Define your storage handlers once; both protocols use them.

```js
import { createServer } from 'email-server';

const server = createServer({
  hostname: 'mail.example.com',
  ports: { imap: 143, imaps: 993, pop3: 110, pop3s: 995 },
  tlsOptions: { cert, key }
});

server.on('auth', info => {
  // Same auth handler for IMAP and POP3
  info.protocol === 'imap' || info.protocol === 'pop3';
  checkCreds(info.username, info.password)
    ? info.accept() : info.reject('Invalid');
});

server.on('mailboxSession', session => {
  // session.protocol: 'imap' | 'pop3'
  // session.username, session.remoteAddress

  session.on('folders', cb => {
    // Return the user's folder list
    cb(null, [
      { name: 'INBOX', specialUse: null },
      { name: 'Sent',  specialUse: 'Sent' },
      { name: 'Drafts', specialUse: 'Drafts' }
    ]);
  });

  session.on('openFolder', (name, cb) => {
    cb(null, {
      uidValidity: 1,
      total:       await countMessages(session.username, name),
      unread:      await countUnread(session.username, name)
    });
  });

  session.on('resolveMessages', (range, cb) => {
    // Resolve a sequence/UID range to concrete message IDs
    cb(null, await listMessageIds(session.username, session.currentFolder, range));
  });

  session.on('messageMeta', (ids, cb) => {
    cb(null, ids.map(id => ({
      id: id,
      uid: id,
      size: getSize(id),
      internalDate: getDate(id),
      flags: ['Seen']               // clean names — no backslashes
    })));
  });

  session.on('messageBody', (id, responder) => {
    // Stream the raw RFC 5322 message — library handles zero-copy delivery
    responder.send({ length: size, stream: fs.createReadStream(pathFor(id)) });
  });

  // IMAP-only (POP3 doesn't have flags)
  session.on('setFlags', (ids, flags, cb) => {
    updateFlags(ids, flags); cb(null);
  });
});

server.listen();
```

When a new message arrives from SMTP, wake any active IDLE client:

```js
server.on('smtpSession', s => s.on('mail', m => m.on('end', () => {
  saveMessage(m.to, raw);
  // Push the new EXISTS count to any connected IDLE client
  server.forEachMailboxSession(session => {
    if (session.username === m.to[0] && session.currentFolder === 'INBOX') {
      session.notifyExists(newTotalCount);
    }
  });
  m.accept();
})));
```

### 4. IMAP Client

`IMAPSession` with `isServer: false` is a full client. Connect to any IMAP server — Gmail, Outlook, Fastmail, or your own.

```js
import net from 'node:net';
import tls from 'node:tls';
import { IMAPSession } from 'email-server';

const socket = tls.connect({ host: 'imap.gmail.com', port: 993 });
const client = new IMAPSession({ isServer: false });

client.on('send', data => socket.write(data));
socket.on('data', data => client.feed(data));

socket.once('secureConnect', () => {
  client.greet();
  client.on('ready', () => {
    client.xoauth2('user@gmail.com', bearerToken, err => {
      client.select('INBOX', (err, info) => {
        console.log(info.total, 'messages in INBOX');

        client.search({ seen: false }, (err, uids) => {
          client.fetch(uids, ['UID', 'ENVELOPE', 'BODY.PEEK[]'], (err, messages) => {
            messages.forEach(m => console.log(m.envelope.subject));
            client.logout();
          });
        });
      });
    });
  });
});
```

### 5. Complete Mail Server

Everything together — receive, store, serve, with auth consistency across all three protocols.

```js
import { createServer, buildDomainMailMaterial } from 'email-server';
import fs from 'node:fs/promises';

const mat = buildDomainMailMaterial('example.com', {
  mtaSts: { mode: 'enforce', mx: ['mx.example.com'] },
  tlsRpt: { ruaEmail: 'tls-reports@example.com' }
});

const server = createServer({
  hostname: 'mail.example.com',
  ports: {
    inbound:    25,     // Incoming mail from other servers
    submission: 587,    // Your users sending (STARTTLS)
    secure:     465,    // Your users sending (implicit TLS)
    imap:       143,    // IMAP (STARTTLS)
    imaps:      993,    // IMAP (implicit TLS)
    pop3:       110,    // POP3 (STARTTLS)
    pop3s:      995     // POP3 (implicit TLS)
  },
  tlsOptions: {
    cert: await fs.readFile('./cert.pem'),
    key:  await fs.readFile('./key.pem')
  }
});

server.addDomain(mat);

// One auth handler for SMTP submission, IMAP, and POP3
server.on('auth', async info => {
  const user = await db.users.findByEmail(info.username);
  if (!user) return info.reject('No such user');

  if (info.authMethod === 'xoauth2') {
    const valid = await verifyOAuth2Token(info.password, user);
    return valid ? info.accept() : info.reject('Token expired');
  }
  const ok = await verifyPassword(info.password, user.passwordHash);
  ok ? info.accept() : info.reject('Bad password');
});

// Inbound mail — save + notify IDLE clients
server.on('smtpSession', session => {
  session.on('mail', mail => {
    mail.on('end', async () => {
      const id = await db.messages.save(mail.to[0], mail.rawBytes);
      server.forEachMailboxSession(s => {
        if (s.username === mail.to[0] && s.currentFolder === 'INBOX') {
          s.notifyExists(await db.messages.countInFolder(s.username, 'INBOX'));
        }
      });
      mail.accept();
    });
  });
});

// IMAP + POP3 storage handlers (shared)
server.on('mailboxSession', session => {
  session.on('folders', cb => db.folders.list(session.username, cb));
  session.on('openFolder', (n, cb) => db.folders.open(session.username, n, cb));
  session.on('resolveMessages', (r, cb) => db.messages.resolve(session.username, session.currentFolder, r, cb));
  session.on('messageMeta', (ids, cb) => db.messages.meta(ids, cb));
  session.on('messageBody', (id, r) => db.messages.streamBody(id, r));
  session.on('setFlags', (ids, flags, cb) => db.messages.setFlags(ids, flags, cb));
  session.on('append', (folder, raw, flags, cb) => db.messages.append(session.username, folder, raw, flags, cb));
  session.on('copyMessages', (ids, dest, cb) => db.messages.copy(ids, dest, cb));
  session.on('move', (ids, dest, cb) => db.messages.move(ids, dest, cb));
  session.on('expunge', (ids, cb) => db.messages.expunge(ids, cb));

  // Opt-in: advertise QUOTA when you register the handler
  session.on('quota', (root, cb) => db.quotas.get(session.username, cb));

  // Opt-in: advertise METADATA when you register the handler
  session.on('getMetadata', (mbox, paths, cb) => db.metadata.get(session.username, mbox, paths, cb));
  session.on('setMetadata', (mbox, entries, cb) => db.metadata.set(session.username, mbox, entries, cb));
});

server.listen(() => console.log('mail stack online'));
```

See **[examples/demo_server.js](examples/demo_server.js)** for a complete working reference implementation with an in-memory backend, 16 seeded messages, and Thunderbird-tested IMAP on port 9143 + SMTP on port 9587.


## 🧠 Core Concepts

These five ideas explain how the library is structured. Read them once; the rest of the docs assume you know them.

### The event model — one pattern, three protocols

```
┌─────────────────────────────────────────────────────────┐
│ server.on('auth',          info     → accept/reject)    │ ← unified
│ server.on('smtpSession',   session                 )    │ ← SMTP
│ server.on('mailboxSession',session                 )    │ ← IMAP + POP3
└─────────────────────────────────────────────────────────┘
                             ↓
                    session.on('folders'         , ...)
                    session.on('messageMeta'     , ...)
                    session.on('messageBody'     , ...)
                    session.on('setFlags'        , ...)
                    session.on('append'          , ...)
                    session.on('move'            , ...)
                    session.on('quota'           , ...)
                    session.on('getMetadata'     , ...)
                    ... (24 total — see API Reference)
```

The same `mailboxSession` event fires for IMAP and POP3. You write storage handlers once and both protocols use them; the library maps each handler to the subset of commands that protocol supports. POP3 will never fire `setFlags` (it has no flags); IMAP will never fire `retr` (it fetches differently).

### Bring-your-own-storage — the library holds nothing

email-server is a protocol-layer library. It parses wire formats, enforces RFC behavior, and emits events — it never stores messages, user lists, folder structures, or flags. You provide all of that in your handlers. This means you can wire it to SQLite for a personal server, Postgres for production, S3 for cold storage, or even an in-memory `Map` for testing.

The examples throughout this document use handlers like `db.messages.save(...)` — that's your code, not the library's.

### Listener-gated capabilities — advertise only what you implement

Advanced IMAP extensions are expensive to half-implement. MOVE, QUOTA, and METADATA are therefore advertised only when your code has registered the corresponding handler. If your backend doesn't do quotas, the client never sees QUOTA in the CAPABILITY list and never attempts `GETQUOTAROOT`. When you later add `session.on('quota', ...)`, the capability automatically appears.

For this to work across authentication — where the capability list may change as the developer registers handlers inside `mailboxSession` — the server re-emits the fresh CAPABILITY list in the OK response to LOGIN and AUTHENTICATE (RFC 3501 §7.1). Clients built with this library honor that response automatically.

### Flag hygiene — clean names, no backslashes

When the library passes flags to your handlers, they come without the `\` prefix: `'Seen'`, `'Flagged'`, `'Answered'`, `'Draft'`, `'Deleted'`. When you return flags from a handler, do the same — return `['Seen', 'Flagged']`, not `['\\Seen', '\\Flagged']`.

This is a one-time migration for developers coming from raw IMAP. The library warns once per process if it sees backslashed flag names in a handler's return value. Custom keywords (unflagged labels) are passed through unchanged.

### IDLE push primitives — wake clients on storage changes

When your backend changes — new message arrives, flags change, a message is expunged — you call a `notify*` method on the active `mailboxSession` and the library takes care of the wire format:

```js
session.notifyExists(newTotalCount);      // * n EXISTS
session.notifyRecent(newRecentCount);     // * n RECENT
session.notifyExpunge(seqNum);            // * n EXPUNGE
session.notifyVanished(uid);              // * VANISHED uid      (QRESYNC)
session.notifyFlags(seqNum, uid, flags);  // * n FETCH (FLAGS ...)
```

The library handles the IDLE state — if the client isn't in IDLE, notifications are buffered and flushed on the next SELECT/EXAMINE; if the client is in IDLE, they're pushed immediately.


## 📚 API Reference

### Module Exports

```js
import {
  // Server
  createServer,                // Create unified server (SMTP + IMAP + POP3)
  Server,                      // Server class (if you need to construct directly)

  // Domain material (DKIM + DNS + MTA-STS)
  buildDomainMailMaterial,     // Generate DKIM keys + all DNS records

  // Message composition / parsing
  composeMessage,              // Build RFC 5322 message
  parseMessage,                // Parse raw email → { text, html, attachments }

  // SMTP client (standalone — no server needed)
  sendMail,                    // Send mail (direct MX or via relay)
  resolveMX,                   // MX record lookup

  // DSN (RFC 3461/3464)
  buildDsn,                    // Build a multipart/report DSN message

  // DKIM / SPF / DMARC (standalone auth checks)
  dkimSign, dkimVerify,
  checkSPF, checkDMARC,

  // Low-level session constructors (use these for custom transports)
  SMTPSession,                 // SMTP session (server or client mode)
  IMAPSession,                 // IMAP session (server or client mode)
  POP3Session,                 // POP3 session (server or client mode)

  // IDN / internationalization helpers
  domainToAscii,               // Unicode → Punycode
  domainToUnicode,             // Punycode → Unicode
  splitAddress,                // 'user@host' → {local, domain}

  // Constants
  SPECIAL_USE,                 // Folder special-use flags (SPECIAL_USE.Sent, Drafts, ...)
  FLAGS                        // Standard message flags (FLAGS.Seen, Flagged, ...)
} from 'email-server';
```

### `createServer(options)`

| Option | Type | Default | Description |
|---|---|---|---|
| `hostname` | string | `'localhost'` | Server hostname for EHLO/banner/STS identity |
| `ports` | object | — | `{ inbound, submission, secure, imap, imaps, pop3, pop3s }` |
| `tlsOptions` | object | null | `{ cert, key, ca, ... }` — base TLS context |
| `maxSize` | number | 25 MB | Maximum message size in bytes |
| `maxRecipients` | number | 100 | Maximum RCPT TO per message |
| `relay` | object | null | `{ host, port, auth }` smarthost for outbound |
| `pool` | object | defaults | Connection pool settings — see below |
| `useProxy` | boolean | false | Enable HAProxy PROXY protocol v1 |
| `closeTimeout` | number | 30000 | Graceful shutdown timeout (ms) |
| `SNICallback` | function | null | `(servername, cb)` for dynamic TLS |
| `dkimCallback` | function | null | `(domain, cb)` for dynamic DKIM |
| `onSecure` | function | null | Post-TLS handshake callback |
| `rateLimit` | object | null | `{ perMinute, perHour, banDuration }` inbound rate limiting |

#### Pool options

| Option | Type | Default | Description |
|---|---|---|---|
| `maxPerDomain` | number | 3 | Max simultaneous connections per destination domain |
| `maxMessagesPerConn` | number | 100 | Close connection after N messages |
| `idleTimeout` | number | 30000 | Close idle connection after (ms) |
| `rateLimitPerMinute` | number | 60 | Max messages per domain per minute |
| `reconnectDelay` | number | 1000 | Min time between connections to same domain |

### Server-level events

| Event | Args | Description |
|---|---|---|
| `connection` | `(info)` | TCP connection — `info.protocol`, `info.remoteAddress`, `info.reject()` |
| `auth` | `(info)` | Authentication request — unified across SMTP, IMAP, POP3 |
| `smtpSession` | `(session)` | SMTP session ready (both inbound and submission) |
| `mailboxSession` | `(session)` | IMAP or POP3 session ready |
| `error` | `(err)` | Server-level error |
| `close` | — | Server fully closed |

### Server methods

| Method | Purpose |
|---|---|
| `server.listen(cb)` | Start listening on all configured ports |
| `server.close(cb)` | Graceful shutdown (close listeners, drain sessions) |
| `server.addDomain(material)` | Register a domain for inbound mail + DKIM signing |
| `server.removeDomain(domain)` | Remove a domain |
| `server.sendDsn(options, cb)` | Dispatch a DSN message with null return-path |
| `server.buildDsn(options)` | Build a DSN message (Buffer) without sending |
| `server.clearTlsCache(servername?)` | Clear SNI cache (use after cert rotation) |
| `server.forEachMailboxSession(fn)` | Iterate active IMAP/POP3 sessions (for push notifications) |
| `server.ban(ip, durationMs?)` | Temporarily ban an IP (rate-limit integration) |
| `server.unban(ip)` | Remove a ban |

### The `auth` event

```js
server.on('auth', info => {
  info.protocol     // 'smtp' | 'imap' | 'pop3'
  info.authMethod   // 'plain' | 'login' | 'xoauth2'
  info.username     // user identifier
  info.password     // password OR bearer token (for xoauth2)
  info.remoteAddress
  info.isTLS

  info.accept()                 // permit the session
  info.reject(message?)         // deny with optional text
});
```

### The `smtpSession` event

```js
server.on('smtpSession', session => {
  session.isSubmission          // false for inbound, true for submission
  session.username              // null for inbound, set for submission
  session.remoteAddress
  session.isTLS

  session.on('mail', mail => {
    mail.from                   // envelope sender
    mail.to                     // [envelope recipients]
    mail.params                 // { size, body, smtputf8, requiretls, ret, envid }
    mail.auth                   // { dkim, spf, dmarc, rdns, dmarcPolicy } (inbound only)

    mail.subject, mail.messageId, mail.date, mail.headers

    mail.on('data', chunk => {})
    mail.on('end', () => {
      mail.text, mail.html, mail.attachments

      mail.accept()              // → 250 OK
      mail.reject(code, text)    // → 5xx
      mail.deliver(cb)           // library signs + sends (submission mode)
    });
  });
});
```

### The `mailboxSession` event — all 24 storage handlers

Your backend implements any subset of these. The library gates features (MOVE, QUOTA, METADATA, THREAD, SORT) on whether the listener is registered.

| Event | Fires on | Purpose |
|---|---|---|
| `folders` | LIST, LIST-EXTENDED, LSUB | Return the user's folder list |
| `openFolder` | SELECT, EXAMINE | Return folder metadata (uidValidity, total, unread) |
| `status` | STATUS | Folder stats without opening it |
| `resolveMessages` | Any sequence/UID command | Range → concrete message IDs |
| `messageMeta` | FETCH minimal | IDs → `{uid, size, internalDate, flags}` |
| `messageEnvelope` | FETCH ENVELOPE | Cached envelope (opt-in perf optimization) |
| `messageBodyStructure` | FETCH BODYSTRUCTURE | Cached body structure |
| `messageBody` | FETCH BODY[], RFC822 | Stream the raw message to the client |
| `setFlags` | STORE | Update flags on messages |
| `append` | APPEND | Add a message to a folder |
| `copyMessages` | COPY | Copy IDs to destination folder |
| `move` | MOVE | Move IDs to destination (IMAP MOVE extension) |
| `expunge` | EXPUNGE, CLOSE | Permanently delete flagged messages |
| `createFolder` | CREATE | Create new folder |
| `deleteFolder` | DELETE | Delete folder |
| `renameFolder` | RENAME | Rename folder |
| `subscribe` | SUBSCRIBE | Add to subscription list |
| `unsubscribe` | UNSUBSCRIBE | Remove from subscription list |
| `search` | SEARCH (incl. WITHIN/OLDER/YOUNGER) | Evaluate search criteria |
| `sort` | SORT | Ordered search (RFC 5256) |
| `thread` | THREAD | Conversation grouping |
| `namespace` | NAMESPACE | Return server namespaces |
| `qresync` | ENABLE QRESYNC, SELECT...QRESYNC | Fast resync for CONDSTORE clients |
| `resolveVanished` | UID FETCH...VANISHED | Return UIDs vanished since modseq |
| `quota` / `quotaRoot` | GETQUOTA, GETQUOTAROOT | Per-folder quota (opt-in) |
| `getMetadata` / `setMetadata` | GETMETADATA, SETMETADATA | RFC 5464 annotations (opt-in) |
| `close` | — | Session disconnecting, cleanup |

### IDLE push primitives

Call these on an active `mailboxSession` to deliver real-time notifications to connected IDLE clients:

```js
session.notifyExists(count)              // → * <count> EXISTS
session.notifyRecent(count)              // → * <count> RECENT
session.notifyExpunge(seqNum)            // → * <seqNum> EXPUNGE
session.notifyVanished(uid)              // → * VANISHED <uid>   (QRESYNC)
session.notifyFlags(seqNum, uid, flags)  // → * <seqNum> FETCH (UID ... FLAGS (...))
```

If the client isn't in IDLE, the library queues notifications and flushes on the next SELECT/EXAMINE. If it is in IDLE, they push immediately.

### `sendMail(options, cb)`

Send a message with no server running. Automatic IDN Punycode + SMTPUTF8 negotiation, MX lookup, DKIM signing (when a domain is registered), connection pooling.

```js
sendMail({
  from: 'alice@example.com',
  to:   ['bob@other.com', 'charlie@другой.рф'],   // Unicode ok
  cc, bcc,
  subject, text, html,
  attachments: [{ filename, content, contentType, cid }],
  headers: { 'X-Custom': 'value' },
  replyTo,
  priority,               // 'high' | 'normal' | 'low'
  relay: { host, port, auth },    // Optional — direct MX lookup if omitted
  pool                    // Share a pool across many sendMail calls
}, (err, info) => {
  info.accepted           // [successful hosts]
  info.rejected           // [{ domain, error }]
  info.messageId
});
```

### IMAP / POP3 client — `IMAPSession` and `POP3Session`

Both accept `{ isServer: false }` and operate as clients. You attach them to a `net.Socket` or `tls.TLSSocket` and pump bytes via `.feed()` / `on('send')`.

```js
const client = new IMAPSession({ isServer: false });
client.on('send', data => socket.write(data));
socket.on('data', data => client.feed(data));

// After socket connects:
client.greet();
client.on('ready', () => {
  client.login(user, pass, cb);
  // or: client.xoauth2(user, token, cb);

  client.capability             // string[] — refreshed after LOGIN/STARTTLS
  client.list('', '*', cb);
  client.listExtended({ reference, patterns, selection, return: ['STATUS'] }, cb);
  client.select('INBOX', cb);
  client.examine('INBOX', cb);
  client.fetch(uids, items, cb);
  client.search(criteria, cb);
  client.sort(keys, charset, criteria, cb);
  client.thread(algo, charset, criteria, cb);
  client.store(uids, flags, mode, cb);     // mode: '+' | '-' | ''
  client.copy(uids, dest, cb);
  client.move(uids, dest, cb);
  client.append(folder, raw, flags, cb);
  client.expunge(cb);
  client.idle(cb);                 // enters IDLE — client.done() to exit
  client.getQuota(root, cb);
  client.getQuotaRoot(mailbox, cb);
  client.getMetadata(mailbox, paths, cb);
  client.setMetadata(mailbox, entries, cb);
  client.compress(cb);             // enable COMPRESS=DEFLATE
  client.logout();
});
```

POP3 client is smaller:

```js
const pop = new POP3Session({ isServer: false });
// ... wire up socket ...
pop.greet();
pop.on('ready', () => {
  pop.user('alice', err => pop.pass('password', err => {
    pop.list((err, entries) => {                       // [{ index, size }, ...]
      pop.top(1, 10, (err, headers) => {});            // first 10 lines
      pop.retr(1, (err, raw) => {});                   // full message
      pop.dele(1, cb);
      pop.quit();
    });
  }));
});
// or: pop.xoauth2(user, token, cb);
```

### `buildDsn(options)` and `server.sendDsn()`

Generate RFC 3464 delivery status notifications with the right MIME format, or dispatch them through the pool with a null return-path (RFC 3461 §6 loop prevention).

```js
import { buildDsn } from 'email-server';

const raw = buildDsn({
  reportingMta: 'mail.example.com',
  originalEnvelopeId: 'ENV-42',                    // from MAIL FROM ENVID
  returnContent: 'headers',                        // or 'full' — matches RET=
  originalMessage: originalBytes,
  from: 'postmaster@example.com',
  to: 'alice@example.com',                         // original envelope sender
  recipients: [{
    finalRecipient:    'bob@unknown.example',
    originalRecipient: 'bob@unknown.example',      // from ORCPT
    action:            'failed',                   // 'failed'|'delayed'|'delivered'|'relayed'|'expanded'
    status:            '5.1.2',
    diagnostic:        '550 5.1.2 Host unknown',
    remoteMta:         'mx.unknown.example',
    lastAttempt:       new Date()
  }]
});

// Dispatch via the outbound pool with null return-path:
server.sendDsn({ /* same shape */ }, (err, info) => {});
```

### `buildDomainMailMaterial(domain, options)`

Generate everything needed to operate as `@domain` — DKIM key pair, all DNS records, MTA-STS policy file, TLS-RPT setup.

```js
const mat = buildDomainMailMaterial('example.com', {
  dkim: {
    algo:       'ed25519-sha256',    // or 'rsa-sha256' (default)
    selector:   's202604',           // auto-generated if omitted
    privateKey: existingPemString    // provide or auto-generate
  },
  policy: {
    spfTxt:   'v=spf1 mx a ~all',             // override defaults
    dmarcTxt: 'v=DMARC1; p=reject; adkim=s;'
  },
  mtaSts: {
    mode:          'enforce',              // 'enforce' | 'testing' | 'none'
    mx:            ['mx.example.com'],     // single string or array
    maxAgeSeconds: 604800                  // 1 week (default)
  },
  tlsRpt: {
    ruaEmail: 'tls-reports@example.com'    // or explicit rua: URI
  }
});

// What you get back:
mat.dkim.privateKey                 // PEM string — store safely
mat.dkim.dnsName                    // 's202604._domainkey.example.com'
mat.dkim.dnsValue                   // DNS TXT value
mat.mtaSts.policy                   // policy file contents
mat.mtaSts.policyUrl                // https://mta-sts.example.com/.well-known/mta-sts.txt
mat.mtaSts.serve                    // http(s).createServer handler — serves the policy
mat.tlsRpt.value                    // 'v=TLSRPTv1; rua=...'
mat.requiredDNS                     // [{type, name, value}, ...] — all records to create

// Verify your DNS setup:
mat.verifyDNS((err, results) => {
  // { dkim: true, spf: true, dmarc: true, mx: true, mtaSts: true, tlsRpt: true }
});
```

Mount the MTA-STS HTTP handler on any Node HTTP server:

```js
import http from 'node:http';
import https from 'node:https';

// On HTTPS for the real mta-sts.example.com subdomain:
https.createServer({ cert, key }, mat.mtaSts.serve).listen(443);

// Or compose with Express/fastify/etc — it's just a (req, res) handler.
```


## 🏛 Standards Compliance

| RFC | Title | Support |
|---|---|---|
| **SMTP** | | |
| RFC 5321 | Simple Mail Transfer Protocol | ✅ Full |
| RFC 3207 | SMTP STARTTLS | ✅ |
| RFC 4954 | SMTP AUTH | ✅ PLAIN, LOGIN, XOAUTH2 |
| RFC 6152 | 8BITMIME | ✅ |
| RFC 2920 | PIPELINING | ✅ |
| RFC 3030 | CHUNKING (BDAT) | ✅ |
| RFC 1870 | SMTP SIZE | ✅ |
| RFC 2034 | ENHANCEDSTATUSCODES | ✅ |
| RFC 6531 | SMTPUTF8 (internationalized addresses) | ✅ |
| RFC 5890 | Internationalized Domain Names (IDN) | ✅ — Punycode fallback |
| RFC 8689 | REQUIRETLS | ✅ |
| RFC 3461 | Delivery Status Notifications (SMTP) | ✅ — NOTIFY / ORCPT / RET / ENVID |
| RFC 3464 | DSN format | ✅ — `buildDsn()` generates compliant messages |
| RFC 8461 | MTA-STS | ✅ — policy + DNS + HTTP handler |
| RFC 8460 | TLS-RPT | ✅ — DNS record generation |
| **IMAP** | | |
| RFC 3501 / 9051 | IMAP4rev1 / IMAP4rev2 | ✅ Core |
| RFC 4315 | UIDPLUS | ✅ |
| RFC 2088 / 7888 | LITERAL+ / LITERAL- | ✅ |
| RFC 5161 | ENABLE | ✅ |
| RFC 7162 | CONDSTORE / QRESYNC | ✅ |
| RFC 5256 | SORT / THREAD | ✅ — ORDEREDSUBJECT, REFERENCES |
| RFC 2177 | IDLE | ✅ — with push primitives |
| RFC 6154 | SPECIAL-USE | ✅ |
| RFC 5258 | LIST-EXTENDED | ✅ |
| RFC 5819 | LIST-STATUS | ✅ |
| RFC 5032 | WITHIN (OLDER / YOUNGER) | ✅ |
| RFC 6851 | MOVE | ✅ (opt-in) |
| RFC 2342 | NAMESPACE | ✅ |
| RFC 9208 | QUOTA | ✅ (opt-in) |
| RFC 5464 | METADATA | ✅ (opt-in) |
| RFC 4978 | COMPRESS=DEFLATE | ✅ |
| **POP3** | | |
| RFC 1939 | POP3 | ✅ |
| RFC 2449 | CAPA | ✅ |
| RFC 2595 | STLS | ✅ |
| RFC 5034 | SASL | ✅ |
| **Auth & Security** | | |
| RFC 6376 | DKIM | ✅ Sign + verify (RSA-SHA256, Ed25519-SHA256) |
| RFC 7208 | SPF | ✅ ip4, ip6, a, mx, include, redirect, ptr |
| RFC 7489 | DMARC | ✅ alignment + org-domain fallback |
| RFC 8617 | ARC | ⏳ Planned |


## 🔐 Security

### Inbound authentication pipeline

When a message is received on port 25, all checks run automatically and in parallel before `mail.accept()` can be called:

1. **Reverse DNS** — FCrDNS (forward-confirmed reverse) + EHLO hostname match
2. **SPF** — authorize the sending IP against the envelope sender's domain
3. **DKIM** — verify every signature in the message; require at least one from the From domain for alignment
4. **DMARC** — evaluate policy (none / quarantine / reject) with SPF-or-DKIM alignment

Results arrive on `mail.auth = { dkim, spf, dmarc, rdns, dmarcPolicy }`. The library does not auto-reject — it gives you the data so you decide what to do.

### Outbound DKIM signing

When a domain is registered via `server.addDomain(material)`, every outbound message from that domain is automatically DKIM-signed using the key from `material.dkim`. No per-message configuration needed.

### Transport security

* **STARTTLS + implicit TLS** on every protocol (SMTP 25/587/465, IMAP 143/993, POP3 110/995)
* **SNI support** — multi-domain on a single port with `SNICallback`
* **TLS context caching** with `server.clearTlsCache()` for Let's Encrypt rotation
* **MTA-STS** enforcement — `server.on('secure')` exposes negotiated version/cipher
* **REQUIRETLS** — refuse to deliver sensitive mail over cleartext
* **TLS-RPT** — receive daily reports about TLS failures from other MTAs

### Built-in protections

* **SMTP smuggling protection** (RFC 5321 §4.1.1.4) — bare LF normalization prevents CVE-2023-51764-class attacks
* **Per-IP rate limiting** — `{ rateLimit: { perMinute, perHour, banDuration } }` in `createServer`
* **Graceful shutdown** — `server.close()` drains sessions with `closeTimeout`
* **Backpressure handling** — server respects TCP flow control; slow clients don't OOM the process
* **PROXY protocol v1** — trust the real client IP when behind HAProxy / Nginx
* **Auth timeout** — unauthenticated sessions time out (configurable)
* **Size limits** — per-message `maxSize` (default 25 MB) enforced before body arrives


## 🧪 Testing

```bash
npm test                        # full suite — 360 assertions across 13 files
node tests/test_imap_unit.mjs         # run individual suites
node tests/test_smtputf8.mjs
node tests/test_dsn.mjs
# ...
```

Current test counts:

| Suite | Tests |
|---|---:|
| `imap_unit` | 37 |
| `imap_session` | 14 |
| `server_integration` | 60 |
| `idle_push` | 11 |
| `pop3_server` | 42 |
| `pop3_client` | 29 |
| `xoauth2` | 27 |
| `compress` | 9 |
| `smtputf8` | 23 |
| `requiretls` | 7 |
| `dsn` | 43 |
| `metadata` | 16 |
| `mta_sts` | 42 |
| **Total** | **360** |


## 📁 Project Structure

```
src/
  server.js                  Main server — integrates all protocols, TLS, domains, DSN
  smtp_session.js            SMTP session — server + client, SMTPUTF8, REQUIRETLS
  smtp_client.js             sendMail + deliverToDomain with IDN negotiation
  smtp_wire.js               SMTP wire parsers (NOTIFY, ORCPT, xtext, ESMTP params)
  imap_session.js            IMAP session — server + client core + dispatcher
  imap_folders.js            IMAP folder ops (LIST-EXTENDED, QUOTA, STATUS)
  imap_messages.js           IMAP message ops (FETCH, STORE, COPY)
  imap_search.js             IMAP SEARCH + SORT + THREAD + WITHIN
  imap_metadata.js           IMAP METADATA (RFC 5464)
  imap_wire.js               IMAP wire parsers + serializers
  pop3_session.js            POP3 session — server + client + SASL + XOAUTH2
  dsn.js                     Delivery Status Notification builder
  domain.js                  buildDomainMailMaterial, MTA-STS, TLS-RPT
  dkim.js                    DKIM sign + verify
  spf.js                     SPF evaluation
  dmarc.js                   DMARC evaluation
  message.js                 MIME compose + parse
  pool.js                    Outbound connection pool
  dns_cache.js               Shared DNS cache (TXT/A/AAAA/MX/PTR) with IDN normalize
  rate_limit.js              Per-IP rate limiter
  utils.js                   IDN helpers, address utilities, UTF-8
examples/
  demo_server.js             Full IMAP + SMTP reference server (Thunderbird-tested)
  demo_db.js                 In-memory backend for the demo
tests/
  test_*.mjs                 One file per feature area (13 files, 360 tests)
```


## 📊 Comparison

Once you understand the scope, here's how `email-server` fits against popular alternatives:

| | email-server | [nodemailer](https://github.com/nodemailer/nodemailer) | [smtp-server](https://github.com/nodemailer/smtp-server) | [imapflow](https://github.com/postalsys/imapflow) | [Haraka](https://github.com/haraka/Haraka) |
|---|:---:|:---:|:---:|:---:|:---:|
| SMTP server                | ✅ | — | ✅ | — | ✅ |
| SMTP client                | ✅ | ✅ | — | — | — |
| IMAP server                | ✅ | — | — | — | plugin |
| IMAP client                | ✅ | — | — | ✅ | — |
| POP3 server                | ✅ | — | — | — | — |
| POP3 client                | ✅ | — | — | — | — |
| DKIM sign/verify           | ✅ | sign only | — | — | plugin |
| SPF / DMARC / rDNS         | ✅ | — | — | — | plugin |
| XOAUTH2 (all protocols)    | ✅ | client | — | client | — |
| IDLE push primitives       | ✅ | — | — | client | — |
| DSN generation             | ✅ | — | — | — | plugin |
| MTA-STS + TLS-RPT setup    | ✅ | — | — | — | — |
| SMTPUTF8 + IDN             | ✅ | ✅ | ✅ | partial | ✅ |
| REQUIRETLS                 | ✅ | — | — | — | — |
| Dependencies               | 1 | many | 6 | many | many |

**When to choose `email-server`:** you want one library for both sides of every protocol with mail authentication built in — a complete mail stack in a single package.

**When another library fits better:** if you only need to *send* transactional mail through an external SMTP relay, [nodemailer](https://github.com/nodemailer/nodemailer) has a larger ecosystem of transports and templating integrations. If you only need a customizable MTA and don't mind plugin sprawl, [Haraka](https://github.com/haraka/Haraka) has a rich plugin library. If you only need an IMAP client for a single inbox, [imapflow](https://github.com/postalsys/imapflow) has a Promise-first API.


## 🛣 Roadmap

✅ = Completed  ⏳ = Planned

### ✅ Completed

| Category | Item |
|---|---|
| SMTP | Inbound, submission, implicit TLS |
| SMTP | STARTTLS (server + client) |
| SMTP | AUTH PLAIN / LOGIN / XOAUTH2 |
| SMTP | 8BITMIME, SMTPUTF8, PIPELINING, ENHANCEDSTATUSCODES, SIZE, CHUNKING |
| SMTP | REQUIRETLS (RFC 8689) |
| SMTP | DSN (RFC 3461/3464) — parse + generate |
| SMTP | SMTP smuggling protection, PROXY protocol v1 |
| SMTP client | Direct MX + relay, connection pool with RSET reuse |
| SMTP client | Retry with backoff, per-domain rate limiting |
| SMTP client | IDN Punycode fallback when peer lacks SMTPUTF8 |
| IMAP server | RFC 3501 full, UIDPLUS, LITERAL+, ENABLE |
| IMAP server | CONDSTORE, QRESYNC (RFC 7162) |
| IMAP server | SORT, THREAD (RFC 5256) |
| IMAP server | IDLE with push primitives |
| IMAP server | MOVE (RFC 6851), NAMESPACE, SPECIAL-USE |
| IMAP server | LIST-EXTENDED (RFC 5258), LIST-STATUS (RFC 5819), WITHIN (RFC 5032) |
| IMAP server | QUOTA (RFC 9208) |
| IMAP server | METADATA (RFC 5464) |
| IMAP server | COMPRESS=DEFLATE (RFC 4978) |
| IMAP client | Full `IMAPSession({isServer:false})` with all extensions |
| POP3 server | RFC 1939 + CAPA + STLS + SASL + XOAUTH2 |
| POP3 client | Full `POP3Session({isServer:false})` |
| Auth | DKIM sign + verify (RSA-SHA256, Ed25519-SHA256) |
| Auth | SPF, DMARC, rDNS — all automatic on inbound |
| Security | MTA-STS (RFC 8461) generation + HTTP handler |
| Security | TLS-RPT (RFC 8460) generation |
| Security | Multi-domain TLS with SNI caching |
| MIME | Compose + parse (nodemailer-compatible) |
| Architecture | Unified `auth` / `smtpSession` / `mailboxSession` event model |
| Architecture | Bring-your-own-storage — library never persists messages |
| Architecture | Listener-gated capabilities — honest CAPABILITY advertising |
| Tooling | 360 tests, `buildDomainMailMaterial()`, Thunderbird demo |
| Packaging | Zero dependencies (`node:` builtins + `flat-ranges`) |

### ⏳ Planned

| Item | Notes |
|---|---|
| Well-known services | `{ service: 'gmail' \| 'outlook' \| 'icloud' }` presets |
| Autoconfig / Autodiscover | RFC 6186 SRV + Mozilla ISPDB + MS Autodiscover |
| ARC (RFC 8617) | Authenticated Received Chain for forwarded mail |
| BIMI | Brand indicators for message identification |
| SIEVE (RFC 5228) | Server-side mail filtering |
| TypeScript types | Comprehensive `index.d.ts` |
| Benchmarks | Throughput, memory, concurrent connections |


## 🤝 Contributing

Pull requests are welcome!  
Please open an issue before submitting major changes.

## 💖 Sponsors

This project is part of the [colocohen](https://github.com/colocohen) Node.js infrastructure stack (QUIC, WebRTC, DNSSEC, TLS, and more).  
You can support ongoing development via [GitHub Sponsors](https://github.com/sponsors/colocohen).

## 📚 References

- [RFC 5321 — SMTP](https://datatracker.ietf.org/doc/html/rfc5321)
- [RFC 3501 — IMAP4rev1](https://datatracker.ietf.org/doc/html/rfc3501)
- [RFC 1939 — POP3](https://datatracker.ietf.org/doc/html/rfc1939)
- [RFC 6376 — DKIM](https://datatracker.ietf.org/doc/html/rfc6376)
- [RFC 7208 — SPF](https://datatracker.ietf.org/doc/html/rfc7208)
- [RFC 7489 — DMARC](https://datatracker.ietf.org/doc/html/rfc7489)
- [RFC 8461 — MTA-STS](https://datatracker.ietf.org/doc/html/rfc8461)
- [RFC 8460 — TLS-RPT](https://datatracker.ietf.org/doc/html/rfc8460)
- [RFC 3461 — DSN](https://datatracker.ietf.org/doc/html/rfc3461)
- [RFC 6531 — SMTPUTF8](https://datatracker.ietf.org/doc/html/rfc6531)
- [Email Authentication Best Practices (M3AAWG)](https://www.m3aawg.org/sites/default/files/m3aawg_email_authentication_recommended_best_practices-2020-03.pdf)


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