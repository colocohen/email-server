<p align="center">
  <img src="https://github.com/colocohen/email-server/raw/main/email-server.svg" width="450" alt="email-server"/>
</p>

<h1 align="center">email-server</h1>
<p align="center">
  <em>📧 Easily run your own mail server — complete email infrastructure with full control, in a single Node.js package with just one small dependency.</em>
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
* 📤 **SMTP Client** — direct delivery via MX lookup or via relay/smarthost. Connection pooling, retry with backoff, and per-domain outbound throttling.
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

* 📦 **MIME compose & parse** — text, HTML, attachments, inline images. Parses any real-world charset (UTF-8, ISO-8859-*, windows-125x, Shift_JIS, EUC-KR, GB18030, Big5, KOI8-R…) with zero extra dependencies, plus RFC 2047 encoded-words and RFC 2231 extended/continued parameters — cross-compatible with nodemailer / mailparser.
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
* ⚡ **Nearly dependency-free** — only `node:` builtins plus one tiny dependency (`flat-ranges`, used for efficient IMAP sequence-set math).


## 📦 Installation

```bash
npm install email-server
```

**Requirements:** Node.js 18+ (uses `node:crypto`, `node:url` IDN, `node:zlib` deflate-raw).


## 🚀 Quick Start

The Quick Start covers three scenarios that together show the whole surface: receiving mail, sending mail, and letting users retrieve it over IMAP. A full combined server comes at the end.

### 1. Receive Email

Inbound SMTP on port 25 — other mail servers delivering to your users. No auth; SPF/DKIM/DMARC/rDNS checks run automatically before the `mail` event fires.

> This example opens **only** an inbound port, so every message reaching
> `smtpSession` arrived from the outside. Once you also open a submission
> port, the same event carries both directions and you branch on
> `session.isSubmission` — see [Two directions, one event](#two-directions-one-event).

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

    // 'data' fires ONCE with the complete message (Uint8Array). The library
    // buffers the whole body before firing 'mail', so this is not a network
    // stream — use it when all you need is the bytes (disk, S3, a queue).
    // Cap the size with createServer({ maxSize }).
    mail.on('data', chunk => { /* the entire message, in a single call */ });

    // 'end' fires immediately after, once MIME parsing has run. Wait for it
    // only if you need the parsed fields.
    mail.on('end', () => {
      console.log(mail.subject, mail.text, mail.html);
      console.log(mail.attachments.length, 'attachments');

      // Save to your storage here (DB, filesystem, S3, ...)
      // saveMessage(mail.to, mail.raw);

      mail.accept();                 // → 250 OK
    });
  });
});

server.listen(() => console.log('SMTP MX on port 25'));
```

### 2. Submission and Send

Authenticated submission on port 587 — your users sending outbound. Library signs with DKIM and delivers via the outbound pool.

> Only a submission port here, so `session.isSubmission` is always `true` and
> `mail.auth` is all `null` — nothing to check, the user authenticated.

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

// SMTP — this server listens on BOTH inbound and submission ports, so the
// same event serves two jobs. session.isSubmission tells them apart; see
// "Two directions, one event" under Core Concepts.
server.on('smtpSession', session => {
  session.on('mail', mail => {
    mail.on('end', async () => {

      // --- Your user, sending outward ---
      if (session.isSubmission) {
        await db.messages.append(session.username, 'Sent', mail.raw, ['Seen']);
        mail.deliver();            // DKIM-signs and queues for delivery
        return;
      }

      // --- Mail arriving from another server ---
      if (mail.auth.dmarc === 'fail' && mail.auth.dmarcPolicy === 'reject') {
        return mail.reject(550, 'DMARC policy rejection');
      }

      await db.messages.save(mail.to[0], mail.raw);
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

These seven ideas explain how the library is structured. Read them once; the rest of the docs assume you know them.

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

### Two directions, one event

`smtpSession` fires for both jobs an SMTP server does, and they are not the
same job:

| | **Inbound** — mail arriving from Gmail | **Submission** — your user sending |
|---|---|---|
| Port | `25` (`ports.inbound`) | `587` / `465` (`ports.submission`, `ports.secure`) |
| Who connects | Any MTA on the internet | Thunderbird, your app, a phone |
| Authentication | None — the internet may talk to you | Required, before anything else |
| `session.isSubmission` | `false` | `true` |
| `session.username` | `null` | the authenticated user |
| `mail.auth.*` | verdict strings | all `null` |
| What you normally do | store it, or reject it | relay it out with `mail.deliver()` |

One event rather than two, because everything else is identical: the same
envelope, the same body, the same `accept()` / `reject()`. Splitting them
would mean duplicating every handler for a difference that two fields
already express.

```js
server.on('smtpSession', session => {
  session.on('mail', mail => {
    mail.on('end', () => {

      if (session.isSubmission) {
        // Your user is sending. They proved who they are with a password,
        // so there is nothing to verify about the origin — sign it and
        // send it on its way.
        mail.deliver();                        // DKIM-signs, then queues
        return;
      }

      // Mail from the outside world. Now the auth verdicts matter.
      if (mail.auth.dmarc === 'fail' && mail.auth.dmarcPolicy === 'reject') {
        return mail.reject(550, 'DMARC policy rejection');
      }
      if (mail.auth.spf === 'fail') {
        return mail.reject(550, 'SPF failure');
      }

      saveToMailbox(mail.to, mail.raw);
      mail.accept();
    });
  });
});
```

#### `null` is not `'none'`

On a submission port every `mail.auth` field is `null`, and that is different
from `'none'`:

* `null` — **not checked.** The user authenticated; there was nothing to check.
* `'none'` — **checked, no record published.** The sending domain has no SPF
  record, no DKIM signature, no DMARC policy.

So this looks reasonable and is a bug:

```js
// ✗ blocks every message YOUR OWN USERS send
if (mail.auth.spf !== 'pass') return mail.reject(550, 'SPF failure');
```

`null !== 'pass'`, so it rejects submissions too. Always gate on the
direction first:

```js
// ✓
if (!session.isSubmission && mail.auth.spf === 'fail') {
  return mail.reject(550, 'SPF failure');
}
```

#### What the session tells you

```js
session.protocol        // 'smtp'
session.isSubmission    // which of the two directions this is
session.username        // authenticated user, or null on inbound
session.remoteAddress   // the peer's IP — the real one, from the PROXY
                        //   header when createServer({ useProxy: true })
session.isTLS           // updated live if the peer runs STARTTLS mid-session
```

`session.remoteAddress` is the same address the library used to evaluate SPF
and reverse DNS, so it will never disagree with `mail.auth`.

### Outbound mail outlives the connection

`mail.deliver()` and `server.send()` return as soon as the message is
**queued**, not when it is delivered. Delivery to a remote MX can take
seconds or, with retries, days — far longer than the SMTP session that
started it. So the outcome arrives later, on the **server**:

```js
server.on('sent',      info => log('delivered', info.to));
server.on('retry',     info => log('deferred, attempt ' + info.attempts, info.error));
server.on('bounce',    info => log('gave up', info.to, info.error));
server.on('sendError', info => log('transport failure', info.error));
```

A `4xx` from the remote server (greylisting, "try again later") produces
`retry` and the message stays queued. A `5xx`, or exhausting every retry,
produces `bounce`. Nothing is lost silently in between.

**The queue is in memory.** A restart drops whatever is still pending, so
snapshot it if that matters:

```js
process.on('SIGTERM', () => {
  fs.writeFileSync('queue.json', JSON.stringify(server.serializeQueue()));
  server.close(() => process.exit(0));
});

// on startup
if (fs.existsSync('queue.json')) {
  server.restoreQueue(JSON.parse(fs.readFileSync('queue.json', 'utf8')));
}
```

#### Forwarding: `mail.deliver()` rewrites the envelope

`deliver()` reuses the envelope of the message it was called on. To send it
somewhere else, reassign `mail.to` first — the field is writable for exactly
this reason:

```js
server.on('smtpSession', session => {
  session.on('mail', mail => {
    mail.on('end', () => {
      const target = aliases[mail.to[0]];
      if (target) {
        mail.to = [target];        // rewrite the envelope recipient
        mail.deliver();            // relays, and answers 250 to the sender
        return;
      }
      saveToMailbox(mail.to[0], mail.raw);
      mail.accept();
    });
  });
});
```

`deliver()` sends the `250` for you once the message is queued, so do not
also call `accept()`. Pass a callback if you would rather answer yourself:

```js
mail.deliver(err => err ? mail.reject(451, 'Try later') : mail.accept());
```

### Bring-your-own-storage — the library holds nothing

email-server is a protocol-layer library. It parses wire formats, enforces RFC behavior, and emits events — it never stores messages, user lists, folder structures, or flags. You provide all of that in your handlers. This means you can wire it to SQLite for a personal server, Postgres for production, S3 for cold storage, or even an in-memory `Map` for testing.

The examples throughout this document use handlers like `db.messages.save(...)` — that's your code, not the library's.

**This extends to attachments and message bytes.** Unlike some send-only libraries that accept a file `path` or a remote `href` and do the reading/downloading for you, email-server never touches the filesystem or network on your behalf for content. You read the bytes however you like — `fs`, an S3 stream you drain yourself, a database blob, a generated buffer — and hand the library a `content` value:

```js
attachments: [
  { filename: 'report.pdf', content: fs.readFileSync('/tmp/report.pdf') },
  { filename: 'logo.png',   content: pngBuffer, cid: 'logo' }   // inline image
]
```

This is deliberate: the library stays a pure protocol layer, so *you* keep full control over where content lives, how it's cached, and how I/O errors and timeouts are handled — decisions a mail library shouldn't make for you. It composes the MIME correctly; the sourcing is yours.

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
session.notifyExpunge(seq, uid);          // * n EXPUNGE  (or * VANISHED uid when QRESYNC enabled)
session.notifyVanished(arg);              // * VANISHED ...  (arg = [uids] | {ranges} | {uids})
session.notifyFlags(seq, uid, flags);     // * n FETCH (FLAGS ...)
```

These emit untagged responses **only while the session has the relevant folder open (SELECTED state)** — whether or not the client is currently in an IDLE command. Outside SELECTED they are no-ops; the library does not buffer them for a later SELECT. To push a change to every session viewing a folder, walk the live sessions:

```js
server.forEachMailboxSession(s => {
  if (s.username === user && s.currentFolder === 'INBOX') s.notifyExists(newTotal);
});
```


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
  parseDsn,                    // Parse an incoming bounce (DSN) into structured data

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
| `addReceived` | boolean | true | Prepend a `Received:` trace header to every inbound message (RFC 5321 §4.4) |
| `maxReceivedHops` | number | 100 | Reject a message carrying at least this many `Received:` headers as a mail loop (RFC 5321 §6.3); `0` disables |
| `handlerTimeout` | number | 0 (off) | Watchdog: if a storage handler never calls its callback, answer `NO`/`-ERR` after this many ms instead of hanging the client. Fires a `handlerTimeout` event |
| `maxAppendSize` | number | 0 (none) | IMAP `APPENDLIMIT` (RFC 7889): reject `APPEND` larger than this with `NO [TOOBIG]` before accepting the bytes |
| `metadataMaxSize` | number | 2 KB | Max METADATA annotation value size (RFC 5464) |
| `SNICallback` | function | null | `(servername, cb)` for dynamic TLS |
| `dkimCallback` | function | null | `(domain, cb)` for dynamic DKIM |
| `onSecure` | function | null | Post-TLS handshake callback |

> **Note on rate limiting:** per-IP connection/auth rate limiting is not built into this version — it needs a dedicated design (per-IP vs per-user, shared state across workers). Enforce limits at your firewall / reverse proxy, or in your `connection` / `auth` handlers, for now.

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
| `loop` | `(info)` | Inbound message refused as a mail loop — `info.hops`, `info.remoteAddress`, `info.from`, `info.to` |
| `sending` | `(options)` | Outbound message about to be dispatched via `server.send()` |
| `sent` | `(info)` | Outbound message accepted by the remote MX |
| `bounce` | `(info)` | Outbound message permanently failed (all retries exhausted) |
| `retry` | `(info)` | Outbound message temporarily failed and will be retried |
| `sendError` | `(info)` | Outbound attempt failed at the transport level (DNS, connect, TLS) |
| `clientError` | `(info)` | A peer misbehaved at the protocol level (e.g. an oversized command line). The connection is dropped; the server keeps running. `info.protocol`, `info.remoteAddress`, `info.error` |
| `handlerTimeout` | `(info)` | A storage handler never called its callback. Only fires when `handlerTimeout` is configured. `info.protocol`, `info.command` |
| `rateLimit` | `(info)` | A peer hit an auth or message rate limit |
| `warning` | `(info)` | Configuration warning at startup — e.g. `info.code === 'NO_TLS'` when no certificate is configured, so STARTTLS cannot be offered |
| `tlsError` | `(err)` | A TLS handshake failed |
| `error` | `(err)` | Server-level error |
| `ready` | — | All configured ports are listening |
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
| `server.forEachMailboxSession(fn)` | Iterate every live IMAP/POP3 session (for push notifications) |
| `server.serializeQueue()` | Snapshot the outbound queue (pending + in-flight) as JSON-safe data |
| `server.restoreQueue(snapshot)` | Re-ingest a queue snapshot on startup — crash-safe outbound mail |

### The `auth` event

**One handler covers all three protocols.** SMTP submission, IMAP and POP3 all
raise the same event, so credentials live in one place instead of three.

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

Nothing protocol-specific is required unless you want it:

```js
server.on('auth', async info => {
  // XOAUTH2 puts the bearer token in info.password, not a password
  if (info.authMethod === 'xoauth2') {
    const ok = await verifyBearerToken(info.username, info.password);
    return ok ? info.accept() : info.reject('Token expired');
  }

  const user = await db.users.find(info.username);
  if (!user) return info.reject('Invalid credentials');

  // Same credentials work for reading mail (IMAP/POP3) and for sending
  // it (SMTP submission). Branch only if you actually need to:
  //   if (info.protocol === 'smtp' && !user.maySend) return info.reject(...)

  const ok = await verifyPassword(info.password, user.passwordHash);
  ok ? info.accept() : info.reject('Invalid credentials');
});
```

#### Authentication is a gate, not a flag

On every port that authenticates — submission, IMAP, POP3 — `smtpSession` and
`mailboxSession` are emitted **only after** `info.accept()`. A rejected login
never reaches them. (Inbound port 25 is the exception: it has no
authentication, so its session is emitted as soon as the connection opens.)

That means by the time you are handling a submitted message, the identity
question is already settled:

```js
server.on('smtpSession', session => {
  session.on('mail', mail => {
    mail.on('end', () => {
      if (session.isSubmission) {
        // Guaranteed: this connection passed your `auth` handler, and
        // session.username is the identity it passed as. No re-check needed.
        mail.deliver();
        return;
      }
      // ... inbound path
    });
  });
});
```

Two consequences worth knowing:

* **Inbound port 25 never fires `auth`.** The library does not advertise
  `AUTH` there at all — a public MX accepts mail from strangers, and
  authentication belongs on the submission port. `session.username` stays
  `null` for the whole inbound session.
* **`session.username` is who they proved to be, not who they claim to be
  in the message.** A logged-in user can still put someone else's address in
  `MAIL FROM`. If you want them to match, check it yourself:

  ```js
  if (session.isSubmission && mail.from !== session.username) {
    return mail.reject(550, 'Sender does not match authenticated user');
  }
  ```

  The library deliberately does not enforce this — aliases, shared
  role addresses and send-on-behalf-of are all legitimate.

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
    mail.auth                   // { dkim, dkimDomain, spf, dmarc, dmarcPolicy,
                                //   rdns, rdnsHostname }
                                // Inbound  → strings ('pass' | 'fail' | 'none' | ...)
                                // Submission → every field is null (nothing was
                                //   checked — the user authenticated). See
                                //   "Two directions, one event" below.

    mail.subject, mail.messageId, mail.date, mail.headers

    mail.on('data', chunk => {})   // once — the complete message
    mail.on('end', () => {         // after MIME parsing
      mail.text, mail.html, mail.attachments

      mail.accept()              // → 250 OK
      mail.reject(code, text)    // → 5xx
      mail.deliver(cb)           // library signs + sends (submission mode)
    });
  });
});
```

### The `mailboxSession` event — start with just 6 handlers

The full list below has 24+ events, but **a working IMAP/POP3 mailbox needs only these six.** Everything else is optional — the library detects what you've registered and adapts (unimplemented extensions simply aren't advertised, and if a *required* handler is missing, the client gets a clear `NO No handler registered for 'openFolder'...` instead of a hang).

```js
server.on('mailboxSession', session => {
  // 1. What folders exist?
  session.on('folders', cb =>
    cb(null, [{ name: 'INBOX' }, { name: 'Sent', specialUse: 'Sent' }]));

  // 2. Open a folder (SELECT): its counters
  session.on('openFolder', (name, cb) =>
    cb(null, { total: 12, unread: 3, uidValidity: 1, uidNext: 13 }));

  // 3. Turn a requested range ("1:10", UIDs...) into concrete messages
  session.on('resolveMessages', (folder, query, cb) =>
    cb(null, [{ seq: 1, uid: 101 }, { seq: 2, uid: 102 }]));

  // 4. Cheap metadata for message lists
  session.on('messageMeta', (folder, uids, cb) =>
    cb(null, uids.map(uid => ({ uid, flags: ['Seen'], size: 2048, internalDate: new Date() }))));

  // 5. The raw message bytes
  session.on('messageBody', (folder, uid, responder) =>
    responder.send(loadRawBytes(uid)));       // or responder.stream(...) for large messages

  // 6. Flag changes (read/starred/deleted) — also receives the implicit
  //    \Seen the library reports when a client fetches a body (query.implicit === true)
  session.on('setFlags', (folder, query, cb) => { saveFlags(query); cb(null); });
});
```

That's a complete, Thunderbird-compatible mailbox. Add `search` when you want server-side search, `append`/`expunge`/`copyMessages` for full manipulation, and the rest only for the extensions you care about.

**Folder names are always clean UTF-8 on your side.** Clients send international folder names in IMAP's modified UTF-7 wire encoding (`&BecF0QXcBdUF6g-`); the library decodes every inbound name and encodes every outbound one, so your handlers see and return `"קבלות"` and never the wire form.

**Missing-folder errors:** in `append`/`copyMessages`/`move`, set `err.tryCreate = true` when the target folder doesn't exist — the library answers `NO [TRYCREATE]` and well-behaved clients auto-create the folder and retry.

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
session.notifyExpunge(seq, uid)          // → * <seq> EXPUNGE  (or * VANISHED <uid> when QRESYNC enabled)
session.notifyVanished(arg)              // → * VANISHED ...   (arg = [uids] | {ranges} | {uids})
session.notifyFlags(seq, uid, flags)     // → * <seq> FETCH (UID ... FLAGS (...))
```

These write untagged responses to the client only while the session is in the **SELECTED** state (the folder the notification concerns is open). Outside SELECTED they are no-ops — the library does not buffer them. Use `server.forEachMailboxSession(fn)` to find the sessions that currently have the affected folder open (`s.currentFolder`) and notify those.

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

When a message is received on an inbound port, these checks run automatically
before the `mail` event fires. The first three run **in parallel**; DMARC runs
last because it needs their results:

1. **Reverse DNS** — FCrDNS (forward-confirmed reverse) + EHLO hostname match
2. **SPF** — authorize the sending IP against the envelope sender's domain
3. **DKIM** — verify every signature in the message; require at least one from the From domain for alignment
4. **DMARC** — evaluate policy (none / quarantine / reject) with SPF-or-DKIM alignment

Results arrive on `mail.auth`:

| Field | Values |
|---|---|
| `dkim` | `pass` `fail` `none` `temperror` `permerror` |
| `dkimDomain` | the `d=` of the signature that passed, or `null` |
| `spf` | `pass` `fail` `softfail` `neutral` `none` `temperror` `permerror` |
| `dmarc` | `pass` `fail` `none` |
| `dmarcPolicy` | `none` `quarantine` `reject` — the **effective** policy: `sp=` when the message came from a subdomain, otherwise `p=` |
| `dmarcPct` | `0`–`100` — the owner's `pct=` rollout percentage (100 when unset) |
| `dmarcApplies` | whether **this** message fell inside that percentage. See below |
| `rdns` | `pass` `fail` |
| `rdnsHostname` | the forward-confirmed PTR name, or `null` |

The library does not auto-reject — it hands you the verdicts and you decide.
It cannot make that call for you: the same DMARC failure that one operator
quarantines, another accepts because they know the sender forwards through a
mailing list.

#### `pct=` — check `dmarcApplies`, not just the policy

Domain owners roll DMARC out gradually: `p=reject; pct=5`, then `20`, then
`50`, then `100`. `pct` means *"apply this policy to N% of failures — let the
rest through while I watch the reports."*

A receiver that ignores `pct` enforces at 100% from day one and rejects mail
the owner explicitly asked it to deliver. So gate on `dmarcApplies`:

```js
// ✗ ignores pct= — rejects mail during someone else's rollout
if (mail.auth.dmarc === 'fail' && mail.auth.dmarcPolicy === 'reject') {
  return mail.reject(550, 'DMARC policy rejection');
}

// ✓ honours the owner's rollout percentage
if (mail.auth.dmarc === 'fail' && mail.auth.dmarcApplies) {
  if (mail.auth.dmarcPolicy === 'reject')     return mail.reject(550, 'DMARC policy rejection');
  if (mail.auth.dmarcPolicy === 'quarantine') return deliverToJunk(mail);
}
```

`dmarcPolicy` always reports what the owner asked for; `dmarcApplies` is the
per-message sampling decision, drawn once when the policy is evaluated.
`p=none` is never sampled out — there is nothing to enforce.

#### `sp=` — subdomains can carry a different policy

`v=DMARC1; p=reject; sp=none` on `example.com` means *"reject failures from
example.com itself, but let subdomains through."* `dmarcPolicy` already
resolves this for you — it reports `sp=` when the message came from a
subdomain, `p=` otherwise — so the code above needs no extra branch.
`mail.auth` also carries the raw verdict details if you want them.

### Outbound DKIM signing

When a domain is registered via `server.addDomain(material)`, every outbound message from that domain is automatically DKIM-signed using the key from `material.dkim`. No per-message configuration needed.

### Transport security

* **STARTTLS + implicit TLS** on every protocol (SMTP 25/587/465, IMAP 143/993, POP3 110/995)
* **SNI support** — multi-domain on a single port with `SNICallback`
* **TLS context caching** with `server.clearTlsCache()` for Let's Encrypt rotation
* **MTA-STS both directions** — policy generation for your domains, AND sender-side enforcement (RFC 8461): before delivering to a remote domain its policy is fetched and, in `enforce` mode, only policy-matching MXs over fully-validated TLS are used. Opt out per-send with `mtaSts: false`
* **REQUIRETLS** — refuse to deliver sensitive mail over cleartext
* **TLS-RPT** — receive daily reports about TLS failures from other MTAs

### Built-in protections

* **SMTP smuggling protection** (RFC 5321 §4.1.1.4) — bare LF normalization prevents CVE-2023-51764-class attacks
* **Mail-loop detection** — messages exceeding `maxReceivedHops` `Received:` headers are refused (RFC 5321 §6.3); a `loop` event fires so you can log the offender
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
| SMTP | `Received:` trace headers + mail-loop detection (RFC 5321 §4.4/§6.3) |
| SMTP | DSN parse (`parseDsn`) — structured incoming-bounce handling |
| SMTP client | MTA-STS sender-side enforcement (RFC 8461) |
| DMARC | Policy evaluation with `p=`, `sp=` (subdomain policy) and `pct=` (rollout sampling) |
| IMAP server | APPENDLIMIT / `[TOOBIG]` (RFC 7889) |
| Architecture | Handler watchdog (`handlerTimeout`) + queue persistence hooks |
| SMTP client | Direct MX + relay, connection pool with RSET reuse |
| SMTP client | Retry with backoff, per-domain outbound throttling |
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
| IMAP server | Modified UTF-7 mailbox names (RFC 3501 §5.1.3) — handlers always see UTF-8 |
| IMAP server | CHECK, implicit \\Seen on FETCH BODY[], [TRYCREATE] |
| IMAP client | Full `IMAPSession({isServer:false})` with all extensions |
| POP3 server | RFC 1939 + CAPA + STLS + SASL + XOAUTH2 |
| POP3 client | Full `POP3Session({isServer:false})` |
| Auth | DKIM sign + verify (RSA-SHA256, Ed25519-SHA256) |
| Auth | SPF, DMARC, rDNS — all automatic on inbound |
| Security | MTA-STS (RFC 8461) generation + HTTP handler |
| Security | TLS-RPT (RFC 8460) generation |
| Security | Multi-domain TLS with SNI caching |
| MIME | Compose + parse — full charset support (ISO-8859-*, windows-125x, CJK), RFC 2047 + RFC 2231 |
| Architecture | Unified `auth` / `smtpSession` / `mailboxSession` event model |
| Architecture | Bring-your-own-storage — library never persists messages |
| Architecture | Listener-gated capabilities — honest CAPABILITY advertising |
| Tooling | 360 tests, `buildDomainMailMaterial()`, Thunderbird demo |
| Packaging | One dependency (`node:` builtins + `flat-ranges`) |

### ⏳ Planned

| Item | Notes |
|---|---|
| Well-known services | `{ service: 'gmail' \| 'outlook' \| 'icloud' }` presets |
| Autoconfig / Autodiscover | RFC 6186 SRV + Mozilla ISPDB + MS Autodiscover |
| ARC (RFC 8617) | Authenticated Received Chain — lets a forwarder (mailing list, alias) vouch that DKIM/SPF passed *before* it rewrote the message, so the final recipient can still trust it |
| DMARC aggregate reports (`rua`) | Sending: accumulate per-source statistics and mail the daily gzipped XML report to the domain owner. Receiving: parse incoming reports into structured data. Deferred pending API design — where the counters are stored, and how the daily job is triggered, are the developer's choice |
| DMARC forensic reports (`ruf`) | Per-failure reports (RFC 6591). Rarely deployed; carries message content, so it needs a privacy story |
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