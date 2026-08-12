
import * as dnsCache from './dns_cache.js';
import { parseTags } from './utils.js';


// ============================================================
//  DMARC check (RFC 7489)
// ============================================================

function checkDMARC(options, cb) {
  let fromDomain = options.fromDomain;

  if (!fromDomain) {
    return cb(null, { result: 'none', reason: 'No From domain' });
  }

  let dmarcName = '_dmarc.' + fromDomain;

  dnsCache.txt(dmarcName, function(err, records) {
    if (err || !records) {
      let orgDomain = getOrgDomain(fromDomain);
      if (orgDomain && orgDomain !== fromDomain) {
        let orgDmarcName = '_dmarc.' + orgDomain;
        dnsCache.txt(orgDmarcName, function(err2, records2) {
          if (err2 || !records2) {
            return cb(null, { result: 'none', domain: fromDomain, reason: 'No DMARC record' });
          }
          evaluateDMARC(fromDomain, orgDomain, records2, options, cb);
        });
        return;
      }
      return cb(null, { result: 'none', domain: fromDomain, reason: 'No DMARC record' });
    }

    evaluateDMARC(fromDomain, fromDomain, records, options, cb);
  });
}

function evaluateDMARC(fromDomain, dmarcDomain, records, options, cb) {
  let flat = records.map(function(r) { return r.join(''); });
  let dmarcRecord = flat.find(function(r) { return /^v=DMARC1/i.test(r); });

  if (!dmarcRecord) {
    return cb(null, { result: 'none', domain: fromDomain, reason: 'No DMARC record' });
  }

  let tags = parseTags(dmarcRecord, true);
  let adkim = tags.adkim || 'r';
  let aspf = tags.aspf || 'r';

  // --- Policy selection: p= vs sp= (RFC 7489 §6.3) ---
  //
  // A domain owner may set a DIFFERENT policy for subdomains. When the record
  // was found on the organizational domain but the message came from one of
  // its subdomains, sp= wins over p=. Ignoring sp= applied the parent's
  // policy to subdomains against the owner's explicit instruction — in both
  // directions: rejecting mail from a subdomain the owner had exempted
  // (sp=none), or waving through a subdomain they wanted quarantined.
  //
  // `dmarcDomain` is the domain the record was actually found on; checkDMARC
  // already falls back from the From domain to the organizational domain, so
  // a difference between the two is exactly the subdomain case.
  let policy = tags.p || 'none';
  let isSubdomain = fromDomain.toLowerCase() !== dmarcDomain.toLowerCase();
  if (isSubdomain && tags.sp) policy = tags.sp;

  // --- pct= : the rollout dial (RFC 7489 §6.3) ---
  //
  // "Apply this policy to N% of messages." Every organization ramps DMARC up
  // this way: p=reject; pct=5, then 20, then 50, then 100. A receiver that
  // ignores pct enforces at 100% from day one and rejects mail the domain
  // owner explicitly asked it to let through — legitimate mail, lost, during
  // exactly the period the owner is trying to measure.
  //
  // The sampling decision is made HERE (one random draw per message) but is
  // NOT applied automatically: `policy` still reports what the owner asked
  // for, and `applies` says whether THIS message fell inside the sample.
  // That keeps the library's contract — it measures, you decide — while
  // making the correct check a single field away.
  let pct = 100;
  if (tags.pct != null) {
    let parsed = parseInt(tags.pct, 10);
    if (!isNaN(parsed) && parsed >= 0 && parsed <= 100) pct = parsed;
  }
  // p=none is advisory anyway, so sampling it would be meaningless.
  let applies = (policy === 'none') ? true : (pct >= 100 ? true : (Math.random() * 100 < pct));

  let dkimAligned = false;
  if (options.dkimResult === 'pass' && options.dkimDomain) {
    if (adkim === 's') {
      dkimAligned = (options.dkimDomain.toLowerCase() === fromDomain.toLowerCase());
    } else {
      dkimAligned = sameOrgDomain(options.dkimDomain, fromDomain);
    }
  }

  let spfAligned = false;
  if (options.spfResult === 'pass' && options.spfDomain) {
    if (aspf === 's') {
      spfAligned = (options.spfDomain.toLowerCase() === fromDomain.toLowerCase());
    } else {
      spfAligned = sameOrgDomain(options.spfDomain, fromDomain);
    }
  }

  let dmarcResult = (dkimAligned || spfAligned) ? 'pass' : 'fail';

  cb(null, {
    result: dmarcResult,
    domain: fromDomain,
    policy: policy,          // effective policy — sp= when this is a subdomain
    pct: pct,                // 0-100, the owner's rollout percentage
    applies: applies,        // did THIS message fall inside the pct sample?
    isSubdomain: isSubdomain,
    dkimAligned: dkimAligned,
    spfAligned: spfAligned,
    adkim: adkim,
    aspf: aspf
  });
}


// ============================================================
//  Domain helpers
// ============================================================

// Multi-label public suffixes. Without this, getOrgDomain('mail.example.co.uk')
// returns 'co.uk' — breaking DMARC relaxed alignment for every domain under a
// two-label suffix. This is a compact embedded subset of the Public Suffix List
// covering the overwhelming majority of real-world mail domains. For full PSL
// coverage the operator can add entries at runtime via addPublicSuffix().
//
// (RFC 7489 §3.2 defines the Organizational Domain in terms of the PSL.)
const MULTI_LABEL_SUFFIXES = new Set([
  // United Kingdom
  'co.uk','org.uk','ac.uk','gov.uk','net.uk','sch.uk','me.uk','ltd.uk','plc.uk','nhs.uk',
  // Israel
  'co.il','org.il','ac.il','gov.il','net.il','k12.il','muni.il','idf.il',
  // Australia / New Zealand
  'com.au','net.au','org.au','edu.au','gov.au','asn.au','id.au',
  'co.nz','net.nz','org.nz','ac.nz','govt.nz','school.nz','geek.nz','gen.nz','maori.nz','iwi.nz',
  // Japan
  'co.jp','or.jp','ne.jp','ac.jp','ad.jp','ed.jp','go.jp','gr.jp','lg.jp',
  // South Korea / China / Taiwan / Hong Kong / Singapore
  'co.kr','or.kr','ne.kr','re.kr','pe.kr','go.kr','ac.kr',
  'com.cn','net.cn','org.cn','gov.cn','edu.cn','ac.cn',
  'com.tw','net.tw','org.tw','edu.tw','gov.tw','idv.tw',
  'com.hk','net.hk','org.hk','edu.hk','gov.hk','idv.hk',
  'com.sg','net.sg','org.sg','edu.sg','gov.sg','per.sg',
  // India / South-East Asia
  'co.in','net.in','org.in','firm.in','gen.in','ind.in','ac.in','edu.in','res.in','gov.in','nic.in',
  'com.my','net.my','org.my','edu.my','gov.my',
  'co.th','in.th','ac.th','go.th','or.th','net.th',
  'com.ph','net.ph','org.ph','edu.ph','gov.ph',
  'co.id','or.id','ac.id','go.id','web.id','my.id','net.id',
  'com.vn','net.vn','org.vn','edu.vn','gov.vn',
  // Latin America
  'com.br','net.br','org.br','gov.br','edu.br','mil.br','art.br','adv.br','ind.br','inf.br',
  'com.mx','net.mx','org.mx','edu.mx','gob.mx',
  'com.ar','net.ar','org.ar','edu.ar','gob.ar','gov.ar','int.ar','mil.ar',
  'com.co','net.co','org.co','edu.co','gov.co','nom.co',
  'com.pe','net.pe','org.pe','edu.pe','gob.pe',
  'com.uy','net.uy','org.uy','edu.uy','gub.uy',
  'com.ve','net.ve','org.ve','co.ve','e12.ve','gob.ve',
  'cl.cl','gob.cl','gov.cl',  // (Chile mostly flat; keep gob/gov)
  // Africa / Middle East
  'co.za','net.za','org.za','web.za','ac.za','gov.za','edu.za',
  'com.eg','net.eg','org.eg','edu.eg','gov.eg','sci.eg',
  'com.sa','net.sa','org.sa','edu.sa','gov.sa','med.sa','sch.sa',
  'com.tr','net.tr','org.tr','edu.tr','gov.tr','bel.tr','k12.tr','av.tr','web.tr',
  'co.ke','or.ke','ne.ke','go.ke','ac.ke','sc.ke',
  'com.ng','net.ng','org.ng','edu.ng','gov.ng','i.ng',
  'co.ma','net.ma','org.ma','ac.ma','gov.ma','press.ma',
  'com.gh','edu.gh','gov.gh','org.gh',
  'ae.org','co.ae',  // UAE common
  // Europe (multi-label ccTLD schemes)
  'com.pl','net.pl','org.pl','edu.pl','gov.pl','waw.pl','biz.pl','info.pl',
  'com.gr','net.gr','org.gr','edu.gr','gov.gr',
  'com.pt','net.pt','org.pt','edu.pt','gov.pt','int.pt','publ.pt',
  'com.es','nom.es','org.es','gob.es','edu.es',
  'co.at','or.at','ac.at','gv.at','priv.at',
  'com.ua','net.ua','org.ua','edu.ua','gov.ua','in.ua','kiev.ua',
  'com.ru','net.ru','org.ru','msk.ru','spb.ru',
  'co.hu','org.hu','info.hu','priv.hu','sport.hu','tm.hu','2000.hu',
  'com.ro','org.ro','tm.ro','nt.ro','store.ro','info.ro','nom.ro','www.ro',
  // North America (other)
  'co.ca','gc.ca',  // rare but exists
  // Popular private/hosted suffixes (operate like registries for DMARC purposes)
  'github.io','gitlab.io','herokuapp.com','azurewebsites.net','cloudfront.net',
  'blogspot.com','appspot.com','web.app','firebaseapp.com','netlify.app',
  'vercel.app','pages.dev','workers.dev','onrender.com','fly.dev','glitch.me',
  'wordpress.com','wixsite.com','weebly.com','fastly.net','s3.amazonaws.com'
]);

// Runtime extension hook — operators with domains under an uncovered suffix
// can register it once at startup: addPublicSuffix('co.xx')
function addPublicSuffix(suffix) {
  if (suffix) MULTI_LABEL_SUFFIXES.add(String(suffix).toLowerCase().replace(/^\./, ''));
}

function getOrgDomain(domain) {
  let d = String(domain || '').toLowerCase().replace(/\.$/, '');
  let parts = d.split('.');
  if (parts.length <= 2) return d;

  // Longest-match: check 3-label suffixes first (e.g. act.edu.au style),
  // then 2-label. The org domain is the suffix plus one more label.
  for (let take = 3; take >= 2; take--) {
    if (parts.length > take) {
      let suffix = parts.slice(-take).join('.');
      if (MULTI_LABEL_SUFFIXES.has(suffix)) {
        return parts.slice(-(take + 1)).join('.');
      }
    }
  }
  return parts.slice(-2).join('.');
}

function sameOrgDomain(domain1, domain2) {
  return getOrgDomain(domain1).toLowerCase() === getOrgDomain(domain2).toLowerCase();
}


export { checkDMARC, getOrgDomain, sameOrgDomain, addPublicSuffix };
