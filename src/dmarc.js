
import * as dnsCache from './dns-cache.js';
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
  let policy = tags.p || 'none';
  let adkim = tags.adkim || 'r';
  let aspf = tags.aspf || 'r';

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
    policy: policy,
    dkimAligned: dkimAligned,
    spfAligned: spfAligned,
    adkim: adkim,
    aspf: aspf
  });
}


// ============================================================
//  Domain helpers
// ============================================================

function getOrgDomain(domain) {
  let parts = domain.split('.');
  if (parts.length <= 2) return domain;
  return parts.slice(-2).join('.');
}

function sameOrgDomain(domain1, domain2) {
  return getOrgDomain(domain1).toLowerCase() === getOrgDomain(domain2).toLowerCase();
}


export { checkDMARC, getOrgDomain, sameOrgDomain };
