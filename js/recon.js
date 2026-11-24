import { webDigestHex } from './crypto-utils.js';

/**
 * Checks HIBP Pwned Passwords using k-Anonymity (only sends first 5 SHA-1 chars).
 */
export async function checkHibpBreach(password) {
  const sha1 = (await webDigestHex('SHA-1', password)).toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);

  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  if (!res.ok) throw new Error(`HIBP API returned HTTP ${res.status}`);
  const text = await res.text();
  for (const line of text.split(/\r?\n/)) {
    const [hashSuffix, count] = line.split(':');
    if (hashSuffix === suffix) {
      return { pwned: true, count: parseInt(count, 10) || 1 };
    }
  }
  return { pwned: false, count: 0 };
}

/**
 * Queries passive DNS records via Google Public DNS-over-HTTPS (DoH).
 */
export async function queryDnsRecon(rawDomain) {
  const domain = rawDomain.trim().replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) {
    throw new Error('Please enter a valid domain name (e.g. github.com).');
  }

  const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA'];
  const results = {};

  await Promise.all(
    types.map(async (type) => {
      const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`);
      const json = await res.json();
      results[type] = (json.Answer || []).map((a) => a.data);
    })
  );

  // Check DMARC separately at _dmarc.<domain>
  const dmarcRes = await fetch(`https://dns.google/resolve?name=${encodeURIComponent('_dmarc.' + domain)}&type=TXT`);
  const dmarcJson = await dmarcRes.json();
  results.DMARC = (dmarcJson.Answer || []).map((a) => a.data);

  const posture = [];
  const hasSpf = results.TXT.some((t) => /v=spf1/i.test(t));
  const hasDmarc = results.DMARC.some((t) => /v=DMARC1/i.test(t));
  const hasCaa = results.CAA.length > 0;

  posture.push(hasSpf
    ? { level: 'ok', text: 'SPF record found — helps prevent domain email spoofing.' }
    : { level: 'warn', text: 'No SPF record found in TXT records — email spoofing risk.' });
  posture.push(hasDmarc
    ? { level: 'ok', text: 'DMARC policy detected at _dmarc.' + domain + '.' }
    : { level: 'warn', text: 'Missing DMARC record at _dmarc.' + domain + ' — attackers may spoof sender domains.' });
  posture.push(hasCaa
    ? { level: 'ok', text: `CAA records present (${results.CAA.length}) — restricts unauthorized TLS certificate issuance.` }
    : { level: 'warn', text: 'No CAA record configured — any public CA may issue certificates for this domain.' });

  return { domain, results, posture };
}
