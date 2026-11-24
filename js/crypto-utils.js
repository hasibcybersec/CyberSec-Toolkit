/**
 * Pure cryptographic, entropy, hash identification, JWT auditing,
 * and payload encoding utilities.
 */

const COMMON_SEQUENCES = ['0123', '1234', '2345', '3456', '4567', '5678', '6789', 'abcd', 'qwer', 'asdf', 'zxcv', 'password', 'admin', 'qwerty', 'letmein', 'welcome'];

/**
 * Computes RFC 1321 MD5 hex digest in pure JS (for legacy hash comparison).
 */
export function md5Hex(input) {
  const bytes = new TextEncoder().encode(input);
  const words = [];
  for (let i = 0; i < bytes.length; i++) {
    words[i >> 2] = (words[i >> 2] || 0) | (bytes[i] << ((i % 4) * 8));
  }
  const bitLen = bytes.length * 8;
  words[bitLen >> 5] = (words[bitLen >> 5] || 0) | (0x80 << (bitLen % 32));
  const len = (((bytes.length + 8) >> 6) + 1) * 16;
  while (words.length < len) words.push(0);
  words[len - 2] = bitLen & 0xffffffff;
  words[len - 1] = Math.floor(bitLen / 0x100000000);

  const s = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];
  const K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;

  const rotl = (x, c) => ((x << c) | (x >>> (32 - c))) >>> 0;

  for (let i = 0; i < len; i += 16) {
    let A = a0, B = b0, C = c0, D = d0;
    for (let j = 0; j < 64; j++) {
      let F, g;
      if (j < 16) { F = (B & C) | (~B & D); g = j; }
      else if (j < 32) { F = (D & B) | (~D & C); g = (5 * j + 1) % 16; }
      else if (j < 48) { F = B ^ C ^ D; g = (3 * j + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * j) % 16; }
      const temp = (F + A + K[j] + (words[i + g] >>> 0)) >>> 0;
      A = D; D = C; C = B; B = (B + rotl(temp, s[j])) >>> 0;
    }
    a0 = (a0 + A) >>> 0;
    b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0;
    d0 = (d0 + D) >>> 0;
  }

  return [a0, b0, c0, d0]
    .map((w) => [0, 8, 16, 24].map((sh) => ((w >>> sh) & 0xff).toString(16).padStart(2, '0')).join(''))
    .join('');
}

export async function webDigestHex(algorithm, text) {
  const data = new TextEncoder().encode(text);
  const buf = await globalThis.crypto.subtle.digest(algorithm, data);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function hmacSha256Hex(key, text) {
  const enc = new TextEncoder();
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw',
    enc.encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await globalThis.crypto.subtle.sign('HMAC', cryptoKey, enc.encode(text));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Analyzes password strength, pool entropy, patterns, and crack duration.
 */
export function analyzePassword(pw) {
  if (!pw) {
    return {
      entropy: 0,
      poolSize: 0,
      verdict: 'Awaiting input',
      level: 'info',
      crackTime: '—',
      percent: 0,
      findings: [],
    };
  }

  let pool = 0;
  const hasLower = /[a-z]/.test(pw);
  const hasUpper = /[A-Z]/.test(pw);
  const hasDigit = /\d/.test(pw);
  const hasSymbol = /[^a-zA-Z0-9]/.test(pw);
  if (hasLower) pool += 26;
  if (hasUpper) pool += 26;
  if (hasDigit) pool += 10;
  if (hasSymbol) pool += 32;

  const rawEntropy = pool > 0 ? pw.length * Math.log2(pool) : 0;
  const lower = pw.toLowerCase();
  const findings = [];
  let penalty = 0;

  if (pw.length < 12) {
    findings.push({ level: 'warn', text: `Short length (${pw.length} chars). NIST/OWASP recommends at least 12–16 characters.` });
    penalty += 10;
  } else {
    findings.push({ level: 'ok', text: `Good length (${pw.length} characters).` });
  }

  const classes = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;
  if (classes < 3) {
    findings.push({ level: 'warn', text: 'Limited character diversity — mix uppercase, lowercase, digits, and symbols.' });
    penalty += 8;
  }

  if (/(.)\1{2,}/.test(pw)) {
    findings.push({ level: 'bad', text: 'Contains repeated characters (e.g., aaa or 111), reducing effective entropy.' });
    penalty += 14;
  }

  const hitSeq = COMMON_SEQUENCES.find((seq) => lower.includes(seq));
  if (hitSeq) {
    findings.push({ level: 'bad', text: `Contains predictable sequence or dictionary word ("${hitSeq}").` });
    penalty += 22;
  }

  const effectiveEntropy = Math.max(0, rawEntropy - penalty);
  const guesses = Math.pow(2, effectiveEntropy);
  const seconds = guesses / 1e10; // 10 billion hashes/sec GPU rig

  let verdict = 'Critical';
  let level = 'bad';
  if (effectiveEntropy >= 80) { verdict = 'Strong'; level = 'ok'; }
  else if (effectiveEntropy >= 60) { verdict = 'Moderate'; level = 'warn'; }
  else if (effectiveEntropy >= 40) { verdict = 'Weak'; level = 'bad'; }

  return {
    entropy: Number(effectiveEntropy.toFixed(1)),
    poolSize: pool,
    verdict,
    level,
    crackTime: formatDuration(seconds),
    percent: Math.min(100, Math.round((effectiveEntropy / 100) * 100)),
    findings,
  };
}

export function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds > 3.15e16) return 'Centuries+ (>1B yrs)';
  if (seconds < 1) return '< 1 second';
  const units = [
    ['years', 31536000],
    ['days', 86400],
    ['hours', 3600],
    ['minutes', 60],
    ['seconds', 1],
  ];
  for (const [name, div] of units) {
    if (seconds >= div) return `${Math.round(seconds / div)} ${name}`;
  }
  return `${seconds.toFixed(1)} seconds`;
}

/**
 * Identifies common cryptographic hash formats and tokens.
 */
export function identifyHash(raw) {
  const s = raw.trim();
  if (!s) return [];
  const matches = [];

  if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(s)) {
    matches.push({ name: 'Bcrypt', level: 'ok', detail: 'Adaptive password hash with salt & cost factor (strong).' });
  }
  if (/^\$argon2(id|i|d)\$/.test(s)) {
    matches.push({ name: 'Argon2', level: 'ok', detail: 'Memory-hard modern password hashing standard (strongest).' });
  }
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(s)) {
    matches.push({ name: 'JSON Web Token (JWT)', level: 'warn', detail: 'Signed/encoded token containing header.payload.signature.' });
  }
  if (/^[a-fA-F0-9]{32}$/.test(s)) {
    matches.push({ name: 'MD5 / NTLM (128-bit hex)', level: 'bad', detail: 'Fast legacy 32-hex digest — vulnerable to rainbow tables & collisions.' });
  }
  if (/^[a-fA-F0-9]{40}$/.test(s)) {
    matches.push({ name: 'SHA-1 (160-bit hex)', level: 'bad', detail: 'Deprecated cryptographic hash (40 hex chars) — collision attacks exist.' });
  }
  if (/^[a-fA-F0-9]{64}$/.test(s)) {
    matches.push({ name: 'SHA-256 / SHA3-256 (256-bit hex)', level: 'ok', detail: 'Modern 64-hex digest suitable for integrity verification.' });
  }
  if (/^[a-fA-F0-9]{96}$/.test(s)) {
    matches.push({ name: 'SHA-384 (384-bit hex)', level: 'ok', detail: 'High-strength 96-hex SHA-2 digest.' });
  }
  if (/^[a-fA-F0-9]{128}$/.test(s)) {
    matches.push({ name: 'SHA-512 / Whirlpool (512-bit hex)', level: 'ok', detail: '512-bit digest (128 hex chars).' });
  }
  if (/^\$6\$/.test(s)) {
    matches.push({ name: 'Linux SHA-512 Crypt ($6$)', level: 'ok', detail: 'Standard /etc/shadow salted SHA-512 hash.' });
  }

  if (matches.length === 0) {
    matches.push({ name: 'Unknown / Custom Format', level: 'warn', detail: `Length ${s.length} chars — does not match standard MD5/SHA/Bcrypt/Argon2/JWT signatures.` });
  }
  return matches;
}

function base64UrlDecode(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(str.length / 4) * 4, '=');
  const bin = atob(padded);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

/**
 * Decodes a JWT without sending it over the network and flags security issues.
 */
export function auditJwt(token) {
  const parts = token.trim().split('.');
  if (parts.length !== 3) {
    return { error: 'Invalid JWT structure. Expected 3 dot-separated segments (header.payload.signature).', findings: [] };
  }
  try {
    const header = JSON.parse(base64UrlDecode(parts[0]));
    const payload = JSON.parse(base64UrlDecode(parts[1]));
    const findings = [];

    const alg = String(header.alg || '').toLowerCase();
    if (!alg || alg === 'none') {
      findings.push({ level: 'bad', text: 'CRITICAL: Token uses "alg: none" — signature verification can be bypassed if accepted by server.' });
    } else if (alg.startsWith('hs')) {
      findings.push({ level: 'warn', text: `Symmetric HMAC (${header.alg}) detected — verify server uses strong >=256-bit secret and resists brute force.` });
    } else {
      findings.push({ level: 'ok', text: `Asymmetric algorithm (${header.alg}) detected.` });
    }

    if (!parts[2]) {
      findings.push({ level: 'bad', text: 'Signature segment is empty — unsigned token!' });
    }
    if (!payload.exp) {
      findings.push({ level: 'warn', text: 'Missing "exp" (expiration) claim — token may remain valid indefinitely if leaked.' });
    } else {
      const expired = payload.exp * 1000 < Date.now();
      findings.push({ level: expired ? 'warn' : 'ok', text: `Token expiration ("exp"): ${new Date(payload.exp * 1000).toISOString()} (${expired ? 'EXPIRED' : 'ACTIVE'}).` });
    }
    return { header, payload, signaturePresent: Boolean(parts[2]), findings };
  } catch (err) {
    return { error: `Failed to parse JWT JSON: ${err.message}`, findings: [] };
  }
}

export function transformPayload(input, mode) {
  switch (mode) {
    case 'b64e': {
      const bytes = new TextEncoder().encode(input);
      return btoa(String.fromCharCode(...bytes));
    }
    case 'b64d': {
      const bin = atob(input.trim());
      return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
    }
    case 'urle':
      return encodeURIComponent(input);
    case 'urld':
      return decodeURIComponent(input);
    case 'hexe':
      return Array.from(new TextEncoder().encode(input), (b) => b.toString(16).padStart(2, '0')).join(' ');
    case 'hexd': {
      const clean = input.replace(/[^0-9a-fA-F]/g, '');
      const bytes = [];
      for (let i = 0; i < clean.length; i += 2) bytes.push(parseInt(clean.slice(i, i + 2), 16));
      return new TextDecoder().decode(new Uint8Array(bytes));
    }
    default:
      return input;
  }
}
