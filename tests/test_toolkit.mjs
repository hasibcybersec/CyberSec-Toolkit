import assert from 'node:assert/strict';
import {
  analyzePassword,
  auditJwt,
  hmacSha256Hex,
  identifyHash,
  md5Hex,
  transformPayload,
  webDigestHex,
} from '../js/crypto-utils.js';

// 1. Verify RFC 1321 MD5 test vectors
assert.equal(md5Hex(''), 'd41d8cd98f00b204e9800998ecf8427e');
assert.equal(md5Hex('abc'), '900150983cd24fb0d6963f7d28e17f72');

// 2. Verify SHA-256 and HMAC-SHA256
const sha256 = await webDigestHex('SHA-256', 'abc');
assert.equal(sha256, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
const hmac = await hmacSha256Hex('secret', 'message');
assert.equal(hmac.length, 64);

// 3. Verify password analyzer flags weak vs strong passwords
const weak = analyzePassword('password123');
assert.equal(weak.verdict, 'Critical');
const strong = analyzePassword('Tr0ub4dour&Kali#2026!Sec');
assert.equal(strong.verdict, 'Strong');
assert.ok(strong.entropy > 80);

// 4. Verify hash identifier
assert.equal(identifyHash('900150983cd24fb0d6963f7d28e17f72')[0].name, 'MD5 / NTLM (128-bit hex)');
assert.equal(identifyHash('$2b$12$eImiTXuWVxfM37uY4JANjQOe3E5r2a0m9fR1n0vK1r6c1E5kQ4mGu')[0].name, 'Bcrypt');

// 5. Verify JWT auditor detects alg: none
const jwtRes = auditJwt('eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMzM3In0.');
assert.ok(jwtRes.findings.some((f) => f.level === 'bad' && f.text.includes('alg: none')));

// 6. Verify payload encoder/decoder roundtrip
const payload = "<script>alert('XSS')</script>";
assert.equal(transformPayload(transformPayload(payload, 'b64e'), 'b64d'), payload);
assert.equal(transformPayload(transformPayload(payload, 'hexe'), 'hexd'), payload);

console.log('All CyberSec Toolkit tests passed!');
