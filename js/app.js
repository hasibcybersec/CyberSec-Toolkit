import {
  analyzePassword,
  auditJwt,
  hmacSha256Hex,
  identifyHash,
  md5Hex,
  transformPayload,
  webDigestHex,
} from './crypto-utils.js';
import { checkHibpBreach, queryDnsRecon } from './recon.js';

// Tab Switching
document.querySelectorAll('.tab').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((b) => {
      b.classList.remove('active');
      b.setAttribute('aria-selected', 'false');
    });
    document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
    btn.classList.add('active');
    btn.setAttribute('aria-selected', 'true');
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
  });
});

function renderFindings(container, findings) {
  container.innerHTML = '';
  for (const item of findings) {
    const div = document.createElement('div');
    div.className = `finding ${item.level || 'info'}`;
    div.textContent = item.text;
    container.appendChild(div);
  }
}

// 1. Password Analyzer
const pwInput = document.getElementById('pw-input');
const pwToggle = document.getElementById('pw-toggle');
const pwFill = document.getElementById('pw-meter-fill');
const pwVerdict = document.getElementById('pw-verdict');
const pwEntropy = document.getElementById('pw-entropy');
const pwCrack = document.getElementById('pw-crack-gpu');
const pwHibpStatus = document.getElementById('pw-hibp-status');
const pwFindings = document.getElementById('pw-findings');

function updatePasswordUI() {
  const res = analyzePassword(pwInput.value);
  pwEntropy.textContent = `${res.entropy} bits`;
  pwVerdict.textContent = res.verdict;
  pwCrack.textContent = res.crackTime;
  pwFill.style.width = `${res.percent}%`;
  pwFill.style.background =
    res.level === 'ok' ? '#10b981' : res.level === 'warn' ? '#f59e0b' : '#ef4444';
  pwHibpStatus.textContent = pwInput.value ? 'Ready to check' : 'Not checked';
  renderFindings(pwFindings, res.findings);
}

pwInput.addEventListener('input', updatePasswordUI);
pwToggle.addEventListener('click', () => {
  const hidden = pwInput.type === 'password';
  pwInput.type = hidden ? 'text' : 'password';
  pwToggle.textContent = hidden ? 'Hide' : 'Show';
});

document.getElementById('pw-hibp-btn').addEventListener('click', async () => {
  if (!pwInput.value) return;
  pwHibpStatus.textContent = 'Querying HIBP...';
  try {
    const res = await checkHibpBreach(pwInput.value);
    pwHibpStatus.textContent = res.pwned ? `LEAKED (${res.count.toLocaleString()}x)` : 'Not found in HIBP';
    pwHibpStatus.style.color = res.pwned ? '#ef4444' : '#10b981';
  } catch (err) {
    pwHibpStatus.textContent = `Check failed (${err.message})`;
  }
});

// 2. Hash Lab & Identifier
const hashInput = document.getElementById('hash-input');
const hmacKey = document.getElementById('hmac-key');
const hashOutputs = document.getElementById('hash-outputs');

async function updateHashes() {
  const text = hashInput.value;
  const rows = [
    ['MD5 (Legacy)', md5Hex(text)],
    ['SHA-1', await webDigestHex('SHA-1', text)],
    ['SHA-256', await webDigestHex('SHA-256', text)],
    ['SHA-512', await webDigestHex('SHA-512', text)],
  ];
  if (hmacKey.value) {
    rows.push(['HMAC-SHA256', await hmacSha256Hex(hmacKey.value, text)]);
  }
  hashOutputs.innerHTML = '';
  for (const [k, v] of rows) {
    const item = document.createElement('div');
    item.className = 'kv-item';
    const kEl = document.createElement('div');
    kEl.className = 'kv-key';
    kEl.textContent = k;
    const vEl = document.createElement('div');
    vEl.className = 'kv-val';
    vEl.textContent = v;
    item.append(kEl, vEl);
    hashOutputs.appendChild(item);
  }
}

hashInput.addEventListener('input', updateHashes);
hmacKey.addEventListener('input', updateHashes);

const hashIdBtn = document.getElementById('hash-id-btn');
const hashIdInput = document.getElementById('hash-id-input');
const hashIdResult = document.getElementById('hash-id-result');

function runHashIdentify() {
  const matches = identifyHash(hashIdInput.value);
  renderFindings(
    hashIdResult,
    matches.map((m) => ({ level: m.level, text: `${m.name} — ${m.detail}` }))
  );
}
hashIdBtn.addEventListener('click', runHashIdentify);

// 3. DNS Recon
const dnsDomain = document.getElementById('dns-domain');
const dnsBtn = document.getElementById('dns-scan-btn');
const dnsPosture = document.getElementById('dns-posture');
const dnsRecords = document.getElementById('dns-records');

async function runDns() {
  dnsBtn.disabled = true;
  dnsBtn.textContent = 'Scanning...';
  dnsRecords.innerHTML = '';
  try {
    const { results, posture } = await queryDnsRecon(dnsDomain.value);
    renderFindings(dnsPosture, posture);
    for (const [rtype, values] of Object.entries(results)) {
      const card = document.createElement('div');
      card.className = 'record-card';
      const title = document.createElement('h4');
      title.textContent = `${rtype} (${values.length})`;
      const ul = document.createElement('ul');
      if (values.length === 0) {
        const li = document.createElement('li');
        li.textContent = 'No records returned';
        li.style.color = '#64748b';
        ul.appendChild(li);
      } else {
        for (const val of values) {
          const li = document.createElement('li');
          li.textContent = val;
          ul.appendChild(li);
        }
      }
      card.append(title, ul);
      dnsRecords.appendChild(card);
    }
  } catch (err) {
    renderFindings(dnsPosture, [{ level: 'bad', text: err.message }]);
  } finally {
    dnsBtn.disabled = false;
    dnsBtn.textContent = 'Run Passive Recon';
  }
}
dnsBtn.addEventListener('click', runDns);

// 4. JWT & Payload Toolkit
const jwtInput = document.getElementById('jwt-input');
const jwtOutput = document.getElementById('jwt-output');
const jwtAudit = document.getElementById('jwt-audit');

function runJwtAudit() {
  const res = auditJwt(jwtInput.value);
  if (res.error) {
    renderFindings(jwtAudit, [{ level: 'bad', text: res.error }]);
    jwtOutput.textContent = '';
    return;
  }
  renderFindings(jwtAudit, res.findings);
  jwtOutput.textContent = JSON.stringify({ header: res.header, payload: res.payload }, null, 2);
}
document.getElementById('jwt-decode-btn').addEventListener('click', runJwtAudit);

const encInput = document.getElementById('enc-input');
const encOutput = document.getElementById('enc-output');
document.querySelectorAll('[data-enc]').forEach((btn) => {
  btn.addEventListener('click', () => {
    try {
      encOutput.textContent = transformPayload(encInput.value, btn.dataset.enc);
    } catch (err) {
      encOutput.textContent = `Transform error: ${err.message}`;
    }
  });
});

// Initial render
const initTab = new URLSearchParams(window.location.search).get('tab');
if (initTab) {
  const targetBtn = document.querySelector(`.tab[data-tab="${initTab}"]`);
  if (targetBtn) targetBtn.click();
}
updatePasswordUI();
updateHashes();
runHashIdentify();
runJwtAudit();
encOutput.textContent = transformPayload(encInput.value, 'b64e');
