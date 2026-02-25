const form = document.getElementById('scanForm');
const urlInput = document.getElementById('urlInput');
const submitBtn = document.getElementById('submitBtn');
const resultEl = document.getElementById('result');
const riskBanner = document.getElementById('riskBanner');
const riskValue = document.getElementById('riskValue');
const riskVerdict = document.getElementById('riskVerdict');
const resultUrl = document.getElementById('resultUrl');
const resultDomain = document.getElementById('resultDomain');
const checksList = document.getElementById('checksList');
const errorEl = document.getElementById('error');
const errorMessage = document.getElementById('errorMessage');

function setLoading(loading) {
  submitBtn.disabled = loading;
  submitBtn.classList.toggle('loading', loading);
}

function showError(msg) {
  errorEl.hidden = false;
  resultEl.hidden = true;
  errorMessage.textContent = msg;
}

function hideError() {
  errorEl.hidden = true;
}

function riskClass(score) {
  if (score <= 25) return 'low';
  if (score <= 60) return 'medium';
  return 'high';
}

function riskVerdictText(score) {
  if (score <= 25) return 'Low risk — looks safer.';
  if (score <= 60) return 'Medium risk — review details below.';
  return 'High risk — likely unsafe. Avoid this URL.';
}

function renderCheck(title, status, detail) {
  const li = document.createElement('li');
  const icon = document.createElement('span');
  icon.className = 'check-icon ' + (status === 'ok' ? 'ok' : status === 'warn' ? 'warn' : status === 'bad' ? 'bad' : 'neutral');
  icon.textContent = status === 'ok' ? '✓' : status === 'bad' ? '!' : '○';
  const body = document.createElement('div');
  body.className = 'check-body';
  const titleEl = document.createElement('div');
  titleEl.className = 'check-title';
  titleEl.textContent = title;
  const detailEl = document.createElement('div');
  detailEl.className = 'check-detail';
  detailEl.textContent = detail;
  body.append(titleEl, detailEl);
  li.append(icon, body);
  checksList.appendChild(li);
}

function formatSSL(r) {
  if (r.error) return `SSL: ${r.error}`;
  if (r.valid) return `Valid SSL (${r.issuer}). Expires in ${r.daysLeft} days.`;
  return `Invalid or expiring: ${r.validTo || r.error}`;
}

function formatWhois(r) {
  if (r.error && !r.ageDays) return `WHOIS: ${r.error}`;
  if (r.ageDays != null) return `Domain age: ${r.ageDays} days (created ${r.createdDate})`;
  return r.error || 'Domain age unknown';
}

function formatTyposquat(r) {
  if (r.matches && r.matches.length) return `Possible typosquat: ${r.matches.map(m => m.brand).join(', ')}`;
  return 'No obvious typosquatting detected';
}

function formatSafeBrowsing(r) {
  if (r.error) return `Safe Browsing: ${r.error}`;
  if (r.matches && r.matches.length) return `Flagged: ${r.matches.map(m => m.threatType || 'threat').join(', ')}`;
  return 'Not in Google Safe Browsing threat list';
}

function formatVirusTotal(r) {
  if (r.error) return `VirusTotal: ${r.error}`;
  if (r.positives != null && r.total != null) return `${r.positives}/${r.total} engines flagged this URL`;
  if (r.positives != null) return `${r.positives} engine(s) flagged`;
  return 'No VirusTotal result (submit URL to scan)';
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  hideError();
  resultEl.hidden = true;
  const url = urlInput.value.trim();
  if (!url) return;

  setLoading(true);
  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      showError(data.error || data.message || 'Scan failed');
      setLoading(false);
      return;
    }

    const { riskScore, domain, results } = data;
    resultUrl.textContent = data.url;
    resultDomain.textContent = domain;
    riskValue.textContent = riskScore;
    riskVerdict.textContent = riskVerdictText(riskScore);
    riskBanner.className = 'risk-banner ' + riskClass(riskScore);

    checksList.innerHTML = '';
    const r = results;

    renderCheck(
      'SSL certificate',
      r.ssl.valid ? 'ok' : (r.ssl.score > 50 ? 'bad' : 'warn'),
      formatSSL(r.ssl)
    );
    renderCheck(
      'Domain age (WHOIS)',
      r.whois.score === 0 ? 'ok' : (r.whois.score >= 50 ? 'bad' : 'warn'),
      formatWhois(r.whois)
    );
    renderCheck(
      'Typosquatting',
      r.typosquat.score === 0 ? 'ok' : (r.typosquat.score >= 50 ? 'bad' : 'warn'),
      formatTyposquat(r.typosquat)
    );
    renderCheck(
      'Google Safe Browsing',
      r.safeBrowsing.score === 0 ? 'ok' : 'bad',
      formatSafeBrowsing(r.safeBrowsing)
    );
    renderCheck(
      'VirusTotal',
      (r.virusTotal.positives || 0) === 0 ? 'ok' : 'bad',
      formatVirusTotal(r.virusTotal)
    );

    resultEl.hidden = false;
  } catch (err) {
    showError(err.message || 'Network error');
  } finally {
    setLoading(false);
  }
});
