require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const https = require('https');
const { URL } = require('url');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- Typosquatting: common brands + character substitutions
const BRAND_DOMAINS = [
  'google', 'amazon', 'microsoft', 'apple', 'facebook', 'netflix', 'paypal',
  'instagram', 'twitter', 'linkedin', 'yahoo', 'ebay', 'outlook', 'icloud',
  'dropbox', 'spotify', 'zoom', 'slack', 'github', 'gitlab', 'bitbucket',
  'bankofamerica', 'chase', 'wellsfargo', 'citibank', 'usps', 'fedex', 'dhl',
  'adobe', 'office365', 'teams', 'whatsapp', 'tiktok', 'discord', 'reddit'
];

const HOMOGLYPHS = {
  'o': ['0', 'q'],
  '0': ['o'],
  '1': ['l', 'i'],
  'l': ['1', 'i'],
  'i': ['1', 'l'],
  'a': ['4', '@'],
  'e': ['3'],
  's': ['5', '$'],
  'n': ['m'],
  'm': ['n']
};

function getDomainFromUrl(input) {
  try {
    let urlStr = input.trim();
    if (!/^https?:\/\//i.test(urlStr)) urlStr = 'https://' + urlStr;
    const u = new URL(urlStr);
    return u.hostname.replace(/^www\./, '').toLowerCase();
  } catch {
    return null;
  }
}

function normalizeForTyposquat(domain) {
  return domain.replace(/[^a-z0-9]/g, '');
}

function levenshtein(a, b) {
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b[i - 1] === a[j - 1]) matrix[i][j] = matrix[i - 1][j - 1];
      else matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j] + 1);
    }
  }
  return matrix[b.length][a.length];
}

function typosquatScore(domain) {
  // Compare the main label (e.g. "g00gle" from "g00gle.com"), not full hostname + TLD
  const mainLabel = domain.split('.')[0] || domain;
  const normalized = normalizeForTyposquat(mainLabel);
  if (normalized.length < 3) return { score: 0, matches: [] };

  const matches = [];
  for (const brand of BRAND_DOMAINS) {
    if (normalized.includes(brand) || brand.includes(normalized)) {
      matches.push({ brand, reason: 'contains_brand' });
      continue;
    }
    const dist = levenshtein(normalized, brand);
    const maxLen = Math.max(normalized.length, brand.length);
    const ratio = dist / maxLen;
    // Match if 1–2 chars different, or similarity ratio ≤ 0.35 (e.g. g00gle vs google)
    if (maxLen >= 3 && (dist <= 2 || ratio <= 0.35))
      matches.push({ brand, distance: dist, reason: 'similar' });
  }

  const score = Math.min(100, matches.length * 35);
  return { score, matches };
}

function checkSSL(targetUrl) {
  return new Promise((resolve) => {
    let urlStr = targetUrl.trim();
    if (!/^https?:\/\//i.test(urlStr)) urlStr = 'https://' + urlStr;
    if (!urlStr.startsWith('https://')) {
      resolve({ valid: false, error: 'No SSL (HTTP only)', score: 80 });
      return;
    }
    try {
      const u = new URL(urlStr);
      const options = {
        hostname: u.hostname,
        port: 443,
        path: '/',
        method: 'GET',
        timeout: 8000,
        rejectUnauthorized: true
      };
      const req = https.request(options, (res) => {
        const cert = res.socket.getPeerCertificate();
        if (!cert || !cert.valid_to) {
          resolve({ valid: false, error: 'No certificate info', score: 50 });
          return;
        }
        const expiry = new Date(cert.valid_to);
        const now = new Date();
        const daysLeft = (expiry - now) / (1000 * 60 * 60 * 24);
        let score = 0;
        if (daysLeft < 0) score = 90;
        else if (daysLeft < 7) score = 70;
        else if (daysLeft < 30) score = 40;
        resolve({
          valid: daysLeft > 0,
          issuer: cert.issuer?.O || 'Unknown',
          validTo: cert.valid_to,
          daysLeft: Math.round(daysLeft),
          score
        });
      });
      req.on('error', (err) => {
        let msg = err.message || 'SSL error';
        if (err.code === 'EPROTO' || /packet length too long|wrong version number/i.test(msg)) {
          msg = 'Server did not respond with SSL/TLS (site may be HTTP-only or use a different port)';
        }
        resolve({ valid: false, error: msg, score: 85 });
      });
      req.on('timeout', () => {
        req.destroy();
        resolve({ valid: false, error: 'Timeout', score: 60 });
      });
      req.setTimeout(8000);
      req.end();
    } catch (err) {
      resolve({ valid: false, error: err.message || 'Invalid URL', score: 70 });
    }
  });
}

async function whoisDomainAge(domain) {
  const apiKey = process.env.WHOISXML_API_KEY;
  if (!apiKey) return { score: 0, error: 'WHOIS API key not set', ageDays: null };

  try {
    const url = `https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName=${encodeURIComponent(domain)}&apiKey=${apiKey}&outputFormat=JSON`;
    const { data } = await axios.get(url, { timeout: 10000 });
    const created = data?.WhoisRecord?.createdDate || data?.WhoisRecord?.registryData?.createdDate;
    if (!created) return { score: 0, error: 'No creation date', ageDays: null };

    const createdDate = new Date(created);
    const ageDays = Math.floor((Date.now() - createdDate) / (1000 * 60 * 60 * 24));
    // New domains (< 30 days) are riskier
    let score = 0;
    if (ageDays < 7) score = 75;
    else if (ageDays < 30) score = 50;
    else if (ageDays < 90) score = 25;
    return { score, ageDays, createdDate: createdDate.toISOString().slice(0, 10) };
  } catch (err) {
    const msg = err.response?.data?.message || err.message;
    return { score: 30, error: msg, ageDays: null };
  }
}

async function virusTotalCheck(urlToCheck) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return { score: 0, error: 'VirusTotal API key not set', positives: null };

  try {
    const scanRes = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      new URLSearchParams({ url: urlToCheck }),
      {
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 15000
      }
    );
    const analysisId = scanRes.data?.data?.id;
    if (!analysisId) return { score: 0, error: 'No analysis ID', positives: null };

    await new Promise(r => setTimeout(r, 2000));

    const reportRes = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      { headers: { 'x-apikey': apiKey }, timeout: 10000 }
    );
    const stats = reportRes.data?.data?.attributes?.stats;
    const malicious = (stats && (stats.malicious || stats.suspicious)) ? (stats.malicious || 0) + (stats.suspicious || 0) : 0;
    const total = (stats && stats.harmless !== undefined) ? (stats.harmless || 0) + (stats.suspicious || 0) + (stats.malicious || 0) + (stats.undetected || 0) : 0;
    const positives = malicious;
    let score = 0;
    if (total > 0 && malicious > 0) score = Math.min(100, 40 + malicious * 15);
    return { score, positives, total, stats: stats || {} };
  } catch (err) {
    if (err.response?.status === 429) return { score: 0, error: 'VirusTotal rate limit', positives: null };
    const msg = err.response?.data?.error?.message || err.message;
    return { score: 0, error: msg, positives: null };
  }
}

async function googleSafeBrowsingCheck(urlToCheck) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey) return { score: 0, error: 'Google Safe Browsing API key not set', matches: [] };

  try {
    const res = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        client: { clientId: 'urlsafetychecker', clientVersion: '1.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url: urlToCheck }]
        }
      },
      { timeout: 8000 }
    );
    const matches = res.data?.matches || [];
    const score = matches.length > 0 ? 95 : 0;
    return { score, matches };
  } catch (err) {
    const msg = err.response?.data?.error?.message || err.message;
    return { score: 0, error: msg, matches: [] };
  }
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/scan', async (req, res) => {
  const { url } = req.body || {};
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'URL is required' });
  }

  let urlToCheck = url.trim();
  if (!/^https?:\/\//i.test(urlToCheck)) urlToCheck = 'https://' + urlToCheck;

  const domain = getDomainFromUrl(urlToCheck);
  if (!domain) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  try {
    const [ssl, whois, typosquat, safeBrowsing, virusTotal] = await Promise.all([
      checkSSL(urlToCheck),
      whoisDomainAge(domain),
      Promise.resolve(typosquatScore(domain)),
      googleSafeBrowsingCheck(urlToCheck),
      virusTotalCheck(urlToCheck)
    ]);

    const weights = { ssl: 0.25, whois: 0.20, typosquat: 0.25, safeBrowsing: 0.20, virusTotal: 0.10 };
    const totalScore = Math.round(
      ssl.score * weights.ssl +
      whois.score * weights.whois +
      typosquat.score * weights.typosquat +
      safeBrowsing.score * weights.safeBrowsing +
      virusTotal.score * weights.virusTotal
    );
    const riskScore = Math.min(100, totalScore);

    res.json({
      url: urlToCheck,
      domain,
      riskScore,
      results: {
        ssl,
        whois,
        typosquat,
        safeBrowsing,
        virusTotal
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Scan failed', message: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Phishing URL Scanner running at http://localhost:${PORT}`);
});
