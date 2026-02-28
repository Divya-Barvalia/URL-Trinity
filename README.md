# Phishing URL Scanner

Paste a URL and get a **risk score** for visiting that site based on:

- **Domain age** (WhoisXML API)
- **SSL certificate** validity
- **VirusTotal** scan
- **Google Safe Browsing** lookup
- **Typosquatting** detection (brand-like domains)

Check it out here 👉 https://url-trinity.onrender.com

## API keys (optional)

Without keys, the app still runs and checks **SSL** and **typosquatting**. For full checks, add:

| Key | Purpose | Get it |
|-----|---------|--------|
| `VIRUSTOTAL_API_KEY` | URL scan & report | [VirusTotal](https://www.virustotal.com/gui/my-apikey) |
| `WHOISXML_API_KEY` | Domain age (WHOIS) | [WhoisXML](https://whoisxmlapi.com/) |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Safe Browsing lookup | [Google Cloud Console](https://console.cloud.google.com/apis/credentials) → enable Safe Browsing API |

Copy `.env.example` to `.env` and set the values.

## Risk score

0–25: low risk  
26–60: medium risk  
61–100: high risk  

Weights: SSL 25%, domain age 20%, typosquatting 25%, Safe Browsing 20%, VirusTotal 10%.
