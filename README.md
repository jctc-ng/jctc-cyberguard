# JCTC CyberGuard

**Check before you click. Verify before you pay.**

JCTC CyberGuard is a privacy-first public cybercrime risk and prevention assistant. The GitHub Pages MVP helps users check text, screenshots, suspicious emails and links for common indicators associated with:

- Phishing / credential theft
- Business Email Compromise (BEC)
- Sextortion / online blackmail
- Impersonation
- Investment / cryptocurrency scams
- Account takeover attempts
- Job / recruitment scams

## Important positioning

CyberGuard provides **risk indicators and prevention guidance**. It does not determine guilt, label a person a criminal, or replace investigators, financial institutions, emergency services or official reporting channels.

The public MVP does **not** create a crime-reporting database.

## Privacy and safeguarding

- Quick scans run locally in the browser.
- Screenshot OCR runs in the browser through Tesseract.js.
- Users are explicitly told **not to upload intimate or explicit images**.
- Passwords, OTPs, PINs and recovery codes should never be entered.
- The optional API analyses requests in memory and does not persist them.

## Repository structure

```text
/docs                GitHub Pages frontend
  index.html
  styles.css
  app.js
  sw.js
  manifest.webmanifest
  /assets
/api                 Optional protected backend
  main.py
  analyzer.py
  requirements.txt
  render.yaml
/.github/workflows   GitHub Pages deployment workflow
```

## Deploy the public frontend to GitHub Pages

1. Create a new GitHub repository, e.g. `jctc-cyberguard`.
2. Upload all files in this package, preserving the folders.
3. Commit to the `main` branch.
4. Open **Settings → Pages**.
5. Under **Build and deployment → Source**, choose **GitHub Actions**.
6. The included workflow will deploy the `/docs` site automatically.
7. After the workflow completes, GitHub will show the public Pages URL.

The frontend is useful immediately and does not require the optional backend.

## Run locally

From the repository root:

```bash
python -m http.server 8080 -d docs
```

Open `http://localhost:8080`.

## Optional API

The `/api` folder is a starter FastAPI backend for future protected AI / threat-intelligence integrations. It is intentionally separate because API keys must **never** be stored in GitHub Pages JavaScript.

Local run:

```bash
cd api
python -m venv .venv
# activate the environment, then:
pip install -r requirements.txt
uvicorn main:app --reload
```

Health check: `http://127.0.0.1:8000/health`

## Recommended next phases

1. Approved AI model integration on the protected backend.
2. Domain reputation and threat-intelligence checks.
3. Secure email-header parsing and DMARC/SPF/DKIM indicators.
4. Approved official reporting-channel directory.
5. Multilingual guidance (English, Hausa, Yoruba, Igbo, Pidgin).
6. Separate authenticated investigator environment for cross-case intelligence.

## Governance before national launch

Before presenting this as an official operational JCTC service, approve:

- privacy notice and data-protection impact assessment;
- safeguarding and child-protection workflow;
- retention/deletion policy;
- acceptable-use policy;
- escalation and reporting language;
- accessibility and security testing;
- legal review of public-facing guidance;
- ownership and maintenance responsibility.

