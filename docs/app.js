const tabs = document.querySelectorAll('.tab');
const panels = {
  message: document.getElementById('messageMode'),
  bec: document.getElementById('becMode'),
  url: document.getElementById('urlMode'),
  sextortion: document.getElementById('sextortionMode')
};

tabs.forEach(btn => btn.addEventListener('click', () => {
  tabs.forEach(b => b.classList.remove('active'));
  Object.values(panels).forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  panels[btn.dataset.mode].classList.add('active');
}));

const rules = {
  phishing: [
    [/otp|one[- ]time password|verification code/i, 16, 'Requests or references to an OTP / verification code'],
    [/password|pin|login|sign in|credential/i, 11, 'Requests for sensitive login information'],
    [/account.{0,25}(blocked|suspended|restricted|locked)/i, 13, 'Threatens account restriction or suspension'],
    [/click.{0,18}(link|here)|verify.{0,18}(account|identity)/i, 12, 'Pushes the recipient to click or verify through a link'],
    [/bank|wallet|payment service/i, 5, 'Uses financial-service language']
  ],
  bec: [
    [/urgent|immediately|asap|right away|today/i, 9, 'Creates urgency around a business action'],
    [/wire|transfer|payment|beneficiary|invoice|bank account/i, 12, 'Contains payment or beneficiary instructions'],
    [/new account|change.{0,15}(account|bank)|updated bank|different account/i, 18, 'Requests a change in payment destination'],
    [/do not call|don'?t call|confidential|keep this between us/i, 16, 'Discourages independent verification'],
    [/ceo|director|md|managing director|chairman|boss/i, 7, 'Uses executive-authority language']
  ],
  sextortion: [
    [/nude|naked|intimate|private (photo|video|image)|sex tape/i, 16, 'References intimate or private material'],
    [/send.{0,20}(money|bitcoin|crypto|usdt)|pay me|payment/i, 15, 'Demands money or value'],
    [/post|publish|share|send.{0,20}(family|friends|contacts|school|work)/i, 18, 'Threatens publication or distribution'],
    [/unless you|if you don'?t|or else|blackmail/i, 14, 'Uses conditional threats or coercion'],
    [/send.{0,15}(more|another).{0,12}(photo|image|video)/i, 18, 'Demands additional intimate material']
  ],
  investment: [
    [/guaranteed (profit|return)|risk[- ]free|no risk/i, 16, 'Promises guaranteed or risk-free returns'],
    [/double|triple|[2-9]x|[1-9]\d{2,}%/i, 11, 'Promises unusually large returns'],
    [/withdrawal fee|release fee|tax fee|unlock fee/i, 18, 'Requests an additional fee before withdrawal'],
    [/invest now|limited slot|act now|today only/i, 9, 'Pressures the recipient to invest quickly'],
    [/crypto|bitcoin|usdt|forex|mining/i, 5, 'Uses high-risk investment terminology']
  ],
  impersonation: [
    [/new number|lost my phone|my other number/i, 10, 'Uses a new-number explanation'],
    [/i'?m (your|the) (boss|director|friend|brother|sister|relative)/i, 8, 'Claims a familiar or authoritative identity'],
    [/send me|help me with|borrow me|urgent money/i, 9, 'Requests money through a personal appeal']
  ],
  takeover: [
    [/reset code|security code|verification code|otp/i, 12, 'References account recovery or verification codes'],
    [/your account|login attempt|password reset/i, 9, 'References account access or password recovery']
  ],
  jobscam: [
    [/job offer|employment|recruitment|work from home/i, 8, 'Presents a job or recruitment opportunity'],
    [/application fee|processing fee|training fee|visa fee/i, 18, 'Requests an upfront job-related fee'],
    [/no interview|instant employment|guaranteed job/i, 14, 'Promises employment without normal verification']
  ]
};

const categoryLabels = {
  phishing: 'Possible Phishing / Credential Theft',
  bec: 'Possible Business Email Compromise',
  sextortion: 'Possible Sextortion / Online Blackmail',
  investment: 'Possible Investment / Crypto Scam',
  impersonation: 'Possible Impersonation Scam',
  takeover: 'Possible Account Takeover Attempt',
  jobscam: 'Possible Job / Recruitment Scam',
  general: 'General Cybercrime Risk Indicators'
};

function analyseText(text, extra = {}) {
  const input = (text || '').trim();
  let categoryScores = {};
  let matched = [];

  Object.entries(rules).forEach(([category, group]) => {
    categoryScores[category] = 0;
    group.forEach(([pattern, score, reason]) => {
      if (pattern.test(input)) {
        categoryScores[category] += score;
        matched.push({ category, score, reason });
      }
    });
  });

  if (extra.replyMismatch) {
    categoryScores.bec = (categoryScores.bec || 0) + 24;
    matched.push({ category:'bec', score:24, reason:'From and Reply-To domains do not match' });
  }
  if (extra.minorInvolved) {
    categoryScores.sextortion = (categoryScores.sextortion || 0) + 25;
    matched.push({ category:'sextortion', score:25, reason:'A person under 18 may be involved — urgent safeguarding review is required' });
  }
  if (extra.moneyDemand) {
    categoryScores.sextortion = (categoryScores.sextortion || 0) + 12;
    matched.push({ category:'sextortion', score:12, reason:'A payment demand is reported' });
  }
  if (extra.moreImagesDemand) {
    categoryScores.sextortion = (categoryScores.sextortion || 0) + 16;
    matched.push({ category:'sextortion', score:16, reason:'More intimate material is being demanded' });
  }
  if (extra.publicationThreat) {
    categoryScores.sextortion = (categoryScores.sextortion || 0) + 18;
    matched.push({ category:'sextortion', score:18, reason:'A threat to publish or share material is reported' });
  }

  const ranked = Object.entries(categoryScores).sort((a,b) => b[1]-a[1]);
  const [topCategory, topScore] = ranked[0] || ['general',0];
  const secondScore = ranked[1]?.[1] || 0;
  const totalRisk = Math.min(100, Math.round(topScore + Math.min(secondScore * 0.25, 12)));
  const topIndicators = matched
    .filter(m => m.category === topCategory || m.score >= 16)
    .sort((a,b) => b.score-a.score)
    .map(m => m.reason)
    .filter((v,i,a) => a.indexOf(v) === i)
    .slice(0,6);

  return buildResult(topCategory, totalRisk, topIndicators, extra);
}

function analyseUrl(raw) {
  let urlString = (raw || '').trim();
  let indicators = [];
  let score = 0;
  if (!urlString) return buildResult('general',0,['No URL was entered.'],{});
  try {
    if (!/^https?:\/\//i.test(urlString)) urlString = 'https://' + urlString;
    const u = new URL(urlString);
    const host = u.hostname.toLowerCase();
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { score += 22; indicators.push('The link uses a raw IP address instead of a normal domain name'); }
    if (host.includes('xn--')) { score += 18; indicators.push('The domain contains Punycode and may visually imitate another domain'); }
    if ((host.match(/-/g)||[]).length >= 3) { score += 10; indicators.push('The domain contains an unusual number of hyphens'); }
    if (host.split('.').length >= 5) { score += 10; indicators.push('The link contains many subdomains, which can obscure the real domain'); }
    if (u.username || u.password) { score += 22; indicators.push('The URL contains embedded username/password information'); }
    if (urlString.length > 120) { score += 8; indicators.push('The URL is unusually long'); }
    if (/login|verify|secure|account|wallet|bank|update/i.test(u.pathname + u.search)) { score += 8; indicators.push('The path uses login, verification or account-security language'); }
    if (u.protocol !== 'https:') { score += 12; indicators.push('The link does not use HTTPS'); }
    if (/bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd/i.test(host)) { score += 10; indicators.push('The link uses a shortening service that hides the final destination'); }
    if (!indicators.length) indicators.push('No obvious structural URL warning signs were detected');
  } catch {
    score = 35;
    indicators.push('The text does not appear to be a well-formed URL');
  }
  return buildResult('phishing', Math.min(score,100), indicators, {urlOnly:true});
}

function buildResult(category, score, indicators, extra) {
  let level = 'LOW';
  if (score >= 65) level = 'CRITICAL';
  else if (score >= 40) level = 'HIGH';
  else if (score >= 15) level = 'MEDIUM';

  if (!indicators.length) indicators = ['No strong indicators were detected in the text provided. Continue to verify independently.'];

  const actionsByCategory = {
    sextortion: [
      'Do not panic and do not send more money or intimate material.',
      'Preserve the threatening messages, usernames, profile links, payment details, dates and times.',
      'Secure your accounts and tell a trusted person.',
      extra.minorInvolved ? 'Because a person under 18 may be involved, seek urgent safeguarding and official reporting support.' : 'Use an appropriate official reporting channel if the threat is active or harm has occurred.',
      'Do not upload or redistribute intimate images when seeking help.'
    ],
    bec: [
      'Do not make or change a payment based only on this email.',
      'Verify the instruction using a trusted phone number or contact method you already had before the email arrived.',
      'Preserve the original email and full headers.',
      'If payment was already made, contact the financial institution immediately and preserve transaction details.'
    ],
    phishing: [
      extra.urlOnly ? 'Do not open the link until the sender and destination are independently verified.' : 'Do not click suspicious links or provide passwords, OTPs, PINs or recovery codes.',
      'Verify the request using the organisation’s independently confirmed website, app or contact details.',
      'Preserve the message, sender details, link and time received.',
      'If credentials were already entered, secure the affected account immediately.'
    ],
    investment: [
      'Do not send money because of urgency or guaranteed-return claims.',
      'Independently verify the operator, investment and regulatory status.',
      'Do not pay repeated “withdrawal”, “tax” or “release” fees without verification.',
      'Preserve adverts, chats, account details, wallet addresses, transaction IDs and receipts.'
    ],
    impersonation: [
      'Contact the person or organisation through a previously trusted channel.',
      'Do not send money solely because the message appears to come from someone you know.',
      'Preserve the fake profile, username, phone number and messages.'
    ],
    takeover: [
      'Do not share verification codes or recovery credentials.',
      'Change compromised passwords and enable additional account security where available.',
      'Review active sessions and recovery details on the account.'
    ],
    jobscam: [
      'Verify the employer independently before paying any fee or sharing sensitive information.',
      'Be cautious of guaranteed jobs, instant offers or recruitment payments.',
      'Preserve the advert, recruiter profile, emails and payment instructions.'
    ],
    general: [
      'Verify unusual requests independently before acting.',
      'Do not disclose passwords, OTPs, PINs or recovery codes.',
      'Preserve relevant messages, account details, links and transaction records.'
    ]
  };

  const evidenceByCategory = {
    sextortion:['Threat messages','Username/profile URL','Phone/email','Payment details','Wallet address','Dates & times'],
    bec:['Original email','Full headers','Invoice','Beneficiary details','Payment record','Verification call notes'],
    phishing:['Message','Sender details','URL','Screenshot','Account activity','Date & time'],
    investment:['Advert','Chats','Website/domain','Bank/wallet details','Transaction IDs','Receipts'],
    impersonation:['Profile URL','Username','Phone number','Messages','Payment request','Screenshot'],
    takeover:['Security alerts','Login history','Recovery changes','Messages','Device/session details'],
    jobscam:['Job advert','Recruiter profile','Emails','Payment request','Bank details'],
    general:['Messages','Screenshots','Usernames','Links','Payment details','Dates & times']
  };

  const summary = score >= 65
    ? 'Multiple high-risk indicators were detected. Treat the communication as potentially harmful until independently verified.'
    : score >= 40
    ? 'Several significant risk indicators were detected. Do not act on the request until you independently verify it.'
    : score >= 15
    ? 'Some warning signs were detected. Use caution and verify before clicking, paying or sharing information.'
    : 'Few strong indicators were detected in the information supplied. This does not guarantee that the communication is safe.';

  return {
    category,
    label: categoryLabels[category] || categoryLabels.general,
    score,
    level,
    indicators,
    actions: actionsByCategory[category] || actionsByCategory.general,
    evidence: evidenceByCategory[category] || evidenceByCategory.general,
    summary
  };
}

function renderResult(result) {
  document.getElementById('emptyState').hidden = true;
  document.getElementById('resultState').hidden = false;
  document.getElementById('resultCategory').textContent = result.label;
  document.getElementById('riskSummary').textContent = result.summary;

  const badge = document.getElementById('riskBadge');
  badge.textContent = `${result.level} • ${result.score}%`;
  const palette = {LOW:'#23c77a',MEDIUM:'#e1b34d',HIGH:'#f09a48',CRITICAL:'#ef5a62'};
  badge.style.background = palette[result.level] + '22';
  badge.style.color = palette[result.level];
  badge.style.border = `1px solid ${palette[result.level]}66`;
  const meter = document.getElementById('riskMeterFill');
  meter.style.width = result.score + '%';
  meter.style.background = palette[result.level];

  const indicatorList = document.getElementById('indicatorList');
  indicatorList.innerHTML = '';
  result.indicators.forEach(x => { const li=document.createElement('li'); li.textContent=x; indicatorList.appendChild(li); });

  const actionList = document.getElementById('actionList');
  actionList.innerHTML = '';
  result.actions.forEach(x => { const li=document.createElement('li'); li.textContent=x; actionList.appendChild(li); });

  const evidence = document.getElementById('evidenceTags');
  evidence.innerHTML = '';
  result.evidence.forEach(x => { const s=document.createElement('span'); s.textContent=x; evidence.appendChild(s); });
}

document.getElementById('analyzeMessage').addEventListener('click', () => {
  renderResult(analyseText(document.getElementById('messageInput').value));
});

document.getElementById('clearMessage').addEventListener('click', () => {
  document.getElementById('messageInput').value='';
  document.getElementById('screenshotInput').value='';
  document.getElementById('ocrStatus').textContent='';
});

document.getElementById('analyzeBec').addEventListener('click', () => {
  const from = document.getElementById('fromEmail').value.trim();
  const reply = document.getElementById('replyToEmail').value.trim();
  let mismatch = false;
  const domain = email => (email.split('@')[1] || '').toLowerCase();
  if (from && reply && domain(from) && domain(reply) && domain(from) !== domain(reply)) mismatch = true;
  const text = `${document.getElementById('emailSubject').value}\n${document.getElementById('emailBody').value}`;
  const res = analyseText(text,{replyMismatch:mismatch});
  if (res.category !== 'bec' && mismatch) res.category='bec';
  renderResult(res);
});

document.getElementById('analyzeUrl').addEventListener('click', () => {
  renderResult(analyseUrl(document.getElementById('urlInput').value));
});

document.getElementById('analyzeSextortion').addEventListener('click', () => {
  renderResult(analyseText(document.getElementById('sextortionText').value, {
    moneyDemand: document.getElementById('moneyDemand').checked,
    moreImagesDemand: document.getElementById('moreImagesDemand').checked,
    publicationThreat: document.getElementById('publicationThreat').checked,
    minorInvolved: document.getElementById('minorInvolved').checked
  }));
});

const screenshotInput = document.getElementById('screenshotInput');
screenshotInput.addEventListener('change', async () => {
  const file = screenshotInput.files?.[0];
  const status = document.getElementById('ocrStatus');
  if (!file) return;
  if (!window.Tesseract) {
    status.textContent = 'Text extraction library could not load. You can still paste the text manually.';
    return;
  }
  status.textContent = 'Extracting text locally from the screenshot…';
  try {
    const result = await Tesseract.recognize(file, 'eng', {
      logger: m => {
        if (m.status === 'recognizing text') status.textContent = `Extracting text… ${Math.round((m.progress||0)*100)}%`;
      }
    });
    const extracted = result.data.text.trim();
    if (extracted) {
      document.getElementById('messageInput').value = extracted;
      status.textContent = 'Text extracted. Review it, then run the risk check.';
    } else status.textContent = 'No readable text was found. Paste the message manually.';
  } catch (e) {
    console.error(e);
    status.textContent = 'Text extraction failed. Paste the message manually.';
  }
});

let deferredPrompt;
window.addEventListener('beforeinstallprompt', e => {
  e.preventDefault(); deferredPrompt = e;
  const btn = document.getElementById('installBtn'); btn.hidden = false;
  btn.addEventListener('click', async () => { deferredPrompt.prompt(); await deferredPrompt.userChoice; btn.hidden=true; });
});

if ('serviceWorker' in navigator) window.addEventListener('load', () => navigator.serviceWorker.register('sw.js'));
