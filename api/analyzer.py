import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Any

RULES = {
    "phishing": [
        (r"otp|one[- ]time password|verification code",16,"Requests or references to an OTP / verification code"),
        (r"password|pin|login|sign in|credential",11,"Requests for sensitive login information"),
        (r"account.{0,25}(blocked|suspended|restricted|locked)",13,"Threatens account restriction or suspension"),
        (r"click.{0,18}(link|here)|verify.{0,18}(account|identity)",12,"Pushes the recipient to click or verify through a link"),
    ],
    "bec": [
        (r"urgent|immediately|asap|right away|today",9,"Creates urgency around a business action"),
        (r"wire|transfer|payment|beneficiary|invoice|bank account",12,"Contains payment or beneficiary instructions"),
        (r"new account|change.{0,15}(account|bank)|updated bank|different account",18,"Requests a change in payment destination"),
        (r"do not call|don't call|confidential|keep this between us",16,"Discourages independent verification"),
    ],
    "sextortion": [
        (r"nude|naked|intimate|private (photo|video|image)|sex tape",16,"References intimate or private material"),
        (r"send.{0,20}(money|bitcoin|crypto|usdt)|pay me|payment",15,"Demands money or value"),
        (r"post|publish|share|send.{0,20}(family|friends|contacts|school|work)",18,"Threatens publication or distribution"),
        (r"unless you|if you don't|or else|blackmail",14,"Uses conditional threats or coercion"),
    ],
    "investment": [
        (r"guaranteed (profit|return)|risk[- ]free|no risk",16,"Promises guaranteed or risk-free returns"),
        (r"double|triple|[2-9]x|[1-9]\d{2,}%",11,"Promises unusually large returns"),
        (r"withdrawal fee|release fee|tax fee|unlock fee",18,"Requests an additional fee before withdrawal"),
    ],
}

LABELS = {
    "phishing":"Possible Phishing / Credential Theft",
    "bec":"Possible Business Email Compromise",
    "sextortion":"Possible Sextortion / Online Blackmail",
    "investment":"Possible Investment / Crypto Scam",
    "general":"General Cybercrime Risk Indicators",
}


def analyse_text(text: str, extras: Dict[str, Any] | None = None):
    extras = extras or {}
    text = text or ""
    scores = {k:0 for k in RULES}
    matches = []
    for cat, rules in RULES.items():
        for pattern, score, reason in rules:
            if re.search(pattern, text, re.I | re.S):
                scores[cat] += score
                matches.append((cat,score,reason))
    if extras.get("reply_mismatch"):
        scores["bec"] += 24
        matches.append(("bec",24,"From and Reply-To domains do not match"))
    if extras.get("minor_involved"):
        scores["sextortion"] += 25
        matches.append(("sextortion",25,"A person under 18 may be involved — urgent safeguarding review is required"))

    ranked=sorted(scores.items(),key=lambda x:x[1],reverse=True)
    top, top_score = ranked[0] if ranked else ("general",0)
    second = ranked[1][1] if len(ranked)>1 else 0
    risk=min(100,round(top_score+min(second*.25,12)))
    level="CRITICAL" if risk>=65 else "HIGH" if risk>=40 else "MEDIUM" if risk>=15 else "LOW"
    indicators=[]
    for cat,score,reason in sorted(matches,key=lambda x:x[1],reverse=True):
        if cat==top or score>=16:
            if reason not in indicators:
                indicators.append(reason)
    if not indicators:
        indicators=["No strong indicators were detected in the text provided. Continue to verify independently."]
    return {
        "category":top,
        "label":LABELS.get(top,LABELS["general"]),
        "score":risk,
        "level":level,
        "indicators":indicators[:6],
    }
