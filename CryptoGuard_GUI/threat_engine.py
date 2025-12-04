# threat_engine.py
def analyze_rsa_size(bits):
    if bits < 2048:
        return ["Warning: RSA key size < 2048 bits — consider 2048+ or 3072/4096 for longer-term security."]
    return ["RSA key size is acceptable (>= 2048)."]

def analyze_aes_length(bytes_len):
    if bytes_len < 32:
        return ["Warning: AES key length less than 256-bit recommended (32 bytes)."]
    return ["AES key length is acceptable (256-bit)."]

def analyze_password(password):
    findings = []
    score = 0
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        findings.append("Password too short (recommend 12+ chars).")

    if any(c.isupper() for c in password) and any(c.islower() for c in password):
        score += 1
    else:
        findings.append("Use both uppercase and lowercase letters.")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        findings.append("Include numbers to increase complexity.")

    special = set("!@#$%^&*()-_=+[]{}\\|;:'\",.<>/?")
    if any(c in special for c in password):
        score += 1
    else:
        findings.append("Include special symbols to increase entropy.")

    entropy_hint = "Low"
    if score >= 5:
        entropy_hint = "High"
    elif score >= 3:
        entropy_hint = "Medium"

    return {"score": score, "entropy": entropy_hint, "findings": findings}

def overall_risk_score(checks):
    """
    Combine simple checks into 0-100 risk score (lower is better).
    `checks` is a list of booleans or severity strings; for simplicity,
    expect a dict with keys: rsa_ok (bool), aes_ok (bool), pw_entropy ('Low'|'Medium'|'High')
    """
    score = 0
    if not checks.get("rsa_ok", True):
        score += 30
    if not checks.get("aes_ok", True):
        score += 30
    entropy = checks.get("pw_entropy", "High")
    if entropy == "Low":
        score += 30
    elif entropy == "Medium":
        score += 10
    # clamp
    return min(100, score)
