# cryptographys/threat_analysis/password_strength.py
import re
import math
from typing import Tuple, List

def analyze_password_strength(password: str) -> Tuple[int, str, List[str]]:
    """
    Returns: (score 0-100, strength_label, detailed_feedback_list)
    Real-world strength based on entropy + common patterns
    """
    if not password:
        return 0, "Empty", ["Password cannot be empty!"]

    length = len(password)
    feedback = []
    score = 0

    # 1. Length bonus (most important factor)
    if length >= 20:
        score += 30
    elif length >= 16:
        score += 25
    elif length >= 12:
        score += 18
    elif length >= 8:
        score += 10
    else:
        feedback.append("Too short! Use at least 12 characters")

    # 2. Character variety
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?~`]", password))

    variety_count = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety_count * 12

    if variety_count < 3:
        feedback.append("Add uppercase, numbers, and symbols")

    # 3. Entropy estimation (bits)
    charset_size = 0
    if has_lower: charset_size += 26
    if has_upper: charset_size += 26
    if has_digit: charset_size += 10
    if has_symbol: charset_size += 32

    if charset_size > 0:
        entropy = length * math.log2(charset_size)
        score += min(entropy / 3, 30)  # Cap entropy bonus
    else:
        entropy = 0

    # 4. DANGEROUS PATTERNS (BIG PENALTIES)
    common_patterns = [
        "123", "abc", "qwerty", "password", "admin", "login", "welcome",
        "letmein", "monkey", "dragon", "sunshine", "princess", "football"
    ]
    lowered = password.lower()
    if any(pat in lowered for pat in common_patterns):
        score -= 40
        feedback.append("Avoid common words or sequences!")

    if re.search(r"(.)\1\1\1", password):  # 4 same chars in a row
        score -= 25
        feedback.append("No repeated characters (aaaa)")

    if re.search(r"(123|abc|qwe|asd|zxc)", lowered):
        score -= 20
        feedback.append("No keyboard patterns (qwerty, 12345)")

    if password.lower() in ["password", "123456", "12345678", "qwerty", "abc123"]:
        score = 0
        feedback.append("This is one of the most common passwords ever!")

    # 5. Final score clamp
    score = max(0, min(100, score))

    # 6. Strength label + color suggestion
    if score >= 90:
        label = "EXCELLENT (Military Grade)"
        color = "#00ff00"
    elif score >= 75:
        label = "VERY STRONG"
        color = "#00ff99"
    elif score >= 60:
        label = "STRONG"
        color = "#00ffff"
    elif score >= 40:
        label = "MEDIUM"
        color = "#ffff00"
    elif score >= 20:
        label = "WEAK"
        color = "#ff9100"
    else:
        label = "VERY WEAK"
        color = "#ff0000"

    # Final feedback
    if not feedback:
        feedback = ["Perfect! This password is extremely secure"]

    return score, label, feedback, color