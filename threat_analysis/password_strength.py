# cryptographys/threat_analysis/password_strength.py
import re
import math
from typing import Tuple, List

def analyze_password_strength(password: str) -> Tuple[int, str, List[str], str]:
    """
    Analyzes password strength using entropy, variety, length, and common pattern checks.
    Returns: (score 0-100, label, feedback_list, color_hex)
    """
    if not password:
        return 0, "EMPTY", ["No password entered!"], "#ff0000"

    feedback: List[str] = []
    score = 0
    length = len(password)

    # === 1. Length (most important factor) ===
    if length >= 20:
        score += 30
        feedback.append("Excellent length (20+ characters)")
    elif length >= 16:
        score += 25
        feedback.append("Great length (16+ characters)")
    elif length >= 12:
        score += 18
        feedback.append("Good length (12+ characters)")
    elif length >= 8:
        score += 10
    else:
        score += 2
        feedback.append("⚠ Too short — use at least 12 characters for real security")

    # === 2. Character variety ===
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?~`]", password))

    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety * 12

    if variety == 4:
        feedback.append("Perfect mix of character types")
    elif variety == 3:
        feedback.append("Good variety — consider adding symbols")
    elif variety < 3:
        feedback.append("⚠ Add uppercase, numbers, and symbols for stronger protection")

    # === 3. Entropy calculation ===
    charset_size = 0
    if has_lower: charset_size += 26
    if has_upper: charset_size += 26
    if has_digit: charset_size += 10
    if has_symbol: charset_size += 32  # Common symbols

    if charset_size > 0:
        entropy_bits = length * math.log2(charset_size)
        score += min(entropy_bits / 3.5, 30)  # Capped bonus
    else:
        entropy_bits = 0

    # === 4. Common weak patterns (big penalties) ===
    lowered = password.lower()

    # Very common passwords
    if lowered in {"password", "123456", "12345678", "qwerty", "abc123", "admin", "letmein"}:
        score = max(0, score - 80)
        feedback.append("🚨 This is one of the MOST COMMON passwords — NEVER use it!")

    # Sequences and repeats
    if re.search(r"(.)\1{3,}", password):  # 4+ repeated chars
        score -= 30
        feedback.append("⚠ Avoid repeated characters (like aaaa)")

    if re.search(r"(1234|abcd|qwer|asdf|zxcv)", lowered):
        score -= 25
        feedback.append("⚠ No keyboard patterns (qwerty, 12345, etc.)")

    common_words = ["pass", "love", "princess", "dragon", "monkey", "football", "sunshine"]
    if any(word in lowered for word in common_words):
        score -= 20
        feedback.append("⚠ Avoid common words")

    # === 5. Final score & label ===
    score = max(0, min(100, int(score)))

    if score >= 90:
        label = "EXCELLENT"
        color = "#00ff88"
    elif score >= 80:
        label = "VERY STRONG"
        color = "#00ffcc"
    elif score >= 65:
        label = "STRONG"
        color = "#00ffff"
    elif score >= 50:
        label = "MODERATE"
        color = "#ffff00"
    elif score >= 30:
        label = "WEAK"
        color = "#ff9100"
    else:
        label = "VERY WEAK"
        color = "#ff4444"

    # Final positive message if strong
    if score >= 80 and "Perfect" not in " ".join(feedback) and "Excellent" not in " ".join(feedback):
        feedback.insert(0, "🔒 This is a highly secure password!")

    return score, label, feedback, color