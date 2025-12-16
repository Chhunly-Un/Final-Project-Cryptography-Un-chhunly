# threat_analysis/password_strength.py
import re
import math
from typing import Tuple, List

def analyze_password_strength(password: str) -> Tuple[int, str, List[str], str]:
    """
    Returns: (score 0-100, label, feedback_list, color_hex)
    Full detailed report with emojis and accurate scoring.
    """
    if not password:
        return 0, "EMPTY", ["⚠ No password entered!"], "#ff0000"

    feedback: List[str] = []
    score = 0
    length = len(password)

    # Length (biggest factor)
    if length >= 20:
        score += 30
        feedback.append("🔥 Excellent length (20+ characters)")
    elif length >= 16:
        score += 25
        feedback.append("✅ Great length (16+ characters)")
    elif length >= 12:
        score += 18
        feedback.append("✅ Good length (12+ characters)")
    elif length >= 8:
        score += 10
        feedback.append("⚠ Acceptable length")
    else:
        score += 2
        feedback.append("🚨 Too short — use at least 12 characters!")

    # Character variety
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?~`]", password))

    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety * 12

    if variety == 4:
        feedback.append("🔥 Perfect mix: lowercase, uppercase, numbers, symbols")
    elif variety == 3:
        feedback.append("✅ Good variety — add symbols for extra strength")
    elif variety == 2:
        feedback.append("⚠ Limited variety — add more character types")
    else:
        feedback.append("🚨 Very weak variety — use multiple character types!")

    # Entropy bonus
    charset = (26 if has_lower else 0) + (26 if has_upper else 0) + (10 if has_digit else 0) + (32 if has_symbol else 0)
    if charset > 0:
        entropy = length * math.log2(charset)
        score += min(entropy / 3.5, 30)

    # Penalties for dangerous patterns
    lowered = password.lower()
    if lowered in ["password", "123456", "12345678", "qwerty", "abc123", "admin", "letmein", "welcome"]:
        score = max(0, score - 70)
        feedback.append("🚨 EXTREMELY COMMON PASSWORD — CHANGE IMMEDIATELY!")

    if re.search(r"(.)\1{3,}", password):  # 4+ repeated chars
        score -= 25
        feedback.append("⚠ Avoid repeated characters (aaaa)")

    if re.search(r"(12345|qwerty|asdfg|zxcvb)", lowered):
        score -= 20
        feedback.append("⚠ No keyboard patterns (12345, qwerty, etc.)")

    # Final score
    score = max(0, min(100, int(score)))

    # Label & Color
    if score >= 90:
        label, color = "EXCELLENT", "#00ff88"
    elif score >= 80:
        label, color = "VERY STRONG", "#00ffcc"
    elif score >= 65:
        label, color = "STRONG", "#00ffff"
    elif score >= 50:
        label, color = "MODERATE", "#ffff00"
    elif score >= 30:
        label, color = "WEAK", "#ff9100"
    else:
        label, color = "VERY WEAK", "#ff4444"

    # Add positive message for strong passwords
    if score >= 80 and not any("secure" in f.lower() for f in feedback):
        feedback.insert(0, "🔒 This is a highly secure password!")

    return score, label, feedback, color