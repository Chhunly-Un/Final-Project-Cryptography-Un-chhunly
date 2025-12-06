def analyze_password_strength(password: str):
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        score += 1

    if score <= 1:
        feedback = "Very Weak – Use longer password with mixed characters!"
    elif score == 2:
        feedback = "Weak – Add numbers and symbols"
    elif score == 3:
        feedback = "Medium – Good, but can be stronger"
    elif score == 4:
        feedback = "Strong – Well done!"
    else:
        feedback = "Excellent – Very secure!"

    return min(score, 4), feedback