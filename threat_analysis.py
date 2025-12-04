import math

def estimate_password_entropy(password: str) -> float:
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 32
    if pool == 0:
        return 0.0
    return math.log2(pool) * len(password)

def password_strength_feedback(password: str):
    entropy = estimate_password_entropy(password)
    issues = []
    if len(password) < 8:
        issues.append('Too short (<8)')
    if len(password) < 12:
        issues.append('Consider 12+ chars')
    if not any(c.islower() for c in password) or not any(c.isupper() for c in password):
        issues.append('Use mixed case')
    if not any(c.isdigit() for c in password):
        issues.append('Add numbers')
    if not any(not c.isalnum() for c in password):
        issues.append('Add special chars')
    return {'entropy': entropy, 'issues': issues}

def hash_collision_warning(algorithm_name: str) -> str:
    alg = algorithm_name.lower()
    if alg in ('md5', 'sha1'):
        return f'Warning: {algorithm_name} vulnerable to collisions. Use SHA-256/512.'
    return f'{algorithm_name} considered safe for integrity.'