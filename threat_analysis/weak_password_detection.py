# Simple examples — expand for production
COMMON = {
'password', '123456', '12345678', 'qwerty', 'abc123', 'letmein', 'admin'
}




def is_weak_password(pw: str) -> bool:
    if not pw:
        return True
    if pw.lower() in COMMON:
        return True
    if len(pw) < 8:
        return True
# simplistic entropy-ish check
    import math
    uniq = len(set(pw))
    if uniq < 4:
        return True
    return False