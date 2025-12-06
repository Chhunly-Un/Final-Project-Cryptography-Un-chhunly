# threat_analysis/hash_collision_risk.py
import hashlib

def check_hash_collision_risk(input1, input2):
    hash1 = hashlib.sha256(input1.encode()).hexdigest()
    hash2 = hashlib.sha256(input2.encode()).hexdigest()
    if hash1 == hash2:
        return "Collision detected! High risk (though unlikely for SHA-256)."
    return f"No collision. Hashes:\n{hash1}\n{hash2}\nNote: SHA-256 has very low collision risk in practice."