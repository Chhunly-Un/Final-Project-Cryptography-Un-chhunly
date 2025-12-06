from cryptography.hazmat.primitives.asymmetric import rsa




def rsa_is_weak(private_key) -> bool:
# Accepts a loaded private key object
    try:
        size = private_key.key_size
        return size < 2048
    except Exception:
        return True