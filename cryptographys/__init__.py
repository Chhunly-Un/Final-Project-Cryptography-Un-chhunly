# cryptography/__init__.py
from .encrypt_text import encrypt_text
from .decrypt_text import decrypt_text
from .encrypt_file import encrypt_file
from .decrypt_file import decrypt_file
#from .encrypt_file import generate_keys_if_not_exist  # auto-generate keys

__all__ = ["encrypt_text", "decrypt_text", "encrypt_file", "decrypt_file"]