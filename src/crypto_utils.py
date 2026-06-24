# src/crypto_utils.py
import os
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from typing import Tuple

KEYSTORE_DIR = os.environ.get("MILBASTER_KEYSTORE", "keystore")

def ensure_keystore():
    if not os.path.exists(KEYSTORE_DIR):
        os.makedirs(KEYSTORE_DIR, exist_ok=True)

def gen_node_keypair(node_id: str) -> Tuple[bytes, bytes]:
    """
    Generates an EC keypair and saves private key to keystore/node_id_priv.pem
    Returns (private_bytes, public_bytes)
    """
    ensure_keystore()
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(os.path.join(KEYSTORE_DIR, f"{node_id}_priv.pem"), "wb") as f:
        f.write(priv_pem)
    with open(os.path.join(KEYSTORE_DIR, f"{node_id}_pub.pem"), "wb") as f:
        f.write(pub_pem)
    return priv_pem, pub_pem

def load_node_private_key(node_id: str):
    ensure_keystore()
    path = os.path.join(KEYSTORE_DIR, f"{node_id}_priv.pem")
    if not os.path.exists(path):
        # generate ephemeral keys for demos, but in production provision keys properly
        gen_node_keypair(node_id)
    with open(path, "rb") as f:
        data = f.read()
    priv = serialization.load_pem_private_key(data, password=None, backend=default_backend())
    return priv

def load_node_public_bytes(node_id: str) -> bytes:
    path = os.path.join(KEYSTORE_DIR, f"{node_id}_pub.pem")
    if not os.path.exists(path):
        _, pub = gen_node_keypair(node_id)
        return pub
    with open(path, "rb") as f:
        return f.read()

def sign_message(priv_key_obj, message: bytes) -> bytes:
    sig = priv_key_obj.sign(message, ec.ECDSA(hashes.SHA256()))
    return sig

def verify_signature(pub_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    pub = serialization.load_pem_public_key(pub_key_bytes, backend=default_backend())
    try:
        pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def derive_shared_key(node_id: str, peer_pub_bytes: bytes) -> bytes:
    """
    Derive a 32-byte symmetric key using ECDH between this node and peer_pub.
    If peer_pub_bytes is None, return a node-specific static symmetric key derived via HKDF (NOT ideal for prod).
    """
    priv = load_node_private_key(node_id)
    if peer_pub_bytes:
        peer_pub = serialization.load_pem_public_key(peer_pub_bytes, backend=default_backend())
        shared = priv.exchange(ec.ECDH(), peer_pub)
        # HKDF derive
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"milbaster-evidence", backend=default_backend())
        return hkdf.derive(shared)
    else:
        # fallback: derive from node public key bytes
        pub_bytes = load_node_public_bytes(node_id)
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"milbaster-node-static", backend=default_backend())
        return hkdf.derive(hashlib.sha256(pub_bytes).digest())

# convenience wrapper used by evidence_manager: derive_node_symmetric_key
def derive_node_symmetric_key(node_id: str, peer_pubkey_bytes: bytes=None) -> bytes:
    return derive_shared_key(node_id, peer_pubkey_bytes)

def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    returns (ciphertext, nonce, tag)
    We'll use AESGCM which returns ciphertext including tag; to be explicit, we split.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    # AESGCM returns ciphertext||tag (tag is last 16 bytes)
    tag = ct[-16:]
    ciphertext = ct[:-16]
    return ciphertext, nonce, tag

def aes_gcm_decrypt(key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, None)

def sha256_hex(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()
