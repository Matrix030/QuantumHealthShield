import oqs
import json
import base64
from datetime import datetime
from os import urandom
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec

# Example EHR record
ehr_record = {
    "patient_id": "12345",
    "name": "John Doe",
    "age": 34,
    "diagnosis": "Hypertension",
    "treatment": "Lifestyle changes and medication"
}

# Logging utility
def log_activity(activity, user_id):
    """Logs user activity for auditing."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"\n[LOG] {timestamp} - User: {user_id} - Activity: {activity}")

# Output formatter
def display_output(title, data):
    """Formats and displays output with a title."""
    print(f"\n{'='*40}\n{title}\n{'='*40}")
    if isinstance(data, dict):
        for key, value in data.items():
            print(f"{key}: {value}")
    elif isinstance(data, list):
        for item in data:
            print(f"- {item}")
    else:
        print(data)
    print(f"{'='*40}\n")

# AES Encryption
def aes_encrypt(data, aes_key):
    """Encrypt data using AES-GCM."""
    iv = urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return {
        "iv": base64.b64encode(iv).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "tag": base64.b64encode(encryptor.tag).decode('utf-8')
    }

def aes_decrypt(encrypted_payload, aes_key):
    """Decrypt data using AES-GCM."""
    iv = base64.b64decode(encrypted_payload["iv"])
    ciphertext = base64.b64decode(encrypted_payload["ciphertext"])
    tag = base64.b64decode(encrypted_payload["tag"])
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Hybrid Encryption using ECDH for ECC
def hybrid_encrypt(data, kyber_instance, kyber_public_key, ecc_private_key, ecc_peer_public_key):
    """Encrypt data using AES, Kyber, and ECC with ECDH."""
    aes_key = urandom(32)  # Generate random AES key
    aes_encrypted = aes_encrypt(json.dumps(data).encode('utf-8'), aes_key)

    # Encrypt AES key using Kyber
    kyber_ciphertext, kyber_shared_secret = kyber_instance.encap_secret(kyber_public_key)

    # Perform ECDH to derive a shared secret
    shared_secret = ecc_private_key.exchange(ec.ECDH(), ecc_peer_public_key)

    # Derive a symmetric key from the ECDH shared secret
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecdh key derivation"
    ).derive(shared_secret)

    # Encrypt the AES key with the derived key
    aes_key_encrypted = aes_encrypt(aes_key, derived_key)

    return {
        "aes_encrypted": aes_encrypted,
        "kyber_ciphertext": base64.b64encode(kyber_ciphertext).decode('utf-8'),
        "aes_key_encrypted": aes_key_encrypted
    }

def hybrid_decrypt(encrypted_payload, kyber_instance, kyber_private_key, ecc_private_key, ecc_peer_public_key):
    """Decrypt data using AES, Kyber, and ECC with ECDH."""
    kyber_ciphertext = base64.b64decode(encrypted_payload["kyber_ciphertext"])
    aes_key_encrypted = encrypted_payload["aes_key_encrypted"]

    # Decrypt AES key using Kyber
    kyber_shared_secret = kyber_instance.decap_secret(kyber_ciphertext)

    # Perform ECDH to derive a shared secret
    shared_secret = ecc_private_key.exchange(ec.ECDH(), ecc_peer_public_key)

    # Derive a symmetric key from the ECDH shared secret
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecdh key derivation"
    ).derive(shared_secret)

    # Decrypt AES key with the derived key
    aes_key = aes_decrypt(aes_key_encrypted, derived_key)

    # Decrypt the data with the AES key
    aes_encrypted = encrypted_payload["aes_encrypted"]
    decrypted_data = aes_decrypt(aes_encrypted, aes_key)
    return json.loads(decrypted_data.decode('utf-8'))

# Hybrid Signing and Verification
def hybrid_sign(data, dilithium_instance, ecc_signing_private_key):
    """Signs data using Dilithium and ECC."""
    serialized_data = json.dumps(data).encode('utf-8')
    dilithium_signature = dilithium_instance.sign(serialized_data)
    ecc_signature = ecc_signing_private_key.sign(serialized_data, ec.ECDSA(hashes.SHA256()))
    return {
        "data": base64.b64encode(serialized_data).decode('utf-8'),
        "dilithium_signature": base64.b64encode(dilithium_signature).decode('utf-8'),
        "ecc_signature": base64.b64encode(ecc_signature).decode('utf-8')
    }

def hybrid_verify(signed_data, dilithium_instance, dilithium_public_key, ecc_signing_public_key):
    """Verifies signatures using Dilithium and ECC."""
    serialized_data = base64.b64decode(signed_data["data"])
    dilithium_signature = base64.b64decode(signed_data["dilithium_signature"])
    ecc_signature = base64.b64decode(signed_data["ecc_signature"])

    if not dilithium_instance.verify(serialized_data, dilithium_signature, dilithium_public_key):
        raise ValueError("Dilithium signature verification failed.")

    ecc_signing_public_key.verify(ecc_signature, serialized_data, ec.ECDSA(hashes.SHA256()))
    return json.loads(serialized_data.decode('utf-8'))

def main():

    kyber_algo = "Kyber1024"
    dilithium_algo = "Dilithium2"
    user_id = "user123"

    # ECC key pairs
    ecc_key_exchange_private_key = ec.generate_private_key(ec.SECP256R1())
    ecc_key_exchange_public_key = ecc_key_exchange_private_key.public_key()

    ecc_signing_private_key = ec.generate_private_key(ec.SECP256R1())
    ecc_signing_public_key = ecc_signing_private_key.public_key()

    with oqs.KeyEncapsulation(kyber_algo) as kyber:
        kyber_public_key = kyber.generate_keypair()

        with oqs.Signature(dilithium_algo) as dilithium:
            dilithium_public_key = dilithium.generate_keypair()

            # Encrypt the EHR
            log_activity("Encrypting EHR", user_id)
            encrypted_ehr = hybrid_encrypt(
                ehr_record, kyber, kyber_public_key, ecc_key_exchange_private_key, ecc_key_exchange_public_key
            )
            display_output("Encrypted EHR", encrypted_ehr)

            # Sign the encrypted EHR
            log_activity("Signing EHR", user_id)
            signed_ehr = hybrid_sign(encrypted_ehr, dilithium, ecc_signing_private_key)
            display_output("Signed EHR", signed_ehr)

            # Verify and Decrypt the EHR
            log_activity("Verifying and Decrypting EHR", user_id)
            verified_ehr = hybrid_verify(signed_ehr, dilithium, dilithium_public_key, ecc_signing_public_key)
            decrypted_ehr = hybrid_decrypt(
                verified_ehr, kyber, kyber_public_key, ecc_key_exchange_private_key, ecc_key_exchange_public_key
            )
            display_output("Decrypted EHR", decrypted_ehr)

if __name__ == "__main__":
    main()
