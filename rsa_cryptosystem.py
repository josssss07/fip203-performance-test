from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

class RSACryptosystem: # keeping it simple for now w/ only RSA, maybe add diffie-hellman to emulate TLS 1.3 if time permits
    # Much of this module is based on the documentation at the following link: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/

    PUBLIC_EXPONENT = 65537 # this always be the public exponent, but modulus N will vary
    def __init__(self, key_length: int):
        self.key_length = key_length
        self.private_key = rsa.generate_private_key(self.PUBLIC_EXPONENT, key_length)
        # initialize RSA private key object

    def encrypt_message(self, message: bytes, public_key: RSAPublicKey) -> bytes: 
        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    
    def decrypt_ciphertext(self, ciphertext: bytes) -> bytes:
        private_key = self.private_key
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def sign_message(self, message: bytes) -> bytes:
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, signature: bytes, message: bytes, signatory_public_key: RSAPublicKey) -> bool:
        try:
            signatory_public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True # If we get here then no exception was raised from the signature not being verified
        except InvalidSignature:
            return False

    def get_public_key(self):
        return self.private_key.public_key()

# Implement this
# Test this 
# Set up benchmarking code
# work on FIPS-204 (for a proper cryptosystem)
    # Review Josh's code for understanding of how I might need to do this
