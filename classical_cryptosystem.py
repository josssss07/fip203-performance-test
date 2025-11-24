

class ClassicalCryptosystem: # Class to mimic a classical cryptosystem in TLS 1.3 using ephemeral DH & RSA
    # This will not handle encrypting messages once the DH key exchange is complete since PQC systems will also use AES 

    def __init__(self, rsa_key_length, diffie_hellman_key_length):
        self.rsa_key_length = rsa_key_length
        self.diffie_hellman_key_length = diffie_hellman_key_length
        # Not sure if we need to set our generator here, if a library uses a constant one, or what have you

    def compute_diffie_hellman_private_key(self, peer_public_key):
        # Use the received peer public key (g^b)modp to compute the shared key (g^(ab))modp
        pass

    def get_generator_prime_pair(self):
        # Return the generator g and prime p that are used
        pass

    def get_public_encapsulation_key(self):
        # Return the value (g^a)modp that is sent publicly
        pass

    def sign_message(self, message):
        pass

    def verify_signature(self, signature, message, signatory_public_key):
        pass

    def get_public_signature_key(self):
        pass
