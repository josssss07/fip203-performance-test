import unittest
from rsa_cryptosystem import *

class TestRSACryptosystem(unittest.TestCase):

    # This test module can be run by entering the following command in the root directory of the repo:
    # python -m unittest tests.test_rsa_cryptosystem
    # If you get a module not found error about unittest, you may need to run:
    # pip install unittest

    def setUp(self):
        self.test_key_length = 2048
        self.test_rsa = RSACryptosystem(self.test_key_length)

    def test_encrypt_decrypt_same_plaintext(self):
        # Test to check that when a plaintext is encrypted, its ciphertext decrypts to the original text of the message
        test_message = b"Don't read me!"
        ciphertext = self.test_rsa.encrypt_message(test_message, self.test_rsa.get_public_key())
        plaintext = self.test_rsa.decrypt_ciphertext(ciphertext)
        self.assertEqual(test_message, plaintext)

    def test_encrypt_different_plaintext_doesnt_match(self): 
        # Test to check that encrypting two different plaintexts gives two different ciphertexts (odds of them encrypting to same C is very very very small)
        test_message_one = b"Test 1!"
        test_message_two = b"Test 2!"
        ciphertext_one = self.test_rsa.encrypt_message(test_message_one, self.test_rsa.get_public_key())
        ciphertext_two = self.test_rsa.encrypt_message(test_message_two, self.test_rsa.get_public_key())
        self.assertNotEqual(ciphertext_one, ciphertext_two)

    def test_encrypt_different_public_key_doesnt_match(self):
        # Test to check that encrypting and decrypting with non-paired public and private keys fails to recover the plaintext
        test_message = b"Try to decrypt me"
        ciphertext = self.test_rsa.encrypt_message(test_message, self.test_rsa.get_public_key())
        different_rsa_object = RSACryptosystem(self.test_key_length)
        self.assertRaises(ValueError, different_rsa_object.decrypt_ciphertext, ciphertext) # Attempting to decrypt with the wrong key raises a ValueError

    def test_sign_verify_succeeds(self):
        # Test to check that signing a message with a public key & verifying w/ corresponding private key works
        test_signed_message = b"Signing off"
        signature = self.test_rsa.sign_message(test_signed_message)
        verification_result = self.test_rsa.verify_signature(signature, test_signed_message, self.test_rsa.get_public_key())
        self.assertTrue(verification_result)

    def test_sign_verify_different_message_fails(self):
        # Test to check that trying to verify a signature with a message different from the signed message fails
        test_signed_message = b"Signing off"
        test_different_message = b"Signing on"
        signature = self.test_rsa.sign_message(test_signed_message)
        verification_result = self.test_rsa.verify_signature(signature, test_different_message, self.test_rsa.get_public_key())
        self.assertFalse(verification_result)

    def test_verify_signature_different_key_fails(self):
        # Test to check that trying to verify a signature with a public key not associated with the signer's private key fails
        test_signed_message = b"Signing off"
        signature = self.test_rsa.sign_message(test_signed_message)
        different_rsa_object = RSACryptosystem(self.test_key_length)
        verification_result = self.test_rsa.verify_signature(signature, test_signed_message, different_rsa_object.get_public_key())
        self.assertFalse(verification_result)