import unittest
from pqc_cryptosystem import *

class TestRSACryptosystem(unittest.TestCase):

    # This test module can be run by entering the following command in the root directory of the repo:
    # python -m unittest tests.test_pqc_cryptosystem
    # If you get a module not found error about unittest, you may need to run:
    # pip install unittest

    def setUp(self):
        self.test_key_length = "long" 
        self.test_pqc_alice = PQCCryptosystem(self.test_key_length)
        self.test_pqc_bob = PQCCryptosystem(self.test_key_length)

    def test_encapsulate_decapsulate_same_shared_secret(self):
        # Check that computing a ciphertext & shared secret with a public key, then decapsulating the shared secret using the ciphertext results in same shared key
        ciphertext = self.test_pqc_bob.encapsulate_shared_secret_ciphertext(self.test_pqc_alice.get_public_encapsulation_key())
        self.test_pqc_alice.decapsulate_shared_secret_ciphertext(ciphertext)
        self.assertEqual(self.test_pqc_alice.shared_secret, self.test_pqc_bob.shared_secret)
        self.assertNotEqual(self.test_pqc_alice.shared_secret, None) # shared secret should be initialized

    def test_encapsulate_wrong_key_different_shared_secret(self):
        # Check that computing a ciphertext & shared secret with the wrong public key fails to arrive at the same shared secret
        ciphertext = self.test_pqc_bob.encapsulate_shared_secret_ciphertext(self.test_pqc_bob.get_public_encapsulation_key()) # Bob is using his own key instead of Alice's
        self.test_pqc_alice.decapsulate_shared_secret_ciphertext(ciphertext)
        self.assertNotEqual(self.test_pqc_alice.shared_secret, self.test_pqc_bob.shared_secret) 

    def test_sign_verify_succeeds(self):
        # Check that signing a message, then verifying that signature with the signer's public key is successful
        test_message = b"Sign me!"
        signature = self.test_pqc_alice.sign_message(test_message)
        verification_result = self.test_pqc_bob.verify_signature(signature, test_message, self.test_pqc_alice.get_public_signature_key())
        # Using assertEqual True instead of assertTrue b/c return should be the boolean value True, strings or any other type are NOT accepted
        self.assertEqual(verification_result, True) 

    def test_sign_verify_different_message_fails(self):
        test_message_one = b"Signing off"
        test_message_two = b"Signing on"
        signature = self.test_pqc_alice.sign_message(test_message_one)
        verification_result = self.test_pqc_bob.verify_signature(signature, test_message_two, self.test_pqc_alice.get_public_signature_key())
        # Using assertEqual False instead of assertTrue b/c return should be the boolean value False, strings or any other type are NOT accepted
        self.assertEqual(verification_result, False) 

    def test_verify_signature_different_key_fails(self):
        test_message = b"Signing on"
        signature = self.test_pqc_alice.sign_message(test_message)
        verification_result = self.test_pqc_bob.verify_signature(signature, test_message, self.test_pqc_bob.get_public_signature_key())
        # Using assertEqual False instead of assertTrue b/c return should be the boolean value False, strings or any other type are NOT accepted
        self.assertEqual(verification_result, False)