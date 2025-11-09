#run this to install oqs 
import oqs

enabled_kems = oqs.get_enabled_kem_mechanisms()
print("Enabled KEM mechanisms:", enabled_kems)
if "ML-KEM-768" in enabled_kems:
    with oqs.KeyEncapsulation("ML-KEM-768") as client_kem:
        public_key = client_kem.generate_keypair()
        print("ML-KEM-768 public key generated.")