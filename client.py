'''
    client side code
'''

#imports: 
import base64, os, time, csv, psutil
import requests, statistics
from  cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import oqs 
from cryptography.fernet import Fernet
import warnings


#ignore self signed HTTPS warnings: 
warnings.filterwarnings("ignore")

#configs 
SERVER = "https://aws_goes_here_later:5000" #fips203 will run on port 5000 and rsa will run on port 5001 (read info.txt)
ITERATION = 10 #api will be called 100 times when program is run to store data into our csv file. can be changed accordingly 
CSV_FILE = 'benchnmark_results.csv' 

#helper b64 encode and decode functions: 
def b64_d(x):
    return base64.b64decode(x) #decodes base64 

def b64_e(x):
    return base64.b64encode(x).decode("ascii") #info.txt for explaination 

#select mlkem/kyber - fips203 algorithm: 
ALG = next((algo for algo in oqs.get_enabled_kem_mechanisms() if "KYBER" in algo.upper() or "ML-KEM" in algo.upper()), None)
if not ALG:
    raise SystemExit("No ML-KEM/Kyber implementation found in liboqs")

#make a local keystore for the keys 
KEYSTORE_FILE = "client_keystore.bin"
KEYSTORE_KEY = "keystore_key.bin"

if not os.path.exists(KEYSTORE_FILE):
    print("generating new private key.....")
    with oqs.KeyEncapsulation(ALG) as kem: 
        kem_public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()

    local_key = Fernet.generate_key()
    with open(KEYSTORE_FILE, "wb") as f: 
        f.write(local_key)
    #encrypt our local key with our private key on a fernet instance
    enc = Fernet(local_key).encrypt(private_key)

    with open(KEYSTORE_KEY, 'wb') as f: 
        f.write(enc)

else:
    local_key = open(KEYSTORE_KEY, 'rb').read()
    enc = open(KEYSTORE_FILE, 'rb').read()
    private_key = Fernet(local_key).decrypt(enc)

print(f"ML-KEM: {ALG} loaded")


#csv for data storage to check information: 
with open(CSV_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Iteration", "EncapTime_s", "DecapTime_s", "CPU%", "MemBytes"])


# benchmarking: 
print("Begining benchmark: ")

for i in range(ITERATION):
    try: 
        proc = psutil.Process()

        # fetch server public key
        srv_pub = requests.get(f"{SERVER}/public_key", verify=False).json()
        server_pk = b64_d(srv_pub["public_key_b64"])
        # generate client keypair
        with oqs.KeyEncapsulation(ALG) as kem_client:
            client_pk = kem_client.generate_keypair()

        # record start time for encapsulation
        t_enc_start = time.perf_counter()

        with oqs.KeyEncapsulation(ALG) as kem_enc:
            kem_ciphertext, shared_secret = kem_enc.encap_secret(server_pk)

        #end time for encapsualtion
        t_enc_end = time.perf_counter()


        #this part makes no sense to me i ripped this off github and then a gpt hallucination
        #create the simulated message for symmetric encryption: 
        hkdf = HKDF(algorithm=hashes.SHA256(), length=44, salt=None, info=b"fips203-packet-v1")
        okm = hkdf.derive(shared_secret)
        key, nonce = okm[:32], okm[32:44]
        aead = ChaCha20Poly1305(key)
        aad = b"hdr:demo"
        ct = aead.encrypt(nonce, b"Benchmarking packet", aad)

        #decryption timer 
        t_decrypt_start = time.perf_counter()

        with oqs.KeyEncapsulation(ALG) as kem_decap: 
            shared_secret_client = kem_decap.decap_secret(kem_ciphertext, private_key)

        t_decrypt_end = time.perf_counter()
        


    except Exception as e: 
        print(f"u messed up, heres your mess up: \n{e}")
        continue