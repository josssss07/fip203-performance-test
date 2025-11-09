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
ITERATION = 100 #api will be called 100 times when program is run to store data into our csv file. can be changed accordingly 
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