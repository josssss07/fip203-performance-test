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



