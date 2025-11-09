'''
    this is the server app that will run on the ec2 instance. 
    packets will be encrypted with the public key recieved from the client and then sent back to the client.
    performance metrics will also be sent back along with the encrypted data
    (maybe this can run on like sockets if we try but i dont really want to)

    you dont need to install the pip dependencies for this on the client but you can if you want
    this runs on an ec2 instacne so install it on that    
 '''


from flask import Flask, request, jsonify   # type: ignore
from pqcrypto.kem.kyber512 import generate_keypair, decapsulate, encapsulate # type: ignore
import psutil
import time

app = Flask(__name__)

public_key, secret_key = generate_keypair()

@app.route("/public_key", methods=["GET"])
def get_public_key():
    return jsonify({"public_key": list(public_key)})

@app.route("/decrypt", methods=["POST"])
def decrypt():
    data = request.get_json()
    ciphertext = bytes(data["ciphertext"])

    # Measure decryption performance
    start_time = time.time()
    cpu_before = psutil.cpu_percent(interval=None)
    mem_before = psutil.virtual_memory().percent

    shared_secret = decapsulate(ciphertext, secret_key)

    cpu_after = psutil.cpu_percent(interval=None)
    mem_after = psutil.virtual_memory().percent
    decrypt_time = time.time() - start_time

    return jsonify({
        "decryption_time": decrypt_time,
        "cpu_before": cpu_before,
        "cpu_after": cpu_after,
        "mem_before": mem_before,
        "mem_after": mem_after
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
