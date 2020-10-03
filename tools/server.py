import json
import base64

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Random import get_random_bytes

from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route('/encrypt')
def encrypt():
    data = b"----------------secret12secretA"
    key = bytes([0x01] * 16)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    decoded_bytes = cipher.iv + ct_bytes
    post = base64.b64encode(decoded_bytes)
    post = post.decode('utf-8')
    post = post.replace('=', '~').replace('/', '!').replace('+', '-')
    return post, 200


@app.route('/decrypt', methods=['POST', 'GET'])
def decrypt():
    post = request.args.get('post')
    post = post.replace('~', '=').replace('!', '/').replace('-', '+')
    decoded_bytes = base64.b64decode(post)
    key = bytes([0x01] * 16)
    iv = decoded_bytes[:16]
    ct = decoded_bytes[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = ""
    decrypted_cipher = cipher.decrypt(ct)
    try:
        pt = unpad(decrypted_cipher, 16)
    except:
        return jsonify(f"PaddingException"), 200

    return jsonify(f"The message was: {pt}"), 200
