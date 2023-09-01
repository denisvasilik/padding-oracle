import base64

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad

from flask import Flask, jsonify, request

app = Flask(__name__)

class Base64OracleWebClientMock(object):

	def request(self, block_provider):
		base64_data = base64.b64encode(block_provider.data)
		base64_data = base64_data.decode('utf-8')
		base64_data = base64_data.replace('=', '~').replace('/', '!').replace('+', '-')
		with app.test_client() as client:
			response = client.get(f"/decrypt?post={base64_data}")
			return self.validate(response)

	def validate(self, response):
		return 'PaddingException' not in response.data.decode('utf8')


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

	return jsonify(f"{pt}"), 200


class SimpleOracleMock(object):

	def __init__(self):
		pass

	def request(self, block_provider):
		response = self._decrypt(block_provider.data)
		return self.validate(response)

	def validate(self, response):
		return b'PaddingException\n' != response

	def _decrypt(self, ciphertext):
		key = bytes.fromhex("65da86eebe1e182e315616eafe4403c4")
		iv = bytes.fromhex("bb243543f0af82df0baa5284b310a48a")
		cipher = AES.new(key, AES.MODE_CBC, iv)
		plaintext = ""
		decrypted_cipher = cipher.decrypt(ciphertext)
		try:
			plaintext = unpad(decrypted_cipher, 16, style='pkcs7')
		except:
			return b'PaddingException\n'
		return f"{plaintext}"

	def encrypt(self):
		key = bytes.fromhex("65da86eebe1e182e315616eafe4403c4")
		iv = bytes.fromhex("bb243543f0af82df0baa5284b310a48a")
		cipher = AES.new(key, AES.MODE_CBC, iv)
		ciphertext = cipher.iv + bytes.fromhex('9e100fb6810a28f04f45344a7b22740d9b9ac73690c6c0809828bfaecce8082e3ec00b33cbc74f84c4da90a57ecd8d75')
		return ciphertext
