import pytest
import requests
import base64
import json
import logging

from base64 import b64decode, b64encode

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Random import get_random_bytes

from flask import Flask
from flask import jsonify
from flask import request

app = Flask(__name__)

from padding_oracle import (
    AESBlockProvider,
    AESPaddingOracle,
    AESIntermediateKeyGenerator,
    AESIntermediateKeyParallelGenerator,
)


def test_block_provider_instantiation():
    block_provider = AESBlockProvider(
        bytes([0x1] * 16 + [0x2] * 16 + [0x3] * 16)
    )
    assert block_provider.iv.value == bytes([0x1] * 16)
    assert block_provider.blocks[0].value == bytes([0x1] * 16)
    assert block_provider.blocks[1].value == bytes([0x2] * 16)
    assert block_provider.blocks[2].value == bytes([0x3] * 16)


def test_block_provider_data_assignment():
    block_provider = AESBlockProvider()
    block_provider.data = bytes([0x1] * 16 + [0x2] * 16 + [0x3] * 16)
    assert block_provider.iv.value == bytes([0x1] * 16)
    assert block_provider.blocks[0].value == bytes([0x1] * 16)
    assert block_provider.blocks[1].value == bytes([0x2] * 16)
    assert block_provider.blocks[2].value == bytes([0x3] * 16)


def test_padding_oracle_decryption():
    post = "2llglo8SFBp49-intDmSfnxEz4wEle0iyPiK87rM8SAGN09XluponcUSj9B1sYny"
    post = post.replace('~', '=').replace('!', '/').replace('-', '+')
    encrypted_data = base64.b64decode(post)
    oracle_client = Base64OracleClientMock()
    padding_oracle = AESPaddingOracle(oracle_client)
    decrypted_data = padding_oracle.decrypt(encrypted_data)
    assert decrypted_data == b'----------------secret12secretA'


def test_padding_oracle_decryption_h1ctf():
    post = 'B7TRtKO5ub9drSnAEnRSLweuSMA!k5dWN87R7kLQL1!WJur4kTuzjPQecfPRw4DqxEFh6B57RpTz0HwYsb!iWi0jSpXvilsw2WZa6Akh0FT31JuJqoCgd-9VxYznYA1lFevImB-vHeFZ2jU5r4psuCUKyotOXn5OUBBr5IuSsUp6vQ1yupJwqis6fNl9ikU7u4bFMIYUr1eXgNP8fe-TDQ~~'
    post = post.replace('~', '=').replace('!', '/').replace('-', '+')
    encrypted_data = base64.b64decode(post)
    oracle_client = Base64OracleClientMock()
    padding_oracle = AESPaddingOracle(oracle_client)
    decrypted_data = padding_oracle.decrypt(encrypted_data)
    pampel = decrypted_data.decode('utf8')
    assert decrypted_data == b'{"flag": "^FLAG^0000000000000000000000000000000000000000000000000000000000000000$FLAG$", "id": "2", "key": "hs0kXlu1MZy1c-VN4QKjLQ~~"}'


def test_padding_oracle_encryption():
    post = "2llglo8SFBp49-intDmSfnxEz4wEle0iyPiK87rM8SAGN09XluponcUSj9B1sYny"
    post = post.replace('~', '=').replace('!', '/').replace('-', '+')
    encrypted_data = base64.b64decode(post)
    plaintext_data = b'----------------secret12secretB'
    plaintext_data = pad(plaintext_data, 16)
    oracle_client = Base64OracleClientMock()
    padding_oracle = AESPaddingOracle(oracle_client)
    encrypted_data = padding_oracle.encrypt(plaintext_data, encrypted_data)
    encrypted_data = base64.b64encode(encrypted_data).decode('utf8')
    encrypted_data = encrypted_data.replace('=', '~').replace('/', '!').replace('+', '-')
    assert encrypted_data == 'N11mHHull!22Um0mqD!7cXxEz4wEle0iyPiK87rM8iAGN09XluponcUSj9B1sYny'


def test_key_block_generation_sequentiell():
    expected_key_block_1 = [15, 33, 172, 254, 97, 225, 220, 16, 187, 157, 233, 129, 223, 184, 176, 33]
    expected_key_block_0 = [247, 116, 77, 187, 162, 63, 57, 55, 85, 218, 197, 138, 153, 20, 191, 83]
    post = "2llglo8SFBp49-intDmSfnxEz4wEle0iyPiK87rM8SAGN09XluponcUSj9B1sYny"
    post = post.replace('~', '=').replace('!', '/').replace('-', '+')
    encrypted_data = base64.b64decode(post)
    oracle_client = Base64OracleClientMock()
    key_generator = AESIntermediateKeyGenerator(encrypted_data, oracle_client)
    key_block_1 = key_generator.generate_key_block(1)
    key_block_0 = key_generator.generate_key_block(0)
    assert key_block_0 == expected_key_block_0
    assert key_block_1 == expected_key_block_1


def test_key_block_generation_parallel():
    expected_key_block_1 = [15, 33, 172, 254, 97, 225, 220, 16, 187, 157, 233, 129, 223, 184, 176, 33]
    expected_key_block_0 = [247, 116, 77, 187, 162, 63, 57, 55, 85, 218, 197, 138, 153, 20, 191, 83]
    post = "2llglo8SFBp49-intDmSfnxEz4wEle0iyPiK87rM8SAGN09XluponcUSj9B1sYny"
    post = post.replace('~', '=').replace('!', '/').replace('-', '+')
    encrypted_data = base64.b64decode(post)
    oracle_client = Base64OracleClientMock()
    key_generator = AESIntermediateKeyParallelGenerator(encrypted_data, oracle_client)
    key_block_1 = key_generator.generate_key_block(1)
    key_block_0 = key_generator.generate_key_block(0)
    assert key_block_0 == expected_key_block_0
    assert key_block_1 == expected_key_block_1


def test_key_block_generation_h1ctf():
    expected_key_block_0 = [124, 150, 183, 216, 194, 222, 155, 133, 125, 143, 119, 134, 94, 53, 21, 113]
    expected_key_block_1 = [55, 158, 120, 240, 15, 163, 167, 102, 7, 254, 225, 222, 114, 224, 31, 111]
    expected_key_block_2 = [230, 22, 218, 200, 161, 11, 131, 188, 196, 46, 65, 195, 225, 243, 176, 218]
    expected_key_block_3 = [244, 113, 81, 216, 46, 75, 118, 164, 195, 224, 76, 40, 129, 143, 210, 106]
    expected_key_block_4 = [29, 19, 122, 165, 223, 186, 107, 0, 233, 86, 106, 216, 57, 17, 224, 100]
    expected_key_block_5 = [211, 146, 215, 200, 237, 164, 130, 91, 207, 119, 172, 232, 197, 90, 45, 71]
    expected_key_block_6 = [39, 201, 228, 184, 61, 196, 120, 152, 123, 224, 21, 27, 199, 249, 92, 211]
    expected_key_block_7 = [125, 102, 191, 186, 3, 4, 7, 127, 51, 61, 61, 170, 191, 195, 250, 32]
    expected_key_block_8 = [54, 236, 115, 12, 152, 239, 122, 160, 33, 48, 118, 211, 119, 128, 79, 49]

    post = "B7TRtKO5ub9drSnAEnRSLweuSMA!k5dWN87R7kLQL1!WJur4kTuzjPQecfPRw4DqxEFh6B57RpTz0HwYsb!iWi0jSpXvilsw2WZa6Akh0FT31JuJqoCgd-9VxYznYA1lFevImB-vHeFZ2jU5r4psuCUKyotOXn5OUBBr5IuSsUp6vQ1yupJwqis6fNl9ikU7u4bFMIYUr1eXgNP8fe-TDQ~~"
    post = post.replace('~', '=').replace('!', '/').replace('-', '+')
    encrypted_data = base64.b64decode(post)
    oracle_client = Base64OracleClientMock()
    key_generator = AESIntermediateKeyParallelGenerator(encrypted_data, oracle_client)

    key_block_0 = key_generator.generate_key_block(0)
    key_block_1 = key_generator.generate_key_block(1)
    key_block_2 = key_generator.generate_key_block(2)
    key_block_3 = key_generator.generate_key_block(3)
    key_block_4 = key_generator.generate_key_block(4)
    key_block_5 = key_generator.generate_key_block(5)
    key_block_6 = key_generator.generate_key_block(6)
    key_block_7 = key_generator.generate_key_block(7)
    key_block_8 = key_generator.generate_key_block(8)

    assert key_block_0 == expected_key_block_0
    assert key_block_1 == expected_key_block_1
    assert key_block_2 == expected_key_block_2
    assert key_block_3 == expected_key_block_3
    assert key_block_4 == expected_key_block_4
    assert key_block_5 == expected_key_block_5
    assert key_block_6 == expected_key_block_6
    assert key_block_7 == expected_key_block_7
    assert key_block_8 == expected_key_block_8


class Base64OracleClientMock(object):

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
