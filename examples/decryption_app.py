import base64
import logging

from padding_oracle import AESPaddingOracle, Base64OracleClient

logger = logging.getLogger('padding-oracle')
logger.setLevel('INFO')

if __name__ == "__main__":
    base64_ciphertext = "2llglo8SFBp49-intDmSfnxEz4wEle0iyPiK87rM8SAGN09XluponcUSj9B1sYny"
    base64_ciphertext = base64_ciphertext.replace('~', '=').replace('!', '/').replace('-', '+')
    ciphertext = base64.b64decode(base64_ciphertext)

    oracle_client = Base64OracleClient("http://localhost:5000/decrypt?post=")
    padding_oracle = AESPaddingOracle(oracle_client)
    plaintext = padding_oracle.decrypt(ciphertext)
    plaintext = plaintext.decode('utf8')

    print(f"Plaintext: {plaintext}")