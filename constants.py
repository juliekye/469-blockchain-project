import os


BCHOC_FILE_PATH: str = os.environ.get('BCHOC_FILE_PATH', 'data/blockchain.dat')
AES_KEY: bytes = b'aes-secret-key'