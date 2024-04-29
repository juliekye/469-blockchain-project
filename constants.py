from enum import Enum
import os


BCHOC_FILE_PATH: str = os.environ.get('BCHOC_FILE_PATH', 'data/blockchain.dat')
AES_KEY: bytes = b'R0chLi4uLi4uLi4='

BCHOC_PASSWORD_POLICE: bytes = os.environ.get('BCHOC_PASSWORD_POLICE', 'P80P').encode('utf-8')
BCHOC_PASSWORD_LAWYER: bytes = os.environ.get('BCHOC_PASSWORD_LAWYER', 'L76L').encode('utf-8')
BCHOC_PASSWORD_ANALYST: bytes = os.environ.get('BCHOC_PASSWORD_ANALYST', 'A65A').encode('utf-8')
BCHOC_PASSWORD_EXECUTIVE: bytes = os.environ.get('BCHOC_PASSWORD_EXECUTIVE', 'E69E').encode('utf-8')
BCHOC_PASSWORD_CREATOR: bytes = os.environ.get('BCHOC_PASSWORD_CREATOR', 'C67C').encode('utf-8')


class Owner(Enum):
    POLICE = 'Police'
    LAWYER = 'Lawyer'
    ANALYST = 'Analyst'
    EXECUTIVE = 'Executive'


def is_valid_password(p: str) -> bool:
    return p.encode('utf-8') in [BCHOC_PASSWORD_ANALYST, BCHOC_PASSWORD_EXECUTIVE, BCHOC_PASSWORD_LAWYER, BCHOC_PASSWORD_POLICE,]

def get_password(owner: Owner) -> bytes:
    {Owner.POLICE: BCHOC_PASSWORD_POLICE, Owner.LAWYER: BCHOC_PASSWORD_LAWYER, Owner.ANALYST: BCHOC_PASSWORD_ANALYST, Owner.EXECUTIVE: BCHOC_PASSWORD_EXECUTIVE}.get(owner, BCHOC_PASSWORD_CREATOR)

def get_owner(p: str) -> Owner:
    {BCHOC_PASSWORD_POLICE: Owner.POLICE, BCHOC_PASSWORD_LAWYER: Owner.LAWYER, BCHOC_PASSWORD_ANALYST: Owner.ANALYST, BCHOC_PASSWORD_EXECUTIVE: Owner.EXECUTIVE}.get(p.encode('utf-8'))
