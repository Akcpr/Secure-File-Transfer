''' 
Code for shared constants used across the database module
'''

# Network Configuration
HOST = '0.0.0.0'
PORT = 9999
BUFFER_SIZE = 5000
CHUNK_SIZE = 4096

# RSA and AES Configuration
RSA_KEY_SIZE = 2048
# 256 bits
AES_KEY_SIZE = 32
# 128 Bits 
AES_IV_SIZE = 16   

# HMAC Configuration
HMAC_KEY_SIZE = 32

# Session Configuration
# Session timeout in seconds
SESSION_TIMEOUT = 86400
TOKEN_LENGTH = 32


# Database Configuration
DATABASE_FILE = 'database.json'
USERS_TABLE = 'users'
FILES_TABLE = 'files'
SESSIONS_TABLE = 'sessions'

# File Storage
SERVER_FILES_DIR = 'server_files/'
CLIENT_KEYS_DIR = 'client_keys/'

# Password Configuration
BCRYPT_ROUNDS = 10

# Response Status
STATUS_SUCCESS = 'success'
STATUS_ERROR = 'error'
STATUS_READY = 'ready'