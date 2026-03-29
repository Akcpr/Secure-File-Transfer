
class User:
    def __init__(self, username, password_hash, role = "user", public_key=None):
        self.username = username
        self.password = password_hash
        self.role = role
        self.public_key = public_key  # Used for encrypting AES key

