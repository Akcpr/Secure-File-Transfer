
def validate_username(username: str):
    if len(username) < 3 or len(username) > 30:
        print(f"Username must be {'greater' if len(username) < 3 else 'smaller'} than {3 if len(username) < 3 else 30}")
        return False
    if not username.isalnum():
        print("username can only contain numbers and letters")
        return False
    return True

def validate_password(password: str):
    if len(password) < 7:
        print("password must be at least 7 characters")
        return False
    if password.isalnum():
        print("password must contain at least 1 special character")
        return False
    if password.lower() == password or password.upper() == password:
        print("password must contain at least 1 uppercase and lowercase letter")
        return False
    return True