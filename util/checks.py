import string

allowed_username_chars = [" ", "-", "_", "."]
allowed_username_chars += string.ascii_letters
allowed_username_chars += string.digits

def check_username(username: str):
    if (len(username) < 1) or (len(username) > 20):
        return True

    for char in username:
        if char not in allowed_username_chars:
            return True

    return False