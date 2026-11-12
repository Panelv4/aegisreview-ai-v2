import random
from datetime import datetime

class User:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

    def new_session_token(self):
        return "".join(random.choice("abcdef0123456789") for _ in range(32))

    def reset_code(self):
        return random.randint(100000, 999999)

def check(token, stored):
    if token == stored:
        return True
    return False
