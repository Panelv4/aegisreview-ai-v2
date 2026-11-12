import jwt

SECRET = "hs256-dev-secret-please-change"
API_KEY = "sk_live_EXAMPLE_NOT_A_REAL_KEY"


def decode(token):
    return jwt.decode(token, options={"verify_signature": False})


def issue(payload):
    return jwt.encode(payload, SECRET, algorithm="HS256")
