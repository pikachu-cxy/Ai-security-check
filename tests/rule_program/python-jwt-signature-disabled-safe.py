import jwt
def safe(token, key):
    return jwt.decode(token, key, algorithms=['HS256'])
