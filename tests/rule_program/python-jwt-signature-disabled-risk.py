import jwt
def vulnerable(token):
    return jwt.decode(token, options={'verify_signature': False})
