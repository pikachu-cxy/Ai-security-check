import jwt
def vulnerable(token):
    # ruleid: ai-security.python.jwt-signature-disabled
    return jwt.decode(token, options={'verify_signature': False})

def safe(token, key):
    # ok: ai-security.python.jwt-signature-disabled
    return jwt.decode(token, key, algorithms=['HS256'])
