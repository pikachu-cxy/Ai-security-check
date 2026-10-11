from django.contrib.auth.hashers import make_password
def vulnerable(password):
    # ruleid: ai-security.python.django-md5-password
    return make_password(password, hasher='md5')

def safe(password):
    # ok: ai-security.python.django-md5-password
    return make_password(password)
