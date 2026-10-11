from django.contrib.auth.hashers import make_password
def vulnerable(password):
    return make_password(password, hasher='md5')
