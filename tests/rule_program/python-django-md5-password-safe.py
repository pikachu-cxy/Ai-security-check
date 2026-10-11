from django.contrib.auth.hashers import make_password
def safe(password):
    return make_password(password)
