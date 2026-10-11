from django.views.decorators.csrf import csrf_exempt, csrf_protect
@csrf_protect
def safe(request):
    return None
