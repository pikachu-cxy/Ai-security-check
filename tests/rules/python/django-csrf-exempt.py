from django.views.decorators.csrf import csrf_exempt, csrf_protect
# ruleid: ai-security.python.django-csrf-exempt
@csrf_exempt
def vulnerable(request):
    return None

# ok: ai-security.python.django-csrf-exempt
@csrf_protect
def safe(request):
    return None
