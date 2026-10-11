from django.views.decorators.csrf import csrf_exempt, csrf_protect
@csrf_exempt
def vulnerable(request):
    return None
