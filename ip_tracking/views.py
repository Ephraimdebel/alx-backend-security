from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from ratelimit.decorators import ratelimit

@csrf_exempt
@ratelimit(key='ip', rate='5/m', method='POST', block=True)
@ratelimit(key='user', rate='10/m', method='POST', block=True)
def login_view(request):
    """
    A sensitive login view protected by rate limiting.
    - Anonymous users: max 5 requests/min
    - Authenticated users: max 10 requests/min
    """
    return JsonResponse({"message": "Login endpoint accessed"})
