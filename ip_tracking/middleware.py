import datetime
from ip_tracking.models import RequestLog

class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        ip = request.META.get('REMOTE_ADDR')
        path = request.path

        # Save to DB
        RequestLog.objects.create(
            ip_address=ip,
            path=path
        )

        return self.get_response(request)
