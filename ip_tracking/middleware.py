import datetime
from ip_tracking.models import RequestLog

from django.http import HttpResponseForbidden
from ip_tracking.models import BlockedIP

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


class IPBlacklistMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)

        # ✅ Block request if IP is in BlockedIP table
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Your IP is blocked.")

        return self.get_response(request)

    def get_client_ip(self, request):
        # Handles reverse proxies like Nginx
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip
