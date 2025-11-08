import datetime
from ip_tracking.models import RequestLog

from django.http import HttpResponseForbidden
from ip_tracking.models import BlockedIP


from django.utils import timezone
from django.core.cache import cache
from ip_tracking.models import RequestLog, BlockedIP
from django.http import HttpResponseForbidden
from ipgeolocation import IpGeoLocationAPI
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
        self.geo = IpGeoLocationAPI()  # ✅ django-ipgeolocation client

        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)

        # ✅ 1. Block blacklisted IPs
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Your IP is blocked.")

        # ✅ 2. Try to get geolocation from cache
        cache_key = f"geo_{ip}"
        geo_data = cache.get(cache_key)

        if not geo_data:
            # ✅ Query geolocation API
            try:
                response = self.geo.get_ip_geolocation(ip)

                geo_data = {
                    "country": response.get("country_name"),
                    "city": response.get("city"),
                }

                # ✅ Cache for 24 hours (86400 seconds)
                cache.set(cache_key, geo_data, 86400)

            except Exception:
                geo_data = {"country": None, "city": None}

        # ✅ 3. Log request with geolocation
        RequestLog.objects.create(
            ip_address=ip,
            timestamp=timezone.now(),
            path=request.path,
            country=geo_data.get("country"),
            city=geo_data.get("city"),
        )

        return self.get_response(request)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get("REMOTE_ADDR")
