from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from ip_tracking.models import RequestLog, SuspiciousIP

SUSPICIOUS_PATHS = ['/admin', '/login']

@shared_task
def detect_suspicious_activity():
    """
    Detect IPs with:
    - More than 100 requests in the last hour
    - Accessing sensitive paths (/admin, /login)
    """

    one_hour_ago = timezone.now() - timedelta(hours=1)

    # 1. Flag IPs exceeding 100 requests/hour
    recent_requests = RequestLog.objects.filter(timestamp__gte=one_hour_ago)

    ip_counts = {}
    for req in recent_requests:
        ip_counts[req.ip_address] = ip_counts.get(req.ip_address, 0) + 1

    for ip, count in ip_counts.items():
        if count > 100:
            SuspiciousIP.objects.create(
                ip_address=ip,
                reason=f"Exceeded 100 requests/hour ({count} requests)"
            )

    # 2. Flag IPs accessing sensitive endpoints (/admin, /login)
    sensitive_logs = recent_requests.filter(path__in=SUSPICIOUS_PATHS)

    for entry in sensitive_logs:
        SuspiciousIP.objects.create(
            ip_address=entry.ip_address,
            reason=f"Accessed sensitive path: {entry.path}"
        )

    return "Anomaly detection completed."
