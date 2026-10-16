import uuid
import logging
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger('security')

class SecurityMonitoringMiddleware(MiddlewareMixin):
    def process_request(self, request):
        request.correlation_id = str(uuid.uuid4())

    def process_response(self, request, response):
        if request.path.startswith('/static/'):
            return response

        user = getattr(request, 'user', None)
        username = user.username if user and user.is_authenticated else "anonymous"

        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        ip = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.META.get('REMOTE_ADDR')

        event_data = {
            "correlation_id": getattr(request, 'correlation_id', 'unknown'),
            "ip": ip,
            "user": username,
            "method": request.method,
            "endpoint": request.path,
            "status_code": response.status_code,
            "alert": False,
        }

        # Wykrywamy próby wejścia bez uprawnień (403 lub próba dostępu do /admin)
        if response.status_code == 403 or (request.path.startswith('/admin') and response.status_code in [302, 401] and username != "anonymous" and not getattr(user, 'is_staff', False)):
            event_data["alert"] = True
            event_data["alert_type"] = "ACCESS_DENIED"
            event_data["alert_severity"] = "HIGH"
            logger.warning("Odmowa dostępu do zasobu chronionego", extra={"security_event": event_data})
        else:
            logger.info("Obsłużono żądanie HTTP", extra={"security_event": event_data})

        return response