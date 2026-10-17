import uuid
import logging
from django.utils.deprecation import MiddlewareMixin

from . import rules
from .detection import get_client_ip, record_event

logger = logging.getLogger('security')


class SecurityMonitoringMiddleware(MiddlewareMixin):
    def process_request(self, request):
        request.correlation_id = str(uuid.uuid4())

    def process_response(self, request, response):
        if request.path.startswith('/static/'):
            return response

        user = getattr(request, 'user', None)
        authenticated = bool(user and user.is_authenticated)
        username = user.username if authenticated else rules.ANONYMOUS
        status = response.status_code

        # Odmowa dostępu: 403 albo zalogowany użytkownik bez uprawnień odbity z /admin (302/401)
        denied = status == 403 or (
            request.path.startswith('/admin') and status in (302, 401)
            and authenticated and not getattr(user, 'is_staff', False)
        )

        if denied:
            record_event(request, rules.ACCESS_DENIED, username=username, status_code=status,
                         message="Odmowa dostępu do zasobu chronionego")
        elif status == 404:
            record_event(request, rules.NOT_FOUND, username=username, status_code=status,
                         message="Zasób nie istnieje")
        else:
            # Zwykły ruch: tylko log (bez zapisu do bazy), żeby nie obciążać każdego żądania
            logger.info("Obsłużono żądanie HTTP", extra={"security_event": {
                "correlation_id": getattr(request, 'correlation_id', 'unknown'),
                "ip": get_client_ip(request),
                "user": username,
                "event": "HTTP_REQUEST",
                "method": request.method,
                "endpoint": request.path,
                "status_code": status,
                "alert": False,
            }})

        return response
