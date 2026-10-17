"""
Warstwa integracyjna detekcji: zapis zdarzeń, uruchamianie reguł (rules.py),
deduplikacja alertów (cooldown) i ustandaryzowany log JSON.

Użycie:  record_event(request, rules.LOGIN_FAILURE, username="user1")
"""
import logging
from datetime import timedelta

from django.conf import settings
from django.db.models import Q
from django.utils import timezone

from . import rules
from .models import SecurityAlert, SecurityEvent

logger = logging.getLogger("security")

MAX_FIELD = 150  # login pochodzi od atakującego - ograniczamy długość przed zapisem


def get_client_ip(request) -> str:
    """Jedno źródło prawdy o IP (middleware i widoki muszą się zgadzać, bo reguły korelują po IP).

    X-Forwarded-For jest nagłówkiem sterowanym przez klienta, więc ufamy mu wyłącznie
    gdy aplikacja stoi za zaufanym proxy (settings.TRUST_X_FORWARDED_FOR = True).
    """
    if getattr(settings, "TRUST_X_FORWARDED_FOR", False):
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        if xff:
            return xff.split(",")[0].strip()[:45]
    return (request.META.get("REMOTE_ADDR") or "unknown")[:45]


def _config() -> dict:
    return rules.build_config(getattr(settings, "DETECTION_RULES", None))


def _history(now, ip, username, config):
    since = now - timedelta(seconds=rules.lookback_seconds(config))
    qs = (SecurityEvent.objects.filter(timestamp__gte=since)
          .filter(Q(ip_address=ip) | Q(username=username))
          .order_by("timestamp"))
    return [rules.Event(e.timestamp, e.event_type, e.ip_address, e.username,
                        e.endpoint, e.status_code, e.details) for e in qs]


def _raise_alert(det, ip, correlation_id, now) -> bool:
    """Tworzy alert, chyba że identyczny (typ+konto+IP) był w oknie cooldown. Zwraca czy utworzono."""
    if det.cooldown:
        recent = SecurityAlert.objects.filter(
            alert_type=det.alert_type, username=det.username, ip_address=ip,
            timestamp__gte=now - timedelta(seconds=det.cooldown))
        if recent.exists():
            return False
    SecurityAlert.objects.create(
        timestamp=now, correlation_id=correlation_id, ip_address=ip, username=det.username,
        alert_type=det.alert_type, rule_id=det.rule_id, description=det.description,
        severity=det.severity)
    return True


_SEVERITY_LEVEL = {"CRITICAL": logging.ERROR, "HIGH": logging.WARNING, "MEDIUM": logging.WARNING}


def record_event(request, event_type, *, username=None, status_code=None, details=None, message=None):
    """Zapisuje zdarzenie, ocenia reguły, tworzy alerty i loguje wynik w jednym, spójnym formacie.

    Błąd w monitoringu nie może przewrócić żądania użytkownika, ale jest widoczny w logu (fail-open + log).
    """
    ip = get_client_ip(request)
    correlation_id = getattr(request, "correlation_id", "unknown")
    if username is None:
        user = getattr(request, "user", None)
        username = user.username if user is not None and user.is_authenticated else rules.ANONYMOUS
    username = (username or rules.ANONYMOUS)[:MAX_FIELD]
    endpoint = request.path[:255]
    details = dict(details or {})

    event_data = {
        "correlation_id": correlation_id, "ip": ip, "user": username, "event": event_type,
        "method": request.method, "endpoint": endpoint, "status_code": status_code,
        "alert": False,
    }
    level = logging.WARNING if event_type in (rules.LOGIN_FAILURE, rules.ACCESS_DENIED) else logging.INFO
    log_message = message or event_type
    try:
        now = timezone.now()
        config = _config()
        history = _history(now, ip, username, config)
        current = rules.Event(now, event_type, ip, username, endpoint, status_code, details)
        detections = rules.evaluate(current, history, config)

        SecurityEvent.objects.create(
            timestamp=now, correlation_id=correlation_id, ip_address=ip, username=username,
            event_type=event_type, endpoint=endpoint, method=request.method,
            status_code=status_code, details=details)

        raised = []
        for det in detections:
            if _raise_alert(det, ip, correlation_id, now):
                raised.append(det)
        event_data.update(details)
        if raised:
            top = max(raised, key=lambda d: ("MEDIUM", "HIGH", "CRITICAL").index(d.severity))
            event_data.update(alert=True, alert_type=top.alert_type, alert_severity=top.severity,
                              alert_rules=[d.rule_id for d in raised])
            level = _SEVERITY_LEVEL.get(top.severity, logging.WARNING)
            log_message = f"ALERT {top.alert_type}: {log_message}"
    except Exception:  # monitoring nie może zablokować aplikacji
        logger.exception("Błąd silnika detekcji", extra={"security_event": event_data})
    logger.log(level, log_message, extra={"security_event": event_data})
    return event_data
