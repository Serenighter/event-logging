from django.db import models
from django.utils import timezone


class SecurityEvent(models.Model):
    """Znormalizowane zdarzenie bezpieczeństwa - źródło danych dla reguł korelacyjnych.

    UWAGA: nigdy nie zapisujemy tu haseł, tokenów ani ciasteczek sesji.
    """
    timestamp = models.DateTimeField(default=timezone.now)
    correlation_id = models.CharField(max_length=64, blank=True)
    ip_address = models.CharField(max_length=45)
    username = models.CharField(max_length=150)
    event_type = models.CharField(max_length=50)
    endpoint = models.CharField(max_length=255, blank=True)
    method = models.CharField(max_length=10, blank=True)
    status_code = models.PositiveSmallIntegerField(null=True, blank=True)
    details = models.JSONField(default=dict, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["event_type", "timestamp"], name="evt_type_ts_idx"),
            models.Index(fields=["ip_address", "timestamp"], name="evt_ip_ts_idx"),
            models.Index(fields=["username", "timestamp"], name="evt_user_ts_idx"),
        ]

    def __str__(self):
        return f"{self.event_type} {self.username}@{self.ip_address} ({self.timestamp})"


class SecurityAlert(models.Model):
    timestamp = models.DateTimeField(default=timezone.now)
    correlation_id = models.CharField(max_length=64, blank=True)
    ip_address = models.CharField(max_length=45)
    username = models.CharField(max_length=150)
    alert_type = models.CharField(max_length=100)
    rule_id = models.CharField(max_length=20, blank=True)
    description = models.TextField()
    severity = models.CharField(max_length=20, default='MEDIUM')

    def __str__(self):
        return f"[{self.severity}] {self.alert_type} - {self.username} ({self.timestamp})"
