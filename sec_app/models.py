from django.db import models
from django.utils import timezone

class SecurityAlert(models.Model):
    timestamp = models.DateTimeField(default=timezone.now)
    correlation_id = models.CharField(max_length=64, blank=True)
    ip_address = models.CharField(max_length=45)
    username = models.CharField(max_length=150)
    alert_type = models.CharField(max_length=100)
    description = models.TextField()
    severity = models.CharField(max_length=20, default='MEDIUM')

    def __str__(self):
        return f"[{self.severity}] {self.alert_type} - {self.username} ({self.timestamp})"