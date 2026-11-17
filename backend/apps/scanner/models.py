import uuid
from django.conf import settings
from django.db import models


class Scan(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETE = "complete", "Complete"
        FAILED = "failed", "Failed"

    class Classification(models.TextChoices):
        LOW = "low", "Low Risk"
        MODERATE = "moderate", "Moderate Risk"
        HIGH = "high", "High Risk"
        CRITICAL = "critical", "Critical Risk"
        ERROR = "error", "Could Not Analyze"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="scans",
    )
    original_url = models.TextField()
    normalized_url = models.TextField(blank=True, default="")
    hostname = models.CharField(max_length=253, blank=True, default="")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    classification = models.CharField(
        max_length=16, choices=Classification.choices, blank=True, default=""
    )
    risk_score = models.PositiveSmallIntegerField(null=True, blank=True)
    # Structured result payloads
    indicators = models.JSONField(default=list, blank=True)
    provider_results = models.JSONField(default=dict, blank=True)
    domain_info = models.JSONField(default=dict, blank=True)
    recommendations = models.JSONField(default=list, blank=True)
    error_message = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "-created_at"]),
            models.Index(fields=["classification"]),
        ]

    def __str__(self):
        return f"{self.normalized_url or self.original_url} [{self.classification or self.status}]"

