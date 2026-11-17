from rest_framework import serializers
from .models import Scan


class ScanCreateSerializer(serializers.Serializer):
    url = serializers.CharField(max_length=2048)
    async_scan = serializers.BooleanField(required=False, default=False)


class ScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = [
            "id", "original_url", "normalized_url", "hostname", "status",
            "classification", "risk_score", "indicators", "provider_results",
            "domain_info", "recommendations", "error_message",
            "created_at", "completed_at",
        ]
        read_only_fields = fields

