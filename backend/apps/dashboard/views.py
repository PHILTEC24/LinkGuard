from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAdminUser
from django.db.models import Count
from apps.scanner.models import Scan

class DashboardStatsView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        total_scans = Scan.objects.count()
        classifications = dict(
            Scan.objects.values_list("classification")
            .annotate(count=Count("id"))
        )
        recent_scans = Scan.objects.order_by("-created_at")[:10].values(
            "id", "normalized_url", "classification", "risk_score", "created_at"
        )
        return Response({
            "total_scans": total_scans,
            "classifications": classifications,
            "recent_scans": list(recent_scans),
        })

