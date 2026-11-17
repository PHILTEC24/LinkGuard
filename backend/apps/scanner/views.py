from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.throttling import ScopedRateThrottle
from django.shortcuts import get_object_or_404

from .models import Scan
from .serializers import ScanCreateSerializer, ScanSerializer
from .services import run_scan
from .tasks import execute_scan_task
from .validators import normalize_and_validate, URLValidationError


class ScanCreateView(generics.CreateAPIView):
    """
    POST /api/scans/  { "url": "...", "async_scan": false }
    Runs synchronously by default for snappy UI response,
    or queues to Celery if async_scan=true.
    """
    serializer_class = ScanCreateSerializer
    permission_classes = [AllowAny]
    throttle_classes = []

    def create(self, request):
        try:
            ser = self.get_serializer(data=request.data)
            ser.is_valid(raise_exception=True)
            raw = ser.validated_data["url"]
            is_async = ser.validated_data.get("async_scan", False)

            # Reject unsafe URLs before creating a row
            try:
                normalize_and_validate(raw)
            except URLValidationError as e:
                return Response(
                    {"detail": str(e), "code": getattr(e, "code", "invalid")},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            scan = Scan.objects.create(
                user=request.user if request.user.is_authenticated else None,
                original_url=raw,
            )

            if is_async:
                execute_scan_task.delay(str(scan.id))
                return Response(ScanSerializer(scan).data, status=status.HTTP_202_ACCEPTED)

            run_scan(scan)
            return Response(ScanSerializer(scan).data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response(
                {"detail": f"Scan processing failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ScanDetailView(generics.RetrieveAPIView):
    serializer_class = ScanSerializer
    permission_classes = [AllowAny]

    def get_object(self):
        pk = self.kwargs["pk"]
        if self.request.user.is_authenticated:
            return get_object_or_404(Scan, id=pk)
        return get_object_or_404(Scan, id=pk, user__isnull=True)


class ScanHistoryView(generics.ListAPIView):
    serializer_class = ScanSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = Scan.objects.filter(user=self.request.user)
        classification = self.request.query_params.get("classification")
        if classification:
            qs = qs.filter(classification=classification)
        search = self.request.query_params.get("q")
        if search:
            qs = qs.filter(normalized_url__icontains=search)
        return qs

