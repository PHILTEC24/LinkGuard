from django.urls import path
from .views import ScanCreateView, ScanDetailView, ScanHistoryView

urlpatterns = [
    path("scans/", ScanCreateView.as_view(), name="scan-create"),
    path("scans/history/", ScanHistoryView.as_view(), name="scan-history"),
    path("scans/<uuid:pk>/", ScanDetailView.as_view(), name="scan-detail"),
]

