from django.contrib import admin
from django.urls import path, include
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

@api_view(["GET"])
@permission_classes([AllowAny])
def api_root(request):
    return Response({
        "service": "LinkGuard Threat Analysis API",
        "status": "healthy",
        "endpoints": {
            "scan_url": "/api/scans/ (POST: { url: 'https://...' })",
            "scan_history": "/api/scans/history/ (GET)",
            "auth_token": "/api/auth/token/ (POST)",
            "auth_refresh": "/api/auth/token/refresh/ (POST)",
            "auth_register": "/api/auth/register/ (POST)",
            "dashboard_stats": "/api/dashboard/stats/ (GET, Admin)",
        },
    })

urlpatterns = [
    path("", api_root, name="home-root"),
    path("admin/", admin.site.urls),
    path("api/", api_root, name="api-root"),
    # Authentication endpoints
    path("api/auth/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/auth/", include("apps.accounts.urls")),
    # Scanner & Dashboard endpoints
    path("api/", include("apps.scanner.urls")),
    path("api/dashboard/", include("apps.dashboard.urls")),
]

