from django.contrib import admin
from django.urls import path
from dashboard.views import login_view, authorize_view, logout_view, ver_dashboard, dashboard_usuario

from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("login/", login_view, name="login"),
    path("authorize/", authorize_view, name="authorize"),
    path("logout/", logout_view, name="logout"),
    path("", ver_dashboard, name="ver_dashboard"),
    path("usuario/", dashboard_usuario, name="dashboard_usuario"),
]
# 👇 Esto permite servir archivos estáticos cuando DEBUG = False
if not settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)