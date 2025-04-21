from django.contrib import admin
from django.urls import path
from dashboard.views import login_view, authorize_view, logout_view, ver_dashboard, dashboard_usuario, validar_asistencia, redireccion_por_grupo, ver_tabla_dynamo, ver_usuarios_activos

from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("login/", login_view, name="login"),
    path("authorize/", authorize_view, name="authorize"),
    path("logout/", logout_view, name="logout"),
    path("", redireccion_por_grupo, name="inicio"),
    path("usuario/", dashboard_usuario, name="dashboard_usuario"),
    path("usuario/validar-asistencia/", validar_asistencia, name="validar_asistencia"),
    path("usuario/ver-dynamo/", ver_tabla_dynamo, name="ver_dynamo"),
    path("usuario/usuarios-activos/", ver_usuarios_activos, name="ver_usuarios_activos"),
]
# 👇 Esto permite servir archivos estáticos cuando DEBUG = False
if not settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)