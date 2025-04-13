from django.contrib import admin
from django.urls import path
from dashboard.views import (
    ver_dashboard,
    crear_usuario_view,
    login_view,
    logout_view,
)

from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),

    # login/logout
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),

    # vistas principales
    path('', ver_dashboard, name='ver_dashboard'),
    path('crear_usuario/', crear_usuario_view, name='crear_usuario'),
]

# 👇 Esto permite servir archivos estáticos cuando DEBUG = False
if not settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)