from django.contrib import admin
from django.urls import path
from dashboard.views import ver_dashboard

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', ver_dashboard),
]
