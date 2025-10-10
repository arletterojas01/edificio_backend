# reservations/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import AreaComunViewSet, ReservaViewSet

router = DefaultRouter()
router.register(r'areas-comunes', AreaComunViewSet)
router.register(r'reservas', ReservaViewSet, basename='reserva')

urlpatterns = [
    path('api/', include(router.urls)),
     # URLs adicionales para redirecciones específicas
    path('mis-reservas/', ReservaViewSet.as_view({'get': 'mis_reservas'}), name='mis_reservas'),
    path('crear-reserva/', ReservaViewSet.as_view({'post': 'crear_reserva'}), name='crear_reserva'),
]