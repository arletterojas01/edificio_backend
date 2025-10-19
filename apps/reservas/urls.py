from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import AreaComunViewSet, ReservaViewSet

router = DefaultRouter()
router.register(r'areas-comunes', AreaComunViewSet)
router.register(r'reservas', ReservaViewSet, basename='reserva')

urlpatterns = [
    path('', include(router.urls)),
    
    # URLs adicionales 
    path('mis-reservas/', ReservaViewSet.as_view({'get': 'mis_reservas'}), name='mis_reservas'),
    
    # ✅ CORREGIDO: Cambiar 'crear_reserva' por 'create'
    path('crear-reserva/', ReservaViewSet.as_view({'post': 'create'}), name='crear-reserva'),
    
    path('verificar-disponibilidad/', ReservaViewSet.as_view({'post': 'verificar_disponibilidad'}), name='verificar_disponibilidad'),
    path('reservas/<int:pk>/confirmar/', ReservaViewSet.as_view({'post': 'confirmar'}), name='confirmar_reserva'),
    path('reservas/<int:pk>/cancelar/', ReservaViewSet.as_view({'post': 'cancelar'}), name='cancelar_reserva'),
]