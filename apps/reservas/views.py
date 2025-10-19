from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.db.models import Q
from .models import Reserva, AreaComun
from .serializers import (
    ReservaSerializer, 
    CrearReservaSerializer, 
    DisponibilidadSerializer,
    AreaComunSerializer
)

class ReservaViewSet(viewsets.ModelViewSet):
    serializer_class = ReservaSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        print(f"🔍 Usuario: {self.request.user}")
        reservas = Reserva.objects.filter(usuario=self.request.user).order_by('-fecha_creacion')
        print(f"🔍 Reservas encontradas: {reservas.count()}")
        return reservas
    
    def get_serializer_class(self):
        if self.action == 'create':
            return CrearReservaSerializer
        return ReservaSerializer

    def retrieve(self, request, *args, **kwargs):
        print(f"🔍 Retrieve llamado para ID: {kwargs.get('pk')}")
        try:
            instance = self.get_object()
            print(f"✅ Reserva encontrada: {instance.id}")
            serializer = self.get_serializer(instance)
            return Response(serializer.data)
        except Exception as e:
            print(f"❌ Error en retrieve: {e}")
            return Response(
                {'error': 'Reserva no encontrada'}, 
                status=status.HTTP_404_NOT_FOUND
            )

    def create(self, request, *args, **kwargs):
        print("🎯 CREATE reserva llamado")
        print(f"📦 Datos recibidos: {request.data}")
        print(f"👤 Usuario: {request.user}")
        
        # ✅ CORREGIDO: Pasar el contexto con la request
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        
        area_comun = serializer.validated_data['area_comun']
        fecha_reserva = serializer.validated_data['fecha_reserva']
        hora_inicio = serializer.validated_data['hora_inicio']
        hora_fin = serializer.validated_data['hora_fin']
        
        print(f"🔍 Verificando disponibilidad: {area_comun.id} - {fecha_reserva} - {hora_inicio} a {hora_fin}")
        
        reservas_solapadas = Reserva.objects.filter(
            area_comun=area_comun,
            fecha_reserva=fecha_reserva,
            estado__in=['pendiente', 'confirmada']
        ).filter(
            Q(hora_inicio__lt=hora_fin, hora_fin__gt=hora_inicio)
        )
        
        if reservas_solapadas.exists():
            print("❌ Área no disponible")
            return Response(
                {'error': 'El área no está disponible en ese horario'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        print("✅ Área disponible, creando reserva...")
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        
        print(f"✅✅✅ RESERVA CREADA EXITOSAMENTE: {serializer.data}")
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    # ✅ ACTION para mis_reservas
    @action(detail=False, methods=['get'])
    def mis_reservas(self, request):
        print("🔍 mis_reservas llamado")
        reservas = self.get_queryset()
        serializer = self.get_serializer(reservas, many=True)
        return Response(serializer.data)
    
    # ✅ ACTION para verificar_disponibilidad
    @action(detail=False, methods=['post'])
    def verificar_disponibilidad(self, request):
        print("🔍 verificar_disponibilidad llamado")
        serializer = DisponibilidadSerializer(data=request.data)
        if serializer.is_valid():
            area_comun_id = serializer.validated_data['area_comun']
            fecha_reserva = serializer.validated_data['fecha_reserva']
            hora_inicio = serializer.validated_data['hora_inicio']
            hora_fin = serializer.validated_data['hora_fin']
            
            reservas_solapadas = Reserva.objects.filter(
                area_comun_id=area_comun_id,
                fecha_reserva=fecha_reserva,
                estado__in=['pendiente', 'confirmada']
            ).filter(
                Q(hora_inicio__lt=hora_fin, hora_fin__gt=hora_inicio)
            )
            
            disponible = not reservas_solapadas.exists()
            return Response({'disponible': disponible})
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    # ✅ ACTION para confirmar
    @action(detail=True, methods=['post'])
    def confirmar(self, request, pk=None):
        print(f"🔍 confirmar llamado para ID: {pk}")
        try:
            reserva = self.get_object()
            print(f"✅ Reserva encontrada para confirmar: {reserva.id}")
            reserva.estado = 'confirmada'
            reserva.save()
            return Response(ReservaSerializer(reserva).data)
        except Exception as e:
            print(f"❌ Error en confirmar: {e}")
            return Response(
                {'error': 'Reserva no encontrada'}, 
                status=status.HTTP_404_NOT_FOUND
            )
    
    # ✅ ACTION para cancelar
    @action(detail=True, methods=['post'])
    def cancelar(self, request, pk=None):
        print(f"🔍 cancelar llamado para ID: {pk}")
        try:
            reserva = self.get_object()
            print(f"✅ Reserva encontrada para cancelar: {reserva.id} - Estado: {reserva.estado}")
            
            if reserva.estado in ['pendiente', 'confirmada']:
                reserva.estado = 'cancelada'
                reserva.save()
                print(f"✅ Reserva cancelada exitosamente")
                return Response(ReservaSerializer(reserva).data)
            else:
                return Response(
                    {'error': 'No se puede cancelar esta reserva'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
        except Exception as e:
            print(f"❌ Error en cancelar: {e}")
            return Response(
                {'error': 'Reserva no encontrada'}, 
                status=status.HTTP_404_NOT_FOUND
            )

class AreaComunViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AreaComun.objects.filter(activo=True)
    serializer_class = AreaComunSerializer
    permission_classes = [IsAuthenticated]