from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import render, redirect, get_object_or_404
from django.db.models import Q
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.urls import reverse
from .models import Reserva, AreaComun
from .serializers import *

# Vistas API para Angular
class AreaComunViewSet(viewsets.ModelViewSet):
    queryset = AreaComun.objects.filter(activo=True)
    serializer_class = AreaComunSerializer
    permission_classes = [IsAuthenticated]

class ReservaViewSet(viewsets.ModelViewSet):
    serializer_class = ReservaSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return Reserva.objects.filter(usuario=self.request.user).order_by('-fecha_creacion')
    
    def get_serializer_class(self):
        if self.action == 'create':
            return CrearReservaSerializer
        return ReservaSerializer
    
    def perform_create(self, serializer):
        reserva = serializer.save(usuario=self.request.user)
        
        # Verificar disponibilidad
        if not reserva.verificar_disponibilidad():
            reserva.delete()
            raise serializers.ValidationError(
                {"error": "El área no está disponible en ese horario"}
            )
    
    @action(detail=False, methods=['get'])
    def mis_reservas(self, request):
        """Endpoint específico para obtener reservas del usuario"""
        reservas = self.get_queryset()
        serializer = self.get_serializer(reservas, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def verificar_disponibilidad(self, request):
        serializer = DisponibilidadSerializer(data=request.data)
        if serializer.is_valid():
            area_comun_id = serializer.validated_data['area_comun']
            fecha_reserva = serializer.validated_data['fecha_reserva']
            hora_inicio = serializer.validated_data['hora_inicio']
            hora_fin = serializer.validated_data['hora_fin']
            
            # Verificar si hay reservas solapadas
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
    
    @action(detail=True, methods=['post'])
    def confirmar(self, request, pk=None):
        reserva = self.get_object()
        reserva.estado = 'confirmada'
        reserva.save()
        return Response(ReservaSerializer(reserva).data)
    
    @action(detail=True, methods=['post'])
    def cancelar(self, request, pk=None):
        reserva = self.get_object()
        if reserva.estado in ['pendiente', 'confirmada']:
            reserva.estado = 'cancelada'
            reserva.save()
            return Response(ReservaSerializer(reserva).data)
        return Response(
            {'error': 'No se puede cancelar esta reserva'}, 
            status=status.HTTP_400_BAD_REQUEST
        )

# Vistas Django para templates (si las necesitas)
def lista_reservas(request):
    """Vista para listar reservas (si usas templates Django)"""
    if not request.user.is_authenticated:
        return redirect('login')
    
    reservas = Reserva.objects.filter(usuario=request.user).order_by('-fecha_creacion')
    return render(request, 'reservas/lista_reservas.html', {'reservas': reservas})

def crear_reserva(request):
    """Vista para crear reserva (si usas templates Django)"""
    if not request.user.is_authenticated:
        return redirect('login')
    
    areas_comunes = AreaComun.objects.filter(activo=True)
    
    if request.method == 'POST':
        area_comun_id = request.POST.get('area_comun')
        fecha_reserva = request.POST.get('fecha_reserva')
        hora_inicio = request.POST.get('hora_inicio')
        hora_fin = request.POST.get('hora_fin')
        monto = request.POST.get('monto', 0)
        
        try:
            area_comun = AreaComun.objects.get(id=area_comun_id)
            
            # Crear reserva
            reserva = Reserva(
                usuario=request.user,
                area_comun=area_comun,
                fecha_reserva=fecha_reserva,
                hora_inicio=hora_inicio,
                hora_fin=hora_fin,
                monto=monto
            )
            
            # Verificar disponibilidad
            if reserva.verificar_disponibilidad():
                reserva.save()
                messages.success(request, 'Reserva creada exitosamente')
                return redirect('lista_reservas')
            else:
                messages.error(request, 'El área no está disponible en ese horario')
                
        except Exception as e:
            messages.error(request, f'Error al crear reserva: {str(e)}')
    
    return render(request, 'reservas/crear_reserva.html', {
        'areas_comunes': areas_comunes
    })

def cancelar_reserva(request, reserva_id):
    """Vista para cancelar reserva (si usas templates Django)"""
    if not request.user.is_authenticated:
        return redirect('login')
    
    reserva = get_object_or_404(Reserva, id=reserva_id, usuario=request.user)
    
    if reserva.estado in ['pendiente', 'confirmada']:
        reserva.estado = 'cancelada'
        reserva.save()
        messages.success(request, 'Reserva cancelada exitosamente')
    else:
        messages.error(request, 'No se puede cancelar esta reserva')
    
    return redirect('lista_reservas')