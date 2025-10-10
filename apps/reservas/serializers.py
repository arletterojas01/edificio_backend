from rest_framework import serializers
from .models import Reserva, AreaComun
from django.conf import settings

class AreaComunSerializer(serializers.ModelSerializer):
    class Meta:
        model = AreaComun
        fields = '__all__'

class ReservaSerializer(serializers.ModelSerializer):
    area_comun_nombre = serializers.CharField(source='area_comun.nombre', read_only=True)
    usuario_nombre = serializers.CharField(source='usuario.get_full_name', read_only=True)
    
    class Meta:
        model = Reserva
        fields = '__all__'
        read_only_fields = ('fecha_creacion', 'codigo_qr', 'usuario')

class DisponibilidadSerializer(serializers.Serializer):
    area_comun = serializers.IntegerField()
    fecha_reserva = serializers.DateField()
    hora_inicio = serializers.TimeField()
    hora_fin = serializers.TimeField()

class CrearReservaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Reserva
        fields = ['area_comun', 'fecha_reserva', 'hora_inicio', 'hora_fin', 'monto']