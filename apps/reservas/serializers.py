from rest_framework import serializers
from django.db.models import Q
from .models import Reserva, AreaComun
from datetime import datetime
import math

class AreaComunSerializer(serializers.ModelSerializer):
    class Meta:
        model = AreaComun
        fields = ['id', 'nombre', 'tipo', 'capacidad', 'tarifa', 'descripcion', 'activo']

class ReservaSerializer(serializers.ModelSerializer):
    area_comun_nombre = serializers.CharField(source='area_comun.nombre', read_only=True)
    usuario_nombre = serializers.CharField(source='usuario.username', read_only=True)
    
    class Meta:
        model = Reserva
        fields = [
            'id', 'usuario', 'usuario_nombre', 'area_comun', 'area_comun_nombre',
            'fecha_reserva', 'hora_inicio', 'hora_fin', 'estado', 'monto',
            'metodo_pago', 'pago_confirmado', 'fecha_creacion', 'codigo_qr'
        ]
        read_only_fields = ['usuario', 'monto', 'fecha_creacion', 'codigo_qr']

class CrearReservaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Reserva
        fields = ['area_comun', 'fecha_reserva', 'hora_inicio', 'hora_fin']

    def validate(self, data):
        if data['hora_inicio'] >= data['hora_fin']:
            raise serializers.ValidationError({
                "hora_fin": "La hora de fin debe ser posterior a la hora de inicio"
            })

        # Verificar disponibilidad
        reservas_solapadas = Reserva.objects.filter(
            area_comun=data['area_comun'],
            fecha_reserva=data['fecha_reserva'],
            estado__in=['pendiente', 'confirmada']
        ).filter(
            Q(hora_inicio__lt=data['hora_fin'], hora_fin__gt=data['hora_inicio'])
        )
        
        if reservas_solapadas.exists():
            raise serializers.ValidationError({
                "error": "El área no está disponible en ese horario"
            })

        return data

    def calcular_monto(self, validated_data):
        area_comun = validated_data['area_comun']
        hora_inicio = validated_data['hora_inicio']
        hora_fin = validated_data['hora_fin']

        inicio_dt = datetime.combine(validated_data['fecha_reserva'], hora_inicio)
        fin_dt = datetime.combine(validated_data['fecha_reserva'], hora_fin)
        duracion_horas = (fin_dt - inicio_dt).total_seconds() / 3600
        duracion_horas = math.ceil(duracion_horas)

        monto = area_comun.tarifa * duracion_horas
        return monto

    def create(self, validated_data):
        validated_data['monto'] = self.calcular_monto(validated_data)
        validated_data['usuario'] = self.context['request'].user
        
        reserva = Reserva.objects.create(**validated_data)
        return reserva

class DisponibilidadSerializer(serializers.Serializer):
    area_comun = serializers.PrimaryKeyRelatedField(queryset=AreaComun.objects.filter(activo=True))
    fecha_reserva = serializers.DateField()
    hora_inicio = serializers.TimeField()
    hora_fin = serializers.TimeField()

    def validate(self, data):
        if data['hora_inicio'] >= data['hora_fin']:
            raise serializers.ValidationError({
                "hora_fin": "La hora de fin debe ser posterior a la hora de inicio"
            })
        return data