# reservations/admin.py
from django.contrib import admin
from .models import AreaComun, Reserva

@admin.register(AreaComun)
class AreaComunAdmin(admin.ModelAdmin):
    list_display = ['nombre', 'tipo', 'tarifa', 'activo']
    list_filter = ['tipo', 'activo']
    search_fields = ['nombre']

@admin.register(Reserva)
class ReservaAdmin(admin.ModelAdmin):
    list_display = ['id', 'usuario', 'area_comun', 'fecha_reserva', 'hora_inicio', 'estado']
    list_filter = ['estado', 'area_comun', 'fecha_reserva']
    search_fields = ['usuario__username', 'area_comun__nombre']