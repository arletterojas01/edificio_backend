from django.db import models
from django.conf import settings
import qrcode
from io import BytesIO
from django.core.files import File
from django.utils import timezone

class AreaComun(models.Model):
    TIPO_AREA = [
        ('salon', 'Salón Principal'),
        ('gimnasio', 'Gimnasio'),
        ('parqueo', 'Parqueo'),
        ('piscina', 'Piscina'),
        ('terraza', 'Terraza'),
    ]
    
    nombre = models.CharField(max_length=100)
    tipo = models.CharField(max_length=20, choices=TIPO_AREA)
    capacidad = models.IntegerField(default=1)
    tarifa = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    descripcion = models.TextField(blank=True)
    activo = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.nombre} ({self.get_tipo_display()})"

class Reserva(models.Model):
    ESTADO_RESERVA = [
        ('pendiente', 'Pendiente'),
        ('confirmada', 'Confirmada'),
        ('cancelada', 'Cancelada'),
        ('completada', 'Completada'),
    ]
    
    usuario = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    area_comun = models.ForeignKey(AreaComun, on_delete=models.CASCADE)
    fecha_reserva = models.DateField()
    hora_inicio = models.TimeField()
    hora_fin = models.TimeField()
    estado = models.CharField(max_length=20, choices=ESTADO_RESERVA, default='pendiente')
    codigo_qr = models.ImageField(upload_to='qrcodes/', blank=True, null=True)
    monto = models.DecimalField(max_digits=10, decimal_places=2)
    metodo_pago = models.CharField(max_length=20, blank=True, null=True)
    pago_confirmado = models.BooleanField(default=False)
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Reserva {self.id} - {self.usuario.username}"
    
    def save(self, *args, **kwargs):
        is_new = self.pk is None
        super().save(*args, **kwargs)
        
        # Generar QR solo para nuevas reservas sin QR
        if is_new and not self.codigo_qr:
            self.generar_qr_code()
            super().save(update_fields=['codigo_qr'])
    
    def generar_qr_code(self):
        try:
            qr_data = f"RESERVA-{self.id}-{self.usuario.username}-{self.fecha_reserva}"
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(qr_data)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = BytesIO()
            img.save(buffer, 'PNG')
            buffer.seek(0)
            
            self.codigo_qr.save(
                f'qr_reserva_{self.id}.png',
                File(buffer),
                save=False
            )
            buffer.close()
        except Exception as e:
            print(f"Error generando QR: {e}")
    
    def verificar_disponibilidad(self):
        from django.db.models import Q
        reservas_solapadas = Reserva.objects.filter(
            area_comun=self.area_comun,
            fecha_reserva=self.fecha_reserva,
            estado__in=['pendiente', 'confirmada']
        ).exclude(id=self.id).filter(
            Q(hora_inicio__lt=self.hora_fin, hora_fin__gt=self.hora_inicio)
        )
        return not reservas_solapadas.exists()