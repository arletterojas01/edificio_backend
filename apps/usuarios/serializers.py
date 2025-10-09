from rest_framework import serializers
from .models import Persona, Usuario, ROLES, ROLE_DEFAULT
from .models import AuditoriaEvento
from .crypto import encrypt_sensitive_data, decrypt_sensitive_data
import re
import bleach

COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "abc123", "111111", "123456789", "12345", "123123", "admin"
]

def validar_password(password, nombre='', apellido='', ci='', fecha_nacimiento=''):
    if len(password) < 8:
        raise serializers.ValidationError("La contraseña debe tener al menos 8 caracteres.")
    if not re.search(r"[A-Z]", password):
        raise serializers.ValidationError("La contraseña debe contener al menos una letra mayúscula.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise serializers.ValidationError("La contraseña debe contener al menos un carácter especial.")
    if password.lower() in COMMON_PASSWORDS:
        raise serializers.ValidationError("La contraseña es demasiado común o débil.")
    if (
        nombre and nombre.lower() in password.lower() or
        apellido and apellido.lower() in password.lower() or
        ci and ci in password or
        fecha_nacimiento and str(fecha_nacimiento) in password
    ):
        raise serializers.ValidationError("La contraseña no debe contener tu nombre, apellido, CI o fecha de nacimiento.")

class PersonaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Persona
        fields = ["nombre", "apellido", "ci", "email", "sexo", "telefono", "fecha_nacimiento"]

class UsuarioSerializer(serializers.ModelSerializer):
    """Serializer para leer/actualizar usuarios (incluyendo rol)"""
    persona = PersonaSerializer(read_only=True)
    
    class Meta:
        model = Usuario
        fields = ['id', 'username', 'email', 'rol', 'is_active', 'persona', 'is_email_verified']
        read_only_fields = ['id', 'username', 'email', 'persona', 'is_email_verified']

class RegisterSerializer(serializers.Serializer):
    persona = PersonaSerializer()
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True)

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("La contraseña debe tener al menos 8 caracteres.")
        if not re.search(r"[A-Z]", value):
            raise serializers.ValidationError("La contraseña debe contener al menos una letra mayúscula.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", value):
            raise serializers.ValidationError("La contraseña debe contener al menos un carácter especial.")
        if value.lower() in COMMON_PASSWORDS:
            raise serializers.ValidationError("La contraseña es demasiado común o débil.")
        return value

    def validate(self, data):
        ci = data['persona']['ci']
        email = data['persona']['email']
        password = data['password']
        nombre = data['persona']['nombre']
        apellido = data['persona']['apellido']
        fecha_nacimiento = data['persona'].get('fecha_nacimiento', '')

        if Persona.objects.filter(ci=ci).exists():
            raise serializers.ValidationError({'ci': 'Ya existe una persona con este CI.'})
        if Persona.objects.filter(email=email).exists():
            raise serializers.ValidationError({'email': 'Ya existe una persona con este email.'})
        if Usuario.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError({'username': 'Ya existe un usuario con este username.'})

        if (
            nombre.lower() in password.lower() or
            apellido.lower() in password.lower() or
            ci in password or
            (fecha_nacimiento and str(fecha_nacimiento) in password)
        ):
            raise serializers.ValidationError({'password': 'La contraseña no debe contener tu nombre, apellido, CI o fecha de nacimiento.'})

        return data

    def create(self, validated_data):
        from django.utils import timezone
        from datetime import timedelta
        import random
        from django.core.mail import send_mail
        from django.conf import settings
        
        persona_data = validated_data.pop("persona")
        persona = Persona.objects.create(**persona_data)
        
        verification_token = str(random.randint(100000, 999999))
        expires_at = timezone.now() + timedelta(hours=24)
        
        # Crear usuario con rol por defecto (residente)
        usuario = Usuario.objects.create_user(
            username=validated_data["username"],
            email=persona.email,
            password=validated_data["password"],
            persona=persona,
            is_email_verified=False,
            email_verification_token=verification_token,
            email_verification_expires=expires_at,
            rol=ROLE_DEFAULT  # Rol por defecto: residente
        )
        
        self._send_verification_email(usuario)
        
        return usuario
    
    def _send_verification_email(self, usuario):
        """Envía correo de verificación al usuario"""
        from django.core.mail import send_mail
        from django.conf import settings
        
        subject = "Código de verificación - EdificioApp"
        
        message = f"""
        ¡Hola {usuario.persona.nombre}!
        
        Gracias por registrarte en EdificioApp. Para completar tu registro, por favor ingresa el siguiente código de verificación en la aplicación:
        
        CÓDIGO DE VERIFICACIÓN: {usuario.email_verification_token}
        
        Este código expirará en 24 horas.
        
        Tu rol asignado es: {usuario.get_rol_display()}
        
        Si no creaste esta cuenta, puedes ignorar este correo.
        
        Saludos,
        El equipo de EdificioApp
        """
        
        try:
            print(f"🔄 Intentando enviar correo a: {usuario.email}")
            print(f"📧 Código de verificación: {usuario.email_verification_token}")
            
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [usuario.email],
                fail_silently=False,
            )
            print(f"✅ Correo enviado exitosamente a: {usuario.email}")
        except Exception as e:
            print(f"❌ ERROR enviando correo de verificación: {e}")
            print(f"📧 Email Backend: {settings.EMAIL_BACKEND}")
            print(f"📧 From Email: {settings.DEFAULT_FROM_EMAIL}")
            raise e

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get("username")
        password = data.get("password")

        try:
            usuario = Usuario.objects.get(username=username)
        except Usuario.DoesNotExist:
            raise serializers.ValidationError("Usuario no encontrado")

        if not usuario.check_password(password):
            raise serializers.ValidationError("Contraseña incorrecta")

        if not usuario.is_email_verified:
            raise serializers.ValidationError({
                "email_not_verified": True,
                "message": "Debes verificar tu correo electrónico antes de iniciar sesión",
                "email": usuario.email,
                "action": "Revisa tu bandeja de entrada o solicita un nuevo correo de verificación",
                "verification_endpoint": "/api/usuarios/verificar-email/",
                "resend_endpoint": "/api/usuarios/reenviar-verificacion/"
            })

        data["usuario"] = usuario
        return data

class UpdateRolSerializer(serializers.Serializer):
    """Serializer para actualizar el rol de un usuario"""
    rol = serializers.ChoiceField(choices=ROLES)
    
    def validate_rol(self, value):
        if value not in [role[0] for role in ROLES]:
            raise serializers.ValidationError("Rol inválido")
        return value

class AuditoriaEventoSerializer(serializers.ModelSerializer):
    def validate_descripcion(self, value):
        return bleach.clean(value)

    class Meta:
        model = AuditoriaEvento
        fields = '__all__'