"""
URLs del módulo de usuarios - Sistema de Edificio Backend

Este módulo define todos los endpoints relacionados con:
- Autenticación y autorización de usuarios
- Gestión de cuentas y perfiles
- Verificación de email y 2FA
- Auditoría y seguridad
- Operaciones de administración

Versión API: v1
Última actualización: Octubre 2025
"""

from django.urls import path, include
from django.views.decorators.cache import cache_page
from django.views.decorators.csrf import csrf_exempt

# Imports organizados por categoría
from .views import (
    # === AUTENTICACIÓN BÁSICA ===
    RegisterAPIView,
    LoginAPIView,
    LogoutAPIView,
    LogoutAllSessionsAPIView,
    
    # === GESTIÓN DE CONTRASEÑAS ===
    ForgotPasswordAPIView,
    ResetPasswordAPIView,
    ChangePasswordAPIView,
    
    # === VERIFICACIÓN Y SEGURIDAD ===
    VerificarEmailAPIView,
    ReenviarVerificacionAPIView,
    Activate2FAAPIView,
    Verify2FAAPIView,
    ValidateLoginTokenAPIView,
    
    # === GESTIÓN DE CUENTAS ===
    AccountStatusAPIView,
    CheckPersonaAPIView,
    UsuarioRawAPIView,
    
    # === AUDITORÍA Y ADMINISTRACIÓN ===
    AuditoriaEventoListAPIView,
)

# ============================================================================
# CONFIGURACIÓN DE NOMBRES DE APP
# ============================================================================
app_name = 'usuarios'

# ============================================================================
# PATRONES DE URL ORGANIZADOS POR FUNCIONALIDAD
# ============================================================================

# === 🔐 ENDPOINTS DE AUTENTICACIÓN ===
auth_patterns = [
    path(
        "register/", 
        RegisterAPIView.as_view(), 
        name="register"
    ),
    path(
        "login/", 
        LoginAPIView.as_view(), 
        name="login"
    ),
    path(
        "logout/", 
        LogoutAPIView.as_view(), 
        name="logout"
    ),
    path(
        "logout-all/", 
        LogoutAllSessionsAPIView.as_view(), 
        name="logout-all-sessions"
    ),
    path(
        "validate-login-token/", 
        ValidateLoginTokenAPIView.as_view(), 
        name="validate-login-token"
    ),
]

# === 🔑 ENDPOINTS DE GESTIÓN DE CONTRASEÑAS ===
password_patterns = [
    path(
        "forgot-password/", 
        ForgotPasswordAPIView.as_view(), 
        name="forgot-password"
    ),
    path(
        "reset-password/", 
        ResetPasswordAPIView.as_view(), 
        name="reset-password"
    ),
    path(
        "change-password/", 
        ChangePasswordAPIView.as_view(), 
        name="change-password"
    ),
]

# === ✉️ ENDPOINTS DE VERIFICACIÓN DE EMAIL ===
email_verification_patterns = [
    path(
        "verificar-email/", 
        VerificarEmailAPIView.as_view(), 
        name="verificar-email"
    ),
    path(
        "reenviar-verificacion/", 
        ReenviarVerificacionAPIView.as_view(), 
        name="reenviar-verificacion"
    ),
]

# === 🛡️ ENDPOINTS DE AUTENTICACIÓN DE DOS FACTORES (2FA) ===
two_factor_patterns = [
    path(
        "2fa/activate/", 
        Activate2FAAPIView.as_view(), 
        name="activate-2fa"
    ),
    path(
        "2fa/verify/", 
        Verify2FAAPIView.as_view(), 
        name="verify-2fa"
    ),
]

# === 👤 ENDPOINTS DE GESTIÓN DE CUENTAS Y PERFILES ===
account_patterns = [
    path(
        "account-status/", 
        AccountStatusAPIView.as_view(), 
        name="account-status"
    ),
    path(
        "check-persona/", 
        CheckPersonaAPIView.as_view(), 
        name="check-persona"
    ),
    path(
        "profile/raw/", 
        UsuarioRawAPIView.as_view(), 
        name="usuario-raw"
    ),
]

# === 📊 ENDPOINTS DE AUDITORÍA Y ADMINISTRACIÓN ===
admin_patterns = [
    path(
        "auditoria/", 
        cache_page(60 * 5)(AuditoriaEventoListAPIView.as_view()), 
        name="auditoria-evento-list"
    ),
]

# ============================================================================
# URLPATTERNS PRINCIPAL - ESTRUCTURA ORGANIZADA
# ============================================================================

urlpatterns = [
    # ========================================================================
    # 🔐 AUTENTICACIÓN Y AUTORIZACIÓN
    # ========================================================================
    *auth_patterns,
    
    # ========================================================================
    # 🔑 GESTIÓN DE CONTRASEÑAS
    # ========================================================================
    *password_patterns,
    
    # ========================================================================
    # ✉️ VERIFICACIÓN DE EMAIL
    # ========================================================================
    *email_verification_patterns,
    
    # ========================================================================
    # 🛡️ AUTENTICACIÓN DE DOS FACTORES (2FA)
    # ========================================================================
    *two_factor_patterns,
    
    # ========================================================================
    # 👤 GESTIÓN DE CUENTAS Y PERFILES
    # ========================================================================
    *account_patterns,
    
    # ========================================================================
    # 📊 AUDITORÍA Y ADMINISTRACIÓN
    # ========================================================================
    *admin_patterns,
]

# ============================================================================
# DOCUMENTACIÓN DE ENDPOINTS
# ============================================================================

"""
📋 ENDPOINTS DISPONIBLES:

🔐 AUTENTICACIÓN:
├── POST /register/                    - Registrar nuevo usuario
├── POST /login/                       - Iniciar sesión
├── POST /logout/                      - Cerrar sesión actual
├── POST /logout-all/                  - Cerrar todas las sesiones
└── POST /validate-login-token/        - Validar token de login

🔑 CONTRASEÑAS:
├── POST /forgot-password/             - Solicitar recuperación de contraseña
├── POST /reset-password/              - Restablecer contraseña con token
└── POST /change-password/             - Cambiar contraseña (autenticado)

✉️ VERIFICACIÓN EMAIL:
├── POST /verificar-email/             - Verificar email con token
└── POST /reenviar-verificacion/       - Reenviar email de verificación

🛡️ AUTENTICACIÓN 2FA:
├── POST /2fa/activate/                - Activar autenticación de dos factores
└── POST /2fa/verify/                  - Verificar código 2FA

👤 GESTIÓN DE CUENTAS:
├── GET  /account-status/              - Estado de la cuenta del usuario
├── POST /check-persona/               - Verificar si persona existe
└── GET  /profile/raw/                 - Datos raw del usuario

📊 AUDITORÍA:
└── GET  /auditoria/                   - Lista de eventos de auditoría (cached)

🔗 CARACTERÍSTICAS:
- ✅ Todos los endpoints usan HTTPS en producción
- ✅ Rate limiting aplicado por middleware
- ✅ Logging de seguridad automático
- ✅ Validación exhaustiva de datos
- ✅ Respuestas consistentes con códigos HTTP estándar
- ✅ Documentación OpenAPI/Swagger integrada
- ✅ Cache inteligente en endpoints de solo lectura
"""

# ============================================================================
# METADATOS DE LA API
# ============================================================================

API_VERSION = "v1"
API_TITLE = "Sistema de Usuarios - Edificio Backend"
API_DESCRIPTION = "API completa para gestión de usuarios, autenticación y seguridad"
API_CONTACT = {
    'name': 'Equipo de Desarrollo',
    'email': 'dev@edificio.com'
}

# ============================================================================
# CONFIGURACIÓN DE SEGURIDAD ADICIONAL
# ============================================================================

# Rate limiting por endpoint (requests por minuto)
RATE_LIMITS = {
    'register': 5,          # Registro limitado
    'login': 10,            # Login con throttling
    'forgot-password': 3,   # Recuperación muy limitada
    'reset-password': 5,    # Reset moderado
    'verificar-email': 10,  # Verificación normal
    'auditoria': 60,        # Auditoría alta frecuencia
}

# Endpoints que requieren HTTPS obligatorio
HTTPS_REQUIRED = [
    'register', 'login', 'forgot-password', 
    'reset-password', 'change-password',
    'activate-2fa', 'verify-2fa'
]

# Endpoints con cache automático
CACHED_ENDPOINTS = [
    'auditoria-evento-list',  # Cache de 5 minutos
    'account-status',         # Cache de 1 minuto
]