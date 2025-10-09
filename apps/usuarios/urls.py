from django.urls import path
from .views import (
    RegisterAPIView, LoginAPIView, CheckPersonaAPIView,
    ForgotPasswordAPIView, ResetPasswordAPIView, ChangePasswordAPIView, ValidateLoginTokenAPIView, AuditoriaEventoListAPIView,
    LogoutAPIView, LogoutAllSessionsAPIView, Activate2FAAPIView, Verify2FAAPIView, UsuarioRawAPIView,
    AccountStatusAPIView, VerificarEmailAPIView, ReenviarVerificacionAPIView,
    # === NUEVAS VISTAS PARA ROLES ===
    UserProfileAPIView, UserListAPIView, UpdateUserRolAPIView, MyRolAPIView
)

urlpatterns = [
    path("register/", RegisterAPIView.as_view(), name="register"),
    path("login/", LoginAPIView.as_view(), name="login"),
    path('check-persona/', CheckPersonaAPIView.as_view(), name='check-persona'),
    path('forgot-password/', ForgotPasswordAPIView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordAPIView.as_view(), name='reset-password'),
    path('change-password/', ChangePasswordAPIView.as_view(), name='change-password'),
    path('validate-login-token/', ValidateLoginTokenAPIView.as_view(), name='validate-login-token'),
    path('auditoria/', AuditoriaEventoListAPIView.as_view(), name='auditoria-evento-list'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('logout-all/', LogoutAllSessionsAPIView.as_view(), name='logout-all-sessions'),
    path('2fa/activate/', Activate2FAAPIView.as_view(), name='activate-2fa'),
    path('2fa/verify/', Verify2FAAPIView.as_view(), name='verify-2fa'),
    path('raw/', UsuarioRawAPIView.as_view(), name='usuario-raw'),
    path('account-status/', AccountStatusAPIView.as_view(), name='account-status'),
    # === NUEVOS ENDPOINTS PARA VERIFICACIÓN DE EMAIL ===
    path('verificar-email/', VerificarEmailAPIView.as_view(), name='verificar-email'),
    path('reenviar-verificacion/', ReenviarVerificacionAPIView.as_view(), name='reenviar-verificacion'),
    
    # === NUEVOS ENDPOINTS PARA GESTIÓN DE ROLES ===
    path('perfil/', UserProfileAPIView.as_view(), name='user-profile'),
    path('usuarios/', UserListAPIView.as_view(), name='user-list'),
    path('usuarios/<int:user_id>/rol/', UpdateUserRolAPIView.as_view(), name='update-user-rol'),
    path('mi-rol/', MyRolAPIView.as_view(), name='my-rol'),
]