from django.contrib import admin
from django.urls import path
from customuser.views import UserList, UserCreate, ChangePasswordView, UserUpdate, PasswordResetView, \
    PasswordResetConfirmView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/users/', UserList.as_view(), name='user-list'),
    path('api/users/create/', UserCreate.as_view(), name='user-create'),
    path('api/change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('api/login/', TokenObtainPairView.as_view(), name='token-obtain-pair'),
    path('api/login/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token-verify'),
    path('api/user/update/', UserUpdate.as_view(), name='user-update'),
    path('api/password_reset/', PasswordResetView.as_view(), name='password_reset'),
    path('password_reset/confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
]
