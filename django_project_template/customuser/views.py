from django.contrib.auth import get_user_model
from django.utils import timezone
from .serializers import UserSerializer, UpdateUserSerializer, ChangePasswordSerializer, PasswordConfirmResetSerializer
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.urls import reverse
from django.core.mail import send_mail
from django.conf import settings
from .serializers import PasswordResetSerializer

User = get_user_model()


class UserList(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        if request.user.is_superuser:
            users = User.objects.all()
        else:
            users = User.objects.exclude(is_staff=True)

        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)


class UserCreate(APIView):

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.is_active = False
            user.email_confirmation_sent_at = timezone.now()
            user.save()

            # Envoyer un e-mail de confirmation de compte avec un lien unique
            confirmation_link = 'http://localhost:8000/confirm/email/{}/'.format(user.pk)
            send_mail(
                'Confirmation de compte',
                'Cliquez sur ce lien pour confirmer votre compte : {}'.format(confirmation_link),
                'noreply@monsite.com',
                [user.email],
                fail_silently=False,
            )

            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ConfirmEmail(APIView):
    def get(self, request, user_id):
        user = User.objects.get(id=user_id)
        time_limit = timezone.now() - timezone.timedelta(hours=24)  # Limite de temps de 24 heures

        # Vérifier si l'e-mail a déjà été confirmé ou si le délai de 24 heures est expiré
        if user.email_confirmed or user.email_confirmation_sent_at < time_limit:
            return Response(status=status.HTTP_400_BAD_REQUEST)  # L'e-mail a expiré ou a déjà été confirmé

        # Confirmer l'adresse e-mail de l'utilisateur
        user.email_confirmed = True
        user.is_active = True
        user.save()
        return Response(status=status.HTTP_200_OK)  # Confirmation d'e-mail réussie


class UserUpdate(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UpdateUserSerializer

    def get_object(self):
        return self.request.user


class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetView(APIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'detail': 'No user with that email address.'}, status=status.HTTP_400_BAD_REQUEST)

        token = PasswordResetTokenGenerator().make_token(user)
        uidb64 = urlsafe_base64_encode(smart_bytes(user.pk))

        email_subject = 'Reset your password'
        reset_url = reverse('password_reset_confirm', kwargs={'uidb64': uidb64, 'token': token})

        email_body = f"Hi, \nPlease click the link below to reset your password: \nhttp://127.0.0.1:8000/{reset_url}"

        send_mail(
            email_subject,
            email_body,
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )

        return Response({'detail': 'Password reset email has been sent.'}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordConfirmResetSerializer

    def get(self, request, uidb64, token):
        try:
            uid = smart_bytes(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and PasswordResetTokenGenerator().check_token(user, token):
            # Set the user ID in the session to be used in the password reset form submission
            request.session['reset_user'] = user.pk
            return Response({'detail': 'Token is valid.'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Token is invalid or expired.'}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, uidb64, token):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            uid = smart_bytes(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and PasswordResetTokenGenerator().check_token(user, token):
            user.set_password(serializer.validated_data['password'])
            user.save()
            return Response({'detail': 'Password reset successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Token is invalid or expired.'}, status=status.HTTP_400_BAD_REQUEST)
