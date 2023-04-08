from django.contrib.auth import get_user_model
from django.contrib.auth.forms import SetPasswordForm
from django.utils.http import urlsafe_base64_decode
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'firstname', 'lastname', 'pseudo', 'password']
        extra_kwargs = {
            'password': {
                'write_only': True,
                'required': True  # ajout de la clé "required"
            }
        }

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user


class UpdateUserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'firstname', 'lastname', 'pseudo']


class ChangePasswordSerializer(serializers.Serializer):
    model = User

    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError('No user with that email address.')
        return value


class PasswordConfirmResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=128, write_only=True)

    def validate_password(self, value):
        # Vérifiez ici que le mot de passe répond à vos critères de complexité
        return value
