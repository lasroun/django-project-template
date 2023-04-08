from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin, Group, Permission


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must be email')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(verbose_name='email address', max_length=100, unique=True, )
    firstname = models.CharField(verbose_name='First Name', max_length=60)
    lastname = models.CharField(verbose_name='Last Name', max_length=60)
    email_confirmed = models.BooleanField(default=False)
    email_confirmation_sent_at = models.DateTimeField(null=True, blank=True)

    pseudo = models.CharField(verbose_name='Pseudo', max_length=60, unique=True)
    password = models.CharField("password", max_length=128)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    groups = models.ManyToManyField(Group, verbose_name="groups", blank=True)
    user_permissions = models.ManyToManyField(Permission, verbose_name="user permissions", blank=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['firstname', 'lastname', 'pseudo']

    def __str__(self):
        return self.email

    objects = UserManager()
