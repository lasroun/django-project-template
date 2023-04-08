from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

User = get_user_model()


class UserAdmin(BaseUserAdmin):
    # Les champs à utiliser pour afficher le modèle User.
    # Celles-ci remplacent les définitions de la baseUserAdmin
    # qui font référence à des champs spécifiques sur auth.User.
    list_display = ['email']
    list_filter = ['is_staff', 'pseudo']
    fieldsets = (
        ('Account info', {'fields': ('pseudo',)}),
        (
            'Personal info',
            {'fields': ('email', 'firstname', 'lastname', 'email_confirmed', 'created_at', 'last_login')}),
        ('Password', {'fields': ('password',)}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
    )
    readonly_fields = ('created_at',)
    # add_fieldsets n'est pas un attribut ModelAdmin standard. UtilisateurAdmin
    # remplace get_fieldsets pour utiliser cet attribut lors de la création d'un utilisateur.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'firstname', 'lastname', 'password', 'password_2')}
         ),
    )
    search_fields = ['email', 'pseudo']
    ordering = ['email']
    filter_horizontal = ()


admin.site.register(User, UserAdmin)
