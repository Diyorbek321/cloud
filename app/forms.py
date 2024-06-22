from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User, Permission
from django.contrib.auth.models import Group


class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    group = forms.ModelChoiceField(queryset=Group.objects.all(), required=True)

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2", "group")


class RoleCreationForm(forms.ModelForm):
    class Meta:
        model = Group
        fields = ['name']


class PermissionForm(forms.ModelForm):
    class Meta:
        model = Permission
        fields = ['name', 'content_type', 'codename']
