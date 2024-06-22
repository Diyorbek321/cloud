from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.contrib.auth.models import User, Group, Permission
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.views import View
from django.views.generic import TemplateView

from app.forms import CustomUserCreationForm, RoleCreationForm, PermissionForm


# Create your views here.
class AdminTemplateView(LoginRequiredMixin, View):
    allowed_groups = ['admin', 'customer', 'manager', 'sales', 'warehouse']

    def dispatch(self, request, *args, **kwargs):
        user_groups = request.user.groups.values_list('name', flat=True)
        # Check if the user is in the allowed group
        if not any(group in user_groups for group in self.allowed_groups):
            return HttpResponse('You are not authorized to view this page', status=403)

        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        return render(request, 'admin.html')


class UsersTemplateView(LoginRequiredMixin, View):
    allowed_groups = ['manager', 'admin']

    def dispatch(self, request, *args, **kwargs):
        user_groups = request.user.groups.values_list('name', flat=True)
        # Check if the user is in the allowed group
        if not any(group in user_groups for group in self.allowed_groups):
            return HttpResponse('You are not authorized to view this page', status=403)

        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        form = CustomUserCreationForm()
        return render(request, 'user_management.html', {'form': form})

    def post(self, request):
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            user_group = form.cleaned_data['group']
            user.groups.add(user_group)
            return redirect('user_list')  # Redirect to a user list or another page
        return render(request, 'user_management.html', {'form': form})


class UserListView(LoginRequiredMixin, View):
    allowed_groups = ['manager', 'admin']

    def dispatch(self, request, *args, **kwargs):
        user_groups = request.user.groups.values_list('name', flat=True)
        # Check if the user is in the allowed group
        if not any(group in user_groups for group in self.allowed_groups):
            return HttpResponse('You are not authorized to view this page', status=403)

        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        users = User.objects.all()
        return render(request, 'user_list.html', {'users': users})


class RolesTemplateView(LoginRequiredMixin, View):
    allowed_groups = ['customer', 'admin']

    def dispatch(self, request, *args, **kwargs):
        user_groups = request.user.groups.values_list('name', flat=True)
        # Check if the user is in the allowed group
        if not any(group in user_groups for group in self.allowed_groups):
            return HttpResponse('You are not authorized to view this page', status=403)

        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        form = RoleCreationForm()
        return render(request, 'roles.html', {'form': form})

    def post(self, request):
        form = RoleCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('role_list')  # Redirect to role list after successful creation
        return render(request, 'roles.html', {'form': form})


class RoleListView(LoginRequiredMixin, View):
    allowed_groups = ['customer', 'admin']

    def dispatch(self, request, *args, **kwargs):
        user_groups = request.user.groups.values_list('name', flat=True)
        # Check if the user is in the allowed group
        if not any(group in user_groups for group in self.allowed_groups):
            return HttpResponse('You are not authorized to view this page', status=403)

        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        roles = Group.objects.all()
        return render(request, 'role_list.html', {'roles': roles})


class PermissionsTemplateView(PermissionRequiredMixin, View):
    allowed_groups = ['admin']

    def dispatch(self, request, *args, **kwargs):
        user_groups = request.user.groups.values_list('name', flat=True)
        # Check if the user is in the allowed group
        if not any(group in user_groups for group in self.allowed_groups):
            return HttpResponse('You are not authorized to view this page', status=403)

        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        form = PermissionForm()
        return render(request, 'permissions.html', {'form': form})

    def post(self, request):
        form = PermissionForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('perm_list')  # Redirect to permission list after successful creation
        return render(request, 'permissions.html', {'form': form})


class PermissionListView(PermissionRequiredMixin, View):
    allowed_groups = ['admin']

    def dispatch(self, request, *args, **kwargs):
        user_groups = request.user.groups.values_list('name', flat=True)
        # Check if the user is in the allowed group
        if not any(group in user_groups for group in self.allowed_groups):
            return HttpResponse('You are not authorized to view this page', status=403)

        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        permissions = Permission.objects.all()
        return render(request, 'permission_lst.html', {'permissions': permissions})


class InventoryTemplateView(LoginRequiredMixin, View):
    allowed_groups = ['admin', 'manager', 'warehouse']

    def dispatch(self, request, *args, **kwargs):
        user_groups = request.user.groups.values_list('name', flat=True)
        # Check if the user is in the allowed group
        if not any(group in user_groups for group in self.allowed_groups):
            return HttpResponse('You are not authorized to view this page', status=403)

        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        form = RoleCreationForm()
        return render(request, 'inventory.html', {'form': form})

    def post(self, request):
        form = RoleCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('role_list')  # Redirect to role list after successful creation
        return render(request, 'inventory.html', {'form': form})


class SalesTemplateView(LoginRequiredMixin, View):
    allowed_groups = ['admin', 'manager', 'sales']

    def dispatch(self, request, *args, **kwargs):
        user_groups = request.user.groups.values_list('name', flat=True)
        # Check if the user is in the allowed group
        if not any(group in user_groups for group in self.allowed_groups):
            return HttpResponse('You are not authorized to view this page', status=403)

        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        form = RoleCreationForm()
        return render(request, 'sales.html', {'form': form})

    def post(self, request):
        form = RoleCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('role_list')  # Redirect to role list after successful creation
        return render(request, 'sales.html', {'form': form})


class CustomerTemplateView(LoginRequiredMixin, View):
    allowed_groups = ['admin', 'manager', 'customer']

    def dispatch(self, request, *args, **kwargs):
        user_groups = request.user.groups.values_list('name', flat=True)
        # Check if the user is in the allowed group
        if not any(group in user_groups for group in self.allowed_groups):
            return HttpResponse('You are not authorized to view this page', status=403)

        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        form = RoleCreationForm()
        return render(request, 'customer.html', {'form': form})

    def post(self, request):
        form = RoleCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('role_list')  # Redirect to role list after successful creation
        return render(request, 'customer.html', {'form': form})


class SettingsTemplateView(LoginRequiredMixin, View):
    allowed_groups = ['admin']

    def dispatch(self, request, *args, **kwargs):
        user_groups = request.user.groups.values_list('name', flat=True)
        # Check if the user is in the allowed group
        if not any(group in user_groups for group in self.allowed_groups):
            return HttpResponse('You are not authorized to view this page', status=403)

        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        form = RoleCreationForm()
        return render(request, 'settings.html', {'form': form})

    def post(self, request):
        form = RoleCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('role_list')  # Redirect to role list after successful creation
        return render(request, 'settings.html', {'form': form})


# @unauthenticated_user
class LoginTemplateView(View):
    def get(self, request):
        return render(request, 'login.html')

    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')
        # Perform authentication (use Django's built-in authentication system)
        # Example:
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('admin')
        else:
            return redirect('dashboard')  # Redirect to dashboard (for demo)


class CustomLogoutView(View):
    def get(self, request, *args, **kwargs):
        logout(request)
        return redirect('login')
