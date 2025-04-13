from django.shortcuts import render, redirect
from django.contrib.auth.models import User, Group
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.http import JsonResponse, HttpResponseForbidden
from django.template import loader


@login_required
def ver_dashboard(request):
    return render(request, 'dashboard/contador.html')


def es_admin(user):
    return user.groups.filter(name='admin').exists()


@login_required
@user_passes_test(es_admin)
def crear_usuario_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')
        grupo = request.POST.get('grupo')  # 'admin' o 'usuario'

        if username and password and grupo:
            user = User.objects.create_user(
                username=username,
                password=password,
                email=email
            )
            group = Group.objects.get(name=grupo)
            user.groups.add(group)
            user.save()

            return JsonResponse({"mensaje": "Usuario creado exitosamente", "usuario": username})

    return render(request, 'dashboard/crear_usuario.html')


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('ver_dashboard')
        else:
            messages.error(request, 'Credenciales inválidas.')

    return render(request, 'dashboard/login.html')


@login_required
def logout_view(request):
    logout(request)
    return redirect('login')


def csrf_error_view(request, reason=""):
    template = loader.get_template('403.html')
    return HttpResponseForbidden(template.render({}, request))
