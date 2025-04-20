from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseForbidden
from django.template import loader
from django.conf import settings
from django.urls import reverse

from authlib.integrations.requests_client import OAuth2Session
import requests
import jwt

# === Configuración de Cognito ===
CLIENT_ID = '1d06unmfrnjnsp6bv43a71db2g'
CLIENT_SECRET = '1iopej75sheeh91i0tdq0g2f11o190qubpniinfck2jv7mbu010q'
ISSUER = 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_B89KEuVRr'
AUTHORIZATION_ENDPOINT = f'{ISSUER}/.well-known/openid-configuration'

# Cargar metadata
config = requests.get(AUTHORIZATION_ENDPOINT).json()
authorize_url = config["authorization_endpoint"]
token_url = config["token_endpoint"]
userinfo_url = config["userinfo_endpoint"]
jwks_uri = config["jwks_uri"]

# === Decoradores personalizados ===

def login_required_custom(view_func):
    def wrapper(request, *args, **kwargs):
        if 'user' not in request.session:
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper

def group_required(required_group):
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            user = request.session.get('user')
            if not user or required_group not in user.get("groups", []):
                return HttpResponseForbidden("Acceso denegado.")
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

# === Vistas ===

def login_view(request):
    redirect_uri = settings.REDIRECT_URI
    session = OAuth2Session(CLIENT_ID, CLIENT_SECRET, scope='openid email', redirect_uri=redirect_uri)
    uri, _ = session.create_authorization_url(authorize_url)
    return redirect(uri)

def authorize_view(request):
    code = request.GET.get('code')
    if not code:
        return redirect('login')

    redirect_uri = settings.REDIRECT_URI
    session = OAuth2Session(CLIENT_ID, CLIENT_SECRET, scope='openid email', redirect_uri=redirect_uri)
    
    try:
        token = session.fetch_token(token_url, code=code)
        id_token = token.get('id_token')
    except Exception as e:
        print("❌ Error al obtener el token:", str(e))
        return redirect('login')

    try:
        # Obtener la clave pública (JWKS) de Cognito
        jwks = requests.get(jwks_uri).json()
        kid = jwt.get_unverified_header(id_token)['kid']
        key = next(k for k in jwks['keys'] if k['kid'] == kid)

        # Decodificar y verificar el token
        userinfo = jwt.decode(
            id_token,
            key=jwt.algorithms.RSAAlgorithm.from_jwk(key),
            audience=CLIENT_ID,
            issuer=ISSUER,
            algorithms=['RS256']
        )

        print("👤 Usuario:", userinfo.get("email"))
        print("🔐 Grupos del token:", userinfo.get("cognito:groups", []))

        # ✅ Guardar token y usuario en sesión
        request.session['id_token'] = id_token
        request.session['user'] = {
            "email": userinfo.get("email"),
            "sub": userinfo.get("sub"),
            "groups": userinfo.get("cognito:groups", [])
        }

        # 🔀 Redirigir según grupo
        groups = userinfo.get("cognito:groups", [])
        if "admin" in groups:
            return redirect('ver_dashboard')
        elif "users" in groups:
            return redirect('dashboard_usuario')
        else:
            return redirect('login')

    except Exception as e:
        print("❌ Error al validar token:", str(e))
        return redirect('login')
def logout_view(request):
    request.session.flush()
    logout_uri = (
        "https://us-east-1b89keuvrr.auth.us-east-1.amazoncognito.com/logout"
        "?client_id=1d06unmfrnjnsp6bv43a71db2g"
        f"&logout_uri={settings.REDIRECT_URI}"
    )
    return redirect(logout_uri)

# === Vistas protegidas ===

@login_required_custom
@group_required("admin")
def ver_dashboard(request):
    user_info = request.session.get('user')
    return render(request, 'dashboard/contador.html', {'user_info': user_info})

@login_required_custom
@group_required("users")
def dashboard_usuario(request):
    user_info = request.session.get('user')
    return render(request, 'dashboard/dashboard_usuario.html', {'user_info': user_info})

def csrf_error_view(request, reason=""):
    template = loader.get_template('403.html')
    return HttpResponseForbidden(template.render({}, request))
