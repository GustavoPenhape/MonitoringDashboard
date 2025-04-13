from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseForbidden
from django.template import loader
from django.conf import settings
from django.urls import reverse

from authlib.integrations.requests_client import OAuth2Session
import requests
import jwt

# Configuración de Cognito
CLIENT_ID = '1d06unmfrnjnsp6bv43a71db2g'
CLIENT_SECRET = '1iopej75sheeh91i0tdq0g2f11o190qubpniinfck2jv7mbu010q'
ISSUER = 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_B89KEuVRr'
AUTHORIZATION_ENDPOINT = f'{ISSUER}/.well-known/openid-configuration'

# Cargar metadata de Cognito
config = requests.get(AUTHORIZATION_ENDPOINT).json()
authorize_url = config["authorization_endpoint"]
token_url = config["token_endpoint"]
userinfo_url = config["userinfo_endpoint"]
jwks_uri = config["jwks_uri"]

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
    token = session.fetch_token(token_url, code=code)
    id_token = token.get('id_token')

    # Validar y decodificar token
    jwks = requests.get(jwks_uri).json()
    kid = jwt.get_unverified_header(id_token)['kid']
    key = next(k for k in jwks['keys'] if k['kid'] == kid)

    userinfo = jwt.decode(
        id_token,
        key=jwt.algorithms.RSAAlgorithm.from_jwk(key),
        audience=CLIENT_ID,
        issuer=ISSUER,
        algorithms=['RS256']
    )

    # Guardar datos mínimos en sesión
    request.session['user'] = {
        "email": userinfo.get("email"),
        "sub": userinfo.get("sub")
    }

    return redirect('ver_dashboard')


def logout_view(request):
    request.session.flush()
    logout_uri = (
        "https://us-east-1b89keuvrr.auth.us-east-1.amazoncognito.com/logout"
        "?client_id=1d06unmfrnjnsp6bv43a71db2g"
        f"&logout_uri={settings.REDIRECT_URI}"
    )
    return redirect(logout_uri)


def login_required_custom(view_func):
    def wrapper(request, *args, **kwargs):
        if 'user' not in request.session:
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper


@login_required_custom
def ver_dashboard(request):
    user_info = request.session.get('user')
    return render(request, 'dashboard/contador.html', {'user_info': user_info})


@login_required_custom
def dashboard_usuario(request):
    return render(request, 'dashboard/dashboard_usuario.html')


def csrf_error_view(request, reason=""):
    template = loader.get_template('403.html')
    return HttpResponseForbidden(template.render({}, request))
