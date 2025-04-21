from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseForbidden
from django.template import loader
from django.conf import settings
from django.urls import reverse
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json
from boto3.dynamodb.conditions import Key
from datetime import datetime
import json
import logging
import boto3
logger = logging.getLogger(__name__)


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
            print("❌ Usuario no autenticado. Redirigiendo a login.")
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper

def group_required(required_group):
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            user = request.session.get('user')
            print("🧪 Usuario actual:", user)  # <- agrega esto temporalmente
            if not user or required_group not in user.get("groups", []):
                print("🚫 Grupo no autorizado:", user.get("groups", []))
                return HttpResponseForbidden("Acceso denegado.")
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

@login_required_custom
def redireccion_por_grupo(request):
    user = request.session.get('user')
    grupos = user.get("groups", [])

    if "admin" in grupos:
        return redirect('ver_dashboard')
    elif "users" in grupos:
        return redirect('dashboard_usuario')
    else:
        return HttpResponseForbidden("No tienes un grupo válido.")

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

@login_required_custom
@group_required("users")
def validar_asistencia(request):
    import boto3
    if request.method == 'POST':
        dni = request.POST.get('dni')
        if not dni:
            messages.error(request, "⚠️ Debes ingresar un DNI.")
            return redirect('validar_asistencia')

        # Buscar en DynamoDB
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')  # cambia la región si es necesario
        tabla = dynamodb.Table('NombreDeTuTabla')  # reemplaza con tu nombre real

        try:
            response = tabla.get_item(Key={'dni': dni})
            if 'Item' in response:
                messages.success(request, f"✅ Asistencia validada para {dni}.")
            else:
                messages.error(request, f"❌ DNI {dni} no encontrado.")
        except Exception as e:
            messages.error(request, f"❌ Error consultando la base: {str(e)}")

        return redirect('validar_asistencia')

    return render(request, 'dashboard/validar_asistencia_form.html')
@login_required_custom
@group_required("users")
def ver_tabla_dynamo(request):
    import boto3

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    tabla = dynamodb.Table('LecturasRFID')  # 🔁 Reemplaza por el nombre real

    try:
        response = tabla.scan()
        items = response.get('Items', [])
    except Exception as e:
        items = []
        messages.error(request, f"❌ Error al obtener datos de DynamoDB: {str(e)}")

    return render(request, 'dashboard/ver_tabla_dynamo.html', {'items': items})

# Vista corregida para mostrar todos los datos primero
@login_required_custom
@group_required("users")
def ver_usuarios_activos(request):
    import boto3

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    tabla = dynamodb.Table('HistorialAsociaciones')

    try:
        response = tabla.scan()
        all_items = response.get("Items", [])

        # Filtrar: solo aquellos sin fecha_devolucion (es decir, tarjeta aún activa)
        items = [item for item in all_items if "fecha_devolucion" not in item or not item["fecha_devolucion"]]

    except Exception as e:
        items = []
        messages.error(request, f"❌ Error al consultar DynamoDB: {str(e)}")

    return render(request, "dashboard/usuarios_activos.html", {"items": items})

@csrf_exempt
def desvincular_rfid(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido'}, status=405)

    data = json.loads(request.body)
    id_tarjeta = data.get('id_tarjeta')

    if not id_tarjeta:
        return JsonResponse({'error': 'Falta id_tarjeta'}, status=400)

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    tabla = dynamodb.Table('HistorialAsociaciones')

    try:
        response = tabla.query(
            KeyConditionExpression=Key('id_tarjeta').eq(id_tarjeta)
        )
    except Exception as e:
        return JsonResponse({'error': f'Error al consultar DynamoDB: {str(e)}'}, status=500)

    registros = response.get('Items', [])

    if not registros:
        return JsonResponse({'error': 'La tarjeta no existe en el sistema'}, status=404)

    # Buscar el uso activo (sin fecha_devolucion y no bloqueado)
    activos = [
        r for r in registros
        if not r.get('fecha_devolucion') and r.get('estado_tarjeta') != 'bloqueado'
    ]

    if activos:
        # Tomar el más reciente y marcarlo como devuelto
        uso_activo = sorted(activos, key=lambda x: x['fecha_asignacion'], reverse=True)[0]
        try:
            now = datetime.utcnow().isoformat()
            tabla.update_item(
                Key={
                    'id_tarjeta': uso_activo['id_tarjeta'],
                    'fecha_asignacion': uso_activo['fecha_asignacion']
                },
                UpdateExpression="SET fecha_devolucion = :fd",
                ExpressionAttributeValues={
                    ':fd': now
                }
            )
            return JsonResponse({
                'status': 'ok',
                'fecha_devolucion': now,
                'mensaje': 'Tarjeta desvinculada correctamente.',
                'usuario': uso_activo.get('nombre', 'Desconocido')
            })
        except Exception as e:
            return JsonResponse({'error': f'Error al actualizar: {str(e)}'}, status=500)

    # ⚠️ Si no hay activos, verificar si hay un registro bloqueado
    bloqueadas = [
        r for r in registros
        if not r.get('fecha_devolucion') and r.get('estado_tarjeta') == 'bloqueado'
    ]

    if bloqueadas:
        bloqueada = bloqueadas[0]
        return JsonResponse({
            'error': 'La tarjeta está bloqueada y no puede ser usada.',
            'usuario': bloqueada.get('nombre', 'Desconocido')
        }, status=403)

    # Si no hay activos ni bloqueadas, es porque ya fue devuelta
    registro_reciente = sorted(registros, key=lambda x: x['fecha_asignacion'], reverse=True)[0]

    return JsonResponse({
        'status': 'ok',
        'mensaje': 'La tarjeta ya fue devuelta anteriormente.',
        'fecha_devolucion': registro_reciente.get('fecha_devolucion'),
        'usuario': registro_reciente.get('nombre', 'Desconocido')
    })
# === Vistas protegidas ===

@login_required_custom
@group_required("admin")
def ver_dashboard(request):
    user_info = request.session.get('user')
    if not user_info:
        return redirect('login')  # seguridad doble por si acaso
    return render(request, 'dashboard/contador.html', {'user_info': user_info})

@login_required_custom
@group_required("users")
def dashboard_usuario(request):
    user_info = request.session.get('user')
    return render(request, 'dashboard/dashboard_usuario.html', {'user_info': user_info})

def csrf_error_view(request, reason=""):
    template = loader.get_template('403.html')
    return HttpResponseForbidden(template.render({}, request))
