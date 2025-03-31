import boto3

# Crear el cliente DynamoDB
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
tabla = dynamodb.Table('LecturasRFID')

# Escanear todos los elementos
response = tabla.scan()
items = response['Items']

print("📦 Datos encontrados:")
for item in items:
    print(item)
