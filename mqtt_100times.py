import paho.mqtt.client as mqtt
import json
from datetime import datetime
import random

# Configurar MQTT
BROKER = "a39ib3frk2ykd9-ats.iot.us-east-1.amazonaws.com"
PORT = 8883
TOPIC = "rfid/lecturas"

CA_CERT = "certs/AmazonRootCA1.pem"
CERT_FILE = "certs/certificate.pem.crt"
KEY_FILE = "certs/private.pem.key"

client = mqtt.Client(client_id="CargaMasivaTest")
client.tls_set(CA_CERT, certfile=CERT_FILE, keyfile=KEY_FILE)
client.connect(BROKER, PORT, 60)
client.loop_start()

print("🚀 Enviando 100 mensajes sin detenerse...")

for i in range(100):
    timestamp = datetime.now().isoformat()
    id_tarjeta = f"ID-{random.randint(100000, 999999)}"

    mensaje = {
        "dispositivo": "VisualStudioCode",
        "id_tarjeta": id_tarjeta,
        "hora": timestamp
    }

    result = client.publish(TOPIC, json.dumps(mensaje), qos=1)
    result.wait_for_publish()
    print(f"✅ {i+1}/100 enviado: {id_tarjeta}")

client.loop_stop()
client.disconnect()

print("✅ Todos los mensajes enviados.")
