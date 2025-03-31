import paho.mqtt.client as mqtt
import time
import json
from datetime import datetime
import random

DISPOSITIVO_ID = "1"  # Este será el segundo dispositivo
BROKER = "a39ib3frk2ykd9-ats.iot.us-east-1.amazonaws.com"
PORT = 8883
TOPIC = "rfid/lecturas"

CA_CERT = "certs/AmazonRootCA1.pem"
CERT_FILE = "certs/certificate.pem.crt"
KEY_FILE = "certs/private.pem.key"

client = mqtt.Client(client_id="Dispositivo1-Test")
client.tls_set(CA_CERT, certfile=CERT_FILE, keyfile=KEY_FILE)
client.connect(BROKER, PORT, 60)
client.loop_start()

print("📡 Dispositivo 1 enviando datos 30 veces...")

try:
    for i in range(30):  # Repite 30 veces
        timestamp = datetime.now().isoformat()
        id_tarjeta = f"ID-{random.randint(100000, 999999)}"

        mensaje = {
            "dispositivo": f"dispositivo_{DISPOSITIVO_ID}",
            "id_tarjeta": id_tarjeta,
            "hora": timestamp
        }

        result = client.publish(TOPIC, json.dumps(mensaje), qos=1)
        result.wait_for_publish()
        print(f"✅ Dispositivo 1 - Mensaje enviado: {mensaje}")
        time.sleep(2)  # Espera 3 segundos antes de enviar el siguiente mensaje

except KeyboardInterrupt:
    print("🛑 Dispositivo 1 detenido por el usuario.")

finally:
    client.loop_stop()
    client.disconnect()
