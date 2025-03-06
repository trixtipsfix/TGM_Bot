import asyncio
import re
from telethon import TelegramClient, events
from key_manager import load_keys, save_keys, get_hwid
from datetime import datetime
import os
import json
import sys

# Expresión regular para validar cadenas de 44 caracteres alfanuméricos
PATTERN_44 = re.compile(r'[A-Za-z0-9]{44}')

# Variables globales
CHATS_ORIGEN = []
CHAT_DESTINO = None
API_ID = 5541799
API_HASH = "f3649a2f0c535be7493b495aa4490430"
RETRASO_ENVIO = 0  # Inicialmente sin retraso

def validate_and_associate_key(key):
    """
    Valida la key antes de iniciar el bot y asocia el HWID al sistema si es válido.
    """
    keys_data = load_keys()
    key_data = keys_data.get(key)

    if not key_data:
        print("[ERROR]: La KEY no se encontró.")
        return False

    expiration_date_str = key_data.get("expiration")
    if expiration_date_str:
        expiration_date = datetime.strptime(expiration_date_str, "%Y-%m-%d")
        current_date = datetime.now()

        if current_date > expiration_date:
            print("[ERROR]: La clave de licencia ha caducado.")
            return False

        # Calcular días restantes
        days_left = (expiration_date - current_date).days
        if days_left <= 5:
            print(f"[ADVERTENCIA]: Tu clave expira en {days_left} días. Considera renovarla pronto.")

    if key_data.get("status") != "active":
        print("[ERROR]: La clave no está activa.")
        return False

    current_hwid = get_hwid()
    if not current_hwid:
        print("[ERROR]: No se pudo obtener un HWID válido. Bloqueando el acceso.")
        sys.exit(1)

    if not key_data.get("hwid"):
        key_data["hwid"] = current_hwid
        save_keys(keys_data)
        print(f"[INFO]: HWID asociado correctamente: {current_hwid}")
    elif key_data["hwid"] != current_hwid:
        print("[ERROR]: La clave ya está asociada a otro sistema.")
        sys.exit(1)

    # Establecer el retraso según el tipo de clave
    global RETRASO_ENVIO
    key_type = key_data.get("type", "normal").lower()
    if key_type == "normal":
        RETRASO_ENVIO = 1.2
    elif key_type == "premium":
        RETRASO_ENVIO = 0.7
    elif key_type == "titanium":
        RETRASO_ENVIO = 0
    else:
        RETRASO_ENVIO = 1.2  # Por defecto, 1.2 segundos para claves no especificadas

    print(f"[INFO]: Tipo de clave: {key_type}")
    return True

def prompt_and_save_user_config(user_folder):
    """
    Pide al usuario los datos de API_ID y API_HASH, y los guarda en el archivo config.json.
    """
    print("[INFO]: Configuración inicial requerida.")
    api_id = input("Por favor, introduce tu API_ID: ")
    api_hash = input("Por favor, introduce tu API_HASH: ")

    config = {
        "api_id": api_id,
        "api_hash": api_hash,
        "chats_origen": [],
        "chat_destino": None
    }

    os.makedirs(user_folder, exist_ok=True)
    with open(os.path.join(user_folder, "config.json"), "w") as file:
        json.dump(config, file, indent=4)

    return config

async def get_user_chats(client):
    """
    Obtiene la lista de chats disponibles del usuario.
    """
    print("[INFO]: Obteniendo lista de chats activos...")
    dialogs = await client.get_dialogs()

    chats = []
    for i, dialog in enumerate(dialogs, 1):
        chats.append({"id": dialog.id, "name": dialog.name or "Sin Nombre"})
        print(f"{i}. {dialog.name or 'Sin Nombre'} (ID: {dialog.id})")

    return chats

async def select_chats(client, user_folder):
    """
    Permite al usuario seleccionar los chats de origen y destino.
    """
    chats = await get_user_chats(client)

    print("[INFO]: Selecciona los chats de origen (puedes seleccionar varios, separados por comas):")
    origen_indices = input("Introduce los números de los chats de origen: ").split(",")
    chats_origen = [chats[int(i) - 1]["id"] for i in origen_indices if i.isdigit() and int(i) <= len(chats)]

    print("[INFO]: Selecciona el chat de destino (solo uno):")
    destino_index = int(input("Introduce el número del chat de destino: "))
    chat_destino = chats[destino_index - 1]["id"]

    config_path = os.path.join(user_folder, "config.json")
    with open(config_path, "r") as file:
        config = json.load(file)

    config["chats_origen"] = chats_origen
    config["chat_destino"] = chat_destino

    with open(config_path, "w") as file:
        json.dump(config, file, indent=4)

    print("[INFO]: Configuración guardada correctamente.")

async def main():
    global CHATS_ORIGEN, CHAT_DESTINO, API_ID, API_HASH

    print("[INFO]: Iniciando el sistema...")
    key = input("Por favor, introduce tu KEY: ")

    try:
        if not validate_and_associate_key(key):
            print("[ERROR]: La KEY no es válida o está caducada. Saliendo...")
            return

        user_folder = f"./configs/{key}"
        print(f"[INFO]: Carpeta del usuario configurada en {user_folder}")

        user_config = None
        config_path = os.path.join(user_folder, "config.json")
        if os.path.exists(config_path):
            with open(config_path, "r") as file:
                user_config = json.load(file)

        if not user_config or not user_config.get("api_id") or not user_config.get("api_hash"):
            user_config = prompt_and_save_user_config(user_folder)

        API_ID = user_config.get("api_id")
        API_HASH = user_config.get("api_hash")
        CHATS_ORIGEN = user_config.get("chats_origen", [])
        CHAT_DESTINO = user_config.get("chat_destino")

        async with TelegramClient(os.path.join(user_folder, "session_name"), API_ID, API_HASH) as client:
            print("[INFO]: Cliente de Telegram iniciado correctamente.")

            await select_chats(client, user_folder)

            with open(config_path, "r") as file:
                user_config = json.load(file)
            CHATS_ORIGEN = user_config.get("chats_origen", [])
            CHAT_DESTINO = user_config.get("chat_destino")

            @client.on(events.NewMessage(chats=CHATS_ORIGEN))
            async def forward_message(event):
                try:
                    message_text = event.message.message
                    if PATTERN_44.search(message_text):  # Validar mensaje con búsqueda parcial
                        await asyncio.sleep(RETRASO_ENVIO)  # Aplicar retraso
                        await client.send_message(CHAT_DESTINO, message_text)
                        print(f"[INFO]: Mensaje reenviado.")
                    else:
                        print(f"[INFO]: Mensaje ignorado.")
                except Exception as e:
                    print(f"[ERROR]: Error al reenviar el mensaje: {e}")

            print("[INFO]: Bot iniciado correctamente y escuchando mensajes...")
            await client.run_until_disconnected()
    except Exception as e:
        print(f"[ERROR]: Ocurrió un error: {e}")
    finally:
        print("[INFO]: Presiona ENTER para salir...")
        input()

if __name__ == "__main__":
    asyncio.run(main())
