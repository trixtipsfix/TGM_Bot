import json
import os
from datetime import datetime, timedelta
import random
import string
import platform
import hashlib

KEYS_FILE = "keys.json"  # Archivo donde están guardadas las KEYS


def load_keys():
    """
    Carga las KEYS desde el archivo keys.json.
    """
    try:
        with open(KEYS_FILE, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}


def save_keys(keys_data):
    """
    Guarda las KEYS en el archivo keys.json.
    """
    with open(KEYS_FILE, "w") as file:
        json.dump(keys_data, file, indent=4)


def get_hwid():
    """
    Obtiene un identificador único para el sistema (HWID).
    """
    system_info = f"{platform.node()}-{platform.system()}-{platform.release()}-{platform.processor()}"
    hwid = hashlib.sha256(system_info.encode()).hexdigest()
    return hwid


def generate_new_key():
    """
    Genera una nueva KEY automáticamente con una longitud de 8 caracteres (letras y números).
    """
    new_key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    keys_data = dict()

    try:
        valid_days = int(input("Introduce cuántos días de validez tendrá esta clave: "))
    except ValueError:
        print("[ERROR]: Por favor, ingresa un número válido de días.")
        return

    print("\nSelecciona el tipo de clave:")
    print("1. Normal")
    print("2. Premium")
    print("3. Titanium")
    key_type = input("Introduce el número correspondiente al tipo de clave: ")

    if key_type == "1":
        key_type = "normal"
    elif key_type == "2":
        key_type = "premium"
    elif key_type == "3":
        key_type = "titanium"
    else:
        print("[ERROR]: Tipo de clave no válido. Se usará 'normal' por defecto.")
        key_type = "normal"

    expiration_date = datetime.now() + timedelta(days=valid_days)

    keys_data[new_key] = {
        "status": "active",
        "expiration": expiration_date.strftime("%Y-%m-%d"),
        "user": "Nuevo Usuario",
        "hwid": None,  # Se asignará automáticamente al primer uso
        "type": key_type
    }

    save_keys(keys_data)
    print(f"[INFO]: Se ha generado una nueva clave: {new_key}, válida hasta {expiration_date.strftime('%Y-%m-%d')} (Tipo: {key_type.capitalize()})")
    return new_key


def associate_hwid_to_key(key):
    """
    Valida la clave y asocia un HWID al sistema si es válido.
    """
    keys_data = load_keys()

    if key not in keys_data:
        print("[ERROR]: La clave no existe.")
        return False

    key_data = keys_data[key]
    hwid = get_hwid()

    if key_data["hwid"] is None:
        key_data["hwid"] = hwid
        save_keys(keys_data)
        print(f"[INFO]: HWID asociado correctamente: {hwid}")
        return True
    elif key_data["hwid"] == hwid:
        print("[INFO]: HWID verificado correctamente.")
        return True
    else:
        print("[ERROR]: La clave ya está asociada a otro sistema.")
        return False


def renew_key():
    """
    Renueva una clave caducada seleccionada actualizando su fecha de expiración.
    """
    keys_data = load_keys()

    if not keys_data:
        print("[INFO]: No hay claves disponibles para renovar.")
        return

    print("[INFO]: Lista de claves disponibles para renovar:")
    for idx, key in enumerate(keys_data.keys(), 1):
        print(f"{idx}. Clave: {key} | Expiración: {keys_data[key].get('expiration')} | Estado: {keys_data[key].get('status')}")

    try:
        key_idx = int(input("Introduce el número de la clave que deseas renovar: "))
        key_to_renew = list(keys_data.keys())[key_idx - 1]
        valid_days = int(input("Introduce cuántos días adicionales deseas añadir a la expiración de esta clave: "))

        current_expiration = datetime.strptime(keys_data[key_to_renew]["expiration"], "%Y-%m-%d")
        new_expiration_date = current_expiration + timedelta(days=valid_days)

        keys_data[key_to_renew]["expiration"] = new_expiration_date.strftime("%Y-%m-%d")
        keys_data[key_to_renew]["status"] = "active"

        save_keys(keys_data)
        print(f"[INFO]: La clave {key_to_renew} ha sido renovada exitosamente. Nueva fecha de expiración: {new_expiration_date.strftime('%Y-%m-%d')}")

    except (ValueError, IndexError):
        print("[ERROR]: Opción no válida.")


def delete_key():
    """
    Elimina una clave seleccionada.
    """
    keys_data = load_keys()

    if not keys_data:
        print("[INFO]: No hay claves disponibles para eliminar.")
        return

    print("[INFO]: Lista de claves disponibles para eliminar:")
    for idx, key in enumerate(keys_data.keys(), 1):
        print(f"{idx}. Clave: {key} | Expiración: {keys_data[key].get('expiration')} | Estado: {keys_data[key].get('status')}")

    try:
        key_idx = int(input("Introduce el número de la clave que deseas eliminar: "))
        key_to_delete = list(keys_data.keys())[key_idx - 1]

        del keys_data[key_to_delete]
        save_keys(keys_data)
        print(f"[INFO]: La clave {key_to_delete} ha sido eliminada exitosamente.")

    except (ValueError, IndexError):
        print("[ERROR]: Opción no válida.")


def reset_hwid():
    """
    Permite resetear el HWID de una clave específica.
    """
    keys_data = load_keys()

    if not keys_data:
        print("[INFO]: No hay claves disponibles para resetear HWID.")
        return

    print("[INFO]: Lista de claves con HWID registrado:")
    for idx, key in enumerate(keys_data.keys(), 1):
        hwid = keys_data[key].get("hwid", "No asignado")
        print(f"{idx}. Clave: {key} | Expiración: {keys_data[key].get('expiration')} | HWID: {hwid}")

    try:
        key_idx = int(input("Introduce el número de la clave cuyo HWID deseas resetear: "))
        key_to_reset = list(keys_data.keys())[key_idx - 1]

        keys_data[key_to_reset]["hwid"] = None
        save_keys(keys_data)
        print(f"[INFO]: Se ha reseteado el HWID de la clave {key_to_reset}. Ahora puede registrarse en un nuevo dispositivo.")

    except (ValueError, IndexError):
        print("[ERROR]: Opción no válida.")


if __name__ == "__main__":
    while True:
        print("\nGestor de KEYS:")
        print("1. Crear nueva KEY")
        print("2. Listar KEYS")
        print("3. Renovar clave")
        print("4. Eliminar clave")
        print("5. Resetear HWID")
        print("6. Salir")

        try:
            option = input("Selecciona una opción: ")

            if option == "1":
                generate_new_key()

            elif option == "2":
                keys_data = load_keys()
                if keys_data:
                    print("\n[INFO]: Lista de KEYS:")
                    for k, v in keys_data.items():
                        expiration = v.get("expiration")
                        status = v.get("status", "unknown")
                        hwid = v.get("hwid", "No asignado")
                        key_type = v.get("type", "normal")
                        days_left = (datetime.strptime(expiration, "%Y-%m-%d") - datetime.now()).days if expiration else "Desconocido"

                        warning = f" [ADVERTENCIA: {days_left} días restantes]" if days_left != "Desconocido" and days_left <= 5 else ""
                        print(f" - {k} | Expiración: {expiration} | Estado: {status} | HWID: {hwid} | Tipo: {key_type.capitalize()}{warning}")
                else:
                    print("[INFO]: No hay claves registradas.")

            elif option == "3":
                renew_key()

            elif option == "4":
                delete_key()

            elif option == "5":
                reset_hwid()

            elif option == "6":
                print("[INFO]: Saliendo del gestor de claves...")
                break

            else:
                print("[ERROR]: Opción no válida.")

        except Exception as e:
            print(f"[ERROR]: {e}")
