import os
import re
import json
import bcrypt
import platform
from time import time, sleep
from shutil import get_terminal_size
from hashlib import md5, sha1, sha256, sha512

CARPETA_ENTRADA = "entrada/"
CARPETA_SALIDA = "salida/"

lista_contraseñas = []
RESULTADO = None
contador_exitos = 0
contador_fallos = 0


def limpiar_pantalla():
    os.system('cls' if platform.system() == 'Windows' else 'clear')


def obtener_hash_salt(contenido: str) -> tuple:
    if contenido is None:
        return (None, None)

    if len(contenido) == 32 and all(c in '0123456789abcdef' for c in contenido):
        return (contenido, None)

    if contenido.startswith('SHA512$'):
        partes = contenido.split('$')
        if len(partes) == 3:
            return (partes[2], partes[1])

    elif contenido.startswith('SHA256$'):
        partes = contenido.split('$')
        if len(partes) == 3:
            return (partes[2], partes[1])

    if contenido.startswith('$SHA512$'):
        partes = contenido.split('$')
        if len(partes) == 4:
            return (partes[2], partes[3])

    elif contenido.startswith('$SHA256$'):
        partes = contenido.split('$')
        if len(partes) == 4:
            return (partes[2], partes[3])

    elif contenido.startswith('$SHA512$'):
        partes = contenido.split('@')
        if len(partes) == 2:
            parte_hash = partes[0].split('$')[2]
            parte_salt = partes[1]
            return (parte_hash, parte_salt)

    if contenido.startswith('$SHA256$'):
        partes = contenido.split('@')
        if len(partes) == 2:
            parte_hash = partes[0].split('$')[2]
            parte_salt = partes[1]
            return (parte_hash, parte_salt)

    if contenido.startswith('$2b$') or contenido.startswith('$2a$') or contenido.startswith('$2y$'):
        partes = contenido.split('$')
        if len(partes) >= 4:
            hash_y_salt = '$'.join(partes[:4])
            return (hash_y_salt, None)

    if '$' in contenido:
        resultado = re.findall("[^$SHA]\w{31,127}", contenido)
        if resultado:
            if len(resultado) > 1:
                seleccionado = (resultado[1], resultado[0]) if len(resultado[1]) > len(resultado[0]) else (resultado[0], resultado[1])
                return seleccionado

            divididos = re.findall("[^$SHA]\w+", contenido)
            salt = ''.join(x for x in divididos if x != resultado[0])
            return (resultado[0], salt if salt else None)

        return (None, None)

    elif ':' in contenido:
        partes = contenido.split(':')
        seleccionado = (partes[0], partes[1]) if len(partes[0]) > len(partes[1]) else (partes[1], partes[0])
        return seleccionado

    for longitud in [40, 64, 128]:
        if len(contenido) == longitud and all(c in '0123456789abcdef' for c in contenido):
            return (contenido, None)

    return (None, None)


def cargar_diccionario(archivo: str):
    global lista_contraseñas
    with open(archivo, 'r', encoding='latin-1') as f:
        lista_contraseñas = [linea.strip() for linea in f]


def iniciar_fuerza_bruta(contraseña: str, hash_str: str, salt: str or None = None):
    global RESULTADO
    longitud_hash = len(hash_str)

    if hash_str.startswith('$2a$') or hash_str.startswith('$2b$') or hash_str.startswith('$2y$'):
        if bcrypt.checkpw(contraseña.encode(), hash_str.encode()):
            RESULTADO = contraseña
        return

    if longitud_hash == 32:
        if salt:
            if (md5(contraseña.encode() + salt.encode()).hexdigest() == hash_str or
                md5(salt.encode() + contraseña.encode()).hexdigest() == hash_str or
                md5(md5(contraseña.encode()).hexdigest().encode() + salt.encode()).hexdigest() == hash_str):
                RESULTADO = contraseña
        else:
            if md5(contraseña.encode()).hexdigest() == hash_str:
                RESULTADO = contraseña

    elif longitud_hash == 40:
        if salt:
            if (sha1(contraseña.encode() + salt.encode()).hexdigest() == hash_str or
                sha1(salt.encode() + contraseña.encode()).hexdigest() == hash_str or
                sha1(sha1(contraseña.encode()).hexdigest().encode() + salt.encode()).hexdigest() == hash_str):
                RESULTADO = contraseña
        else:
            if sha1(contraseña.encode()).hexdigest() == hash_str:
                RESULTADO = contraseña

    elif longitud_hash == 64:
        if salt:
            if (sha256(contraseña.encode() + salt.encode()).hexdigest() == hash_str or
                sha256(salt.encode() + contraseña.encode()).hexdigest() == hash_str or
                sha256(sha256(contraseña.encode()).hexdigest().encode() + salt.encode()).hexdigest() == hash_str):
                RESULTADO = contraseña
        else:
            if sha256(contraseña.encode()).hexdigest() == hash_str:
                RESULTADO = contraseña

    elif longitud_hash == 128:
        if salt:
            if (sha512(contraseña.encode() + salt.encode()).hexdigest() == hash_str or
                sha512(salt.encode() + contraseña.encode()).hexdigest() == hash_str or
                sha512(sha512(contraseña.encode()).hexdigest().encode() + salt.encode()).hexdigest() == hash_str):
                RESULTADO = contraseña
        else:
            if sha512(contraseña.encode()).hexdigest() == hash_str:
                RESULTADO = contraseña


def fuerza_bruta(hash_str: str, salt: str):
    global RESULTADO
    RESULTADO = None
    if hash_str is None:
        return None
    for contraseña in lista_contraseñas:
        if RESULTADO is not None:
            break
        iniciar_fuerza_bruta(contraseña, hash_str, salt)
    return RESULTADO


def cargar_hashes_json(archivo_entrada):
    with open(archivo_entrada, 'r', encoding='utf-8') as f:
        return json.load(f)


def guardar_resultados(resultados, archivo_salida):
    with open(archivo_salida, 'w', encoding='utf-8') as f:
        json.dump(resultados, f, indent=4)


def barra_progreso(actual, total, exitosos, fallidos, tiempo_inicio):
    ancho_terminal = get_terminal_size().columns
    longitud_barra = ancho_terminal - 75
    largo_llenado = int(longitud_barra * actual // total)
    barra = '=' * largo_llenado + '-' * (longitud_barra - largo_llenado)
    porcentaje = (actual / total) * 100
    tiempo_transcurrido = time() - tiempo_inicio
    print(f"\r[{barra}] {porcentaje:6.2f}% | Exitosos: {exitosos} | Fallidos: {fallidos} | Tiempo: {tiempo_transcurrido:.1f}s", end='', flush=True)


def procesar_hashes(lista_hashes, archivo_salida):
    global contador_exitos, contador_fallos
    resultados = lista_hashes
    total = len(resultados)
    inicio = time()

    for indice, entrada in enumerate(resultados, start=1):
        nombre = entrada.get('name', 'Desconocido')
        contraseña_hash = entrada.get('password', None)

        if contraseña_hash is None:
            contador_fallos += 1
            continue

        hash_str, salt = obtener_hash_salt(contraseña_hash)
        contraseña = fuerza_bruta(hash_str, salt)

        if contraseña is not None:
            contador_exitos += 1
            entrada['password'] = contraseña
        else:
            contador_fallos += 1

        if indice % 300 == 0:
            guardar_resultados(resultados, archivo_salida)

        barra_progreso(indice, total, contador_exitos, contador_fallos, inicio)

    guardar_resultados(resultados, archivo_salida)
    print()


def pedir_archivo(mensaje, carpeta, extension_check=None):
    while True:
        nombre_archivo = input(mensaje).strip()
        ruta = os.path.join(carpeta, nombre_archivo)
        if not os.path.isfile(ruta):
            print(f"Archivo '{nombre_archivo}' no encontrado en la carpeta '{carpeta}'.")
            continue
        if extension_check and not nombre_archivo.lower().endswith(extension_check):
            print(f"Solo se aceptan archivos con extensión '{extension_check}'.")
            continue
        return ruta


def principal():
    limpiar_pantalla()
    print("=== DESENCRIPTADOR DE BASE DE DATOS ===\n")

    diccionario_path = pedir_archivo("Ingresa el nombre del archivo de diccionario (Wordlist.txt): ", ".", None)
    archivo_entrada = pedir_archivo("Ingresa el nombre del archivo de entrada (en carpeta 'input/', debe ser .json): ", CARPETA_ENTRADA, ".json")
    nombre_salida = input("Ingresa el nombre deseado para el archivo de salida (sin extensión): ").strip()
    archivo_salida = os.path.join(CARPETA_SALIDA, f"{nombre_salida}.json")

    print("\nCargando diccionario...")
    cargar_diccionario(diccionario_path)

    print("Cargando hashes...")
    hashes = cargar_hashes_json(archivo_entrada)

    print(f"\nIniciando proceso de desencriptado de {len(hashes)} entradas...\n")
    procesar_hashes(hashes, archivo_salida)

    print("\nProceso finalizado.")
    print(f"Resultados guardados en '{archivo_salida}'")
    print(f"Total desencriptados: {contador_exitos}")
    print(f"Total fallidos: {contador_fallos}\n")


if __name__ == "__main__":
    principal()
