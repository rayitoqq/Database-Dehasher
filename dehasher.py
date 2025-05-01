import os
import re
import json
import bcrypt
import platform
from time import time, strftime, gmtime
from shutil import get_terminal_size
from hashlib import md5, sha1, sha256, sha512
from concurrent.futures import ProcessPoolExecutor, as_completed, wait
from multiprocessing import cpu_count

CARPETA_ENTRADA = "entrada/"
CARPETA_SALIDA = "salida/"


def limpiar_pantalla():
    os.system('cls' if platform.system() == 'Windows' else 'clear')


def obtener_hash_salt(contenido: str) -> tuple:
    if contenido is None:
        return (None, None)
    if len(contenido) == 32 and all(c in '0123456789abcdef' for c in contenido):
        return (contenido, None)
    if contenido.startswith(('SHA512$', 'SHA256$')):
        partes = contenido.split('$')
        if len(partes) == 3:
            return (partes[2], partes[1])
    if contenido.startswith(('$SHA512$', '$SHA256$')):
        partes = contenido.split('$')
        if len(partes) == 4:
            return (partes[2], partes[3])
    if contenido.startswith(('$SHA512$', '$SHA256$')):
        partes = contenido.split('@')
        if len(partes) == 2:
            return (partes[0].split('$')[2], partes[1])
    if contenido.startswith(('$2b$', '$2a$', '$2y$')):
        partes = contenido.split('$')
        if len(partes) >= 4:
            return ('$'.join(partes[:4]), None)
    if '$' in contenido:
        resultado = re.findall(r"[^$SHA]\w{31,127}", contenido)
        if resultado:
            if len(resultado) > 1:
                return (resultado[1], resultado[0]) if len(resultado[1]) > len(resultado[0]) else (resultado[0], resultado[1])
            dividido = re.findall(r"[^$SHA]\w+", contenido)
            salt = ''.join(x for x in dividido if x != resultado[0])
            return (resultado[0], salt if salt else None)
        return (None, None)
    elif ':' in contenido:
        dividido = contenido.split(':')
        return (dividido[0], dividido[1]) if len(dividido[0]) > len(dividido[1]) else (dividido[1], dividido[0])
    for longitud in [40, 64, 128]:
        if len(contenido) == longitud and all(c in '0123456789abcdef' for c in contenido):
            return (contenido, None)
    return (None, None)


def cargar_wordlist(archivo: str):
    with open(archivo, 'r', encoding='latin-1') as f:
        return [linea.strip() for linea in f]


def intentar_contraseña(contraseña, hash_str, salt):
    if not hash_str:
        return None
    longitud_hash = len(hash_str)
    if hash_str.startswith(('$2a$', '$2b$', '$2y$')):
        if bcrypt.checkpw(contraseña.encode(), hash_str.encode()):
            return contraseña
    funciones_hash = {32: md5, 40: sha1, 64: sha256, 128: sha512}
    if longitud_hash in funciones_hash:
        hash_func = funciones_hash[longitud_hash]
        if salt:
            combinaciones = [
                hash_func(contraseña.encode() + salt.encode()).hexdigest(),
                hash_func(salt.encode() + contraseña.encode()).hexdigest(),
                hash_func(hash_func(contraseña.encode()).hexdigest().encode() + salt.encode()).hexdigest()
            ]
            if hash_str in combinaciones:
                return contraseña
        else:
            if hash_func(contraseña.encode()).hexdigest() == hash_str:
                return contraseña
    return None


def barra_progreso(actual, total, exitosos, fallidos, inicio):
    ancho_terminal = get_terminal_size().columns
    largo_barra = max(10, ancho_terminal - 85)
    llenado = int(largo_barra * actual // total) if total else 0
    barra = '🟩' * llenado + '⬜' * (largo_barra - llenado)
    porcentaje = (actual / total * 100) if total else 0
    tiempo_transcurrido = time() - inicio
    velocidad = actual / tiempo_transcurrido if tiempo_transcurrido > 0 else 0
    estimado_total = (total / velocidad) if velocidad else 0
    tiempo_restante = estimado_total - tiempo_transcurrido
    eta = strftime('%H:%M:%S', gmtime(tiempo_restante)) if tiempo_restante > 0 else "00:00:00"
    print(f"\r🔓 {porcentaje:6.2f}% [{barra}] | ✅ {exitosos} | ❌ {fallidos} | ⏱️ {int(tiempo_transcurrido)}s | ⚡ {velocidad:.2f} hash/s | ETA: {eta}",
          end='', flush=True)


def fuerza_bruta(hash_str, salt, lista_contraseñas):
    if not hash_str:
        return None
    num_procesos = max(1, int(cpu_count() * 0.75))
    with ProcessPoolExecutor(max_workers=num_procesos) as executor:
        tareas = {executor.submit(intentar_contraseña, c, hash_str, salt): c for c in lista_contraseñas}
        for future in as_completed(tareas):
            resultado = future.result()
            if resultado:
                executor.shutdown(cancel_futures=True)
                return resultado
    return None


def cargar_hashes_json(archivo_entrada):
    with open(archivo_entrada, 'r', encoding='utf-8') as f:
        return json.load(f)


def guardar_resultados(resultados, archivo_salida):
    with open(archivo_salida, 'w', encoding='utf-8') as f:
        json.dump(resultados, f, indent=4, ensure_ascii=False)


def procesar_hashes(hash_list, archivo_salida, lista_contraseñas):
    exitosos = 0
    fallidos = 0
    total = len(hash_list)
    inicio = time()
    barra_progreso(0, total, exitosos, fallidos, inicio)

    for i, entrada in enumerate(hash_list, start=1):
        contraseña_hash = entrada.get('password', None)
        hash_str, salt = obtener_hash_salt(contraseña_hash)
        resultado = fuerza_bruta(hash_str, salt, lista_contraseñas) if hash_str else None

        if resultado:
            entrada['password'] = resultado
            exitosos += 1
        else:
            fallidos += 1

        if i % 300 == 0:
            guardar_resultados(hash_list, archivo_salida)

        barra_progreso(i, total, exitosos, fallidos, inicio)

    guardar_resultados(hash_list, archivo_salida)
    print()


def pedir_archivo(mensaje, carpeta, extension=None):
    while True:
        nombre_archivo = input(mensaje).strip()
        ruta = os.path.join(carpeta, nombre_archivo)
        if not os.path.isfile(ruta):
            print(f"⚠️  No encontré el archivo '{nombre_archivo}' en la carpeta '{carpeta}'. Intenta de nuevo.")
            continue
        if extension and not nombre_archivo.lower().endswith(extension):
            print(f"🔒 Solo se permiten archivos que terminen en '{extension}'.")
            continue
        return ruta


def main():
    limpiar_pantalla()
    print("🔍 DESCIFRADOR DE CONTRASEÑAS JSON 🔓\n")
    ruta_wordlist = pedir_archivo("📁 Nombre de tu wordlist (con extensión, en el directorio actual): ", ".", None)
    ruta_entrada = pedir_archivo("📄 Nombre del archivo con hashes (en 'entrada/', debe ser .json): ", CARPETA_ENTRADA, ".json")
    nombre_salida = input("💾 Nombre para guardar los resultados (sin extensión): ").strip()
    archivo_salida = os.path.join(CARPETA_SALIDA, f"{nombre_salida}.json")

    print("\n🔃 Cargando wordlist...")
    lista_contraseñas = cargar_wordlist(ruta_wordlist)

    print("📦 Cargando hashes para trabajar...")
    hashes = cargar_hashes_json(ruta_entrada)

    print(f"\n🛠️  Procesando {len(hashes)} registros...\n🚀 Iniciando búsqueda...\n")
    procesar_hashes(hashes, archivo_salida, lista_contraseñas)

    print(f"\n✅ ¡Todo listo! Contraseñas guardadas en: '{archivo_salida}'\n📂 ¡Revisa tu carpeta de salida!\n")


if __name__ == "__main__":
    main()