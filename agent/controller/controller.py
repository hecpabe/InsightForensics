

"""
    Título: Controller
    Nombre: Héctor Paredes Benavides y Sergio Bermúdez Fernández
    Descripción: Controlador de InsightForensics
    Fecha: 16/10/2023
    Última Modificación: 09/11/2023
"""

# ========== IMPORTADO DE BIBLIOTECAS ==========
import subprocess, requests, time, os

# ========== DECLARACIONES GLOBALES ==========

# ========== CODIFICACIÓN DE FUNCIONES ==========
"""
    Nombre: Controller | Find recent modified files
    Descripción: Función con la que obtenemos la lista de los ficheros modificados recientemente
    Parámetros: 
        0: [INT] Minutos desde los que un archivo se ha modificado para considerarse reciente
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna.
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de ficheros obtenidos
"""
def controllerFindRecentModifiedFiles(time):

    # Realizamos la búsqueda de ficheros modificados recientemente
    return executeCommand(["find", "/", "-cmin", "-" + str(time), "-ls"])

"""
    Nombre: Controller | Find executable files
    Descripción: Función con la que obtenemos la lista de ficheros ejecutables de una ruta
    Parámetros:
        0: [STRING] Ruta en la que buscar los ficheros
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de ficheros obtenidos
"""
def controllerFindExecutableFiles(path):

    # Realizamos la búsqueda de archivos ejecutables en la ruta que se pasa como argumento
    return executeCommand(["find", path, "-executable", "-type", "f"])

"""
    Nombre: Controller | Find files by extensions
    Descripción: Función con la que obtenemos una lista con los ficheros con extensión indicada en la ruta indicada
    Parámetros:
        0: [STRING] Ruta en la que buscar los ficheros
        1: [LIST] Lista con las extensiones en formato ".extensión"
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad de extensiones
    Complejidad Espacial: O(n) n -> Cantidad de ficheros obtenidos
"""
def controllerFindFilesByExtensions(path, extensions):

    # Variables necesarias
    command = [
        "find",
        path,
        "-type",
        "f",
        "("
    ]

    # Agregamos las extensiones
    for i in range(len(extensions)):
        command.append("-name")
        command.append(f'*{extensions[i]}')
        if i < (len(extensions) - 1):
            command.append("-o")
    command.append(")")

    return executeCommand(command)

"""
    Nombre: Controller | Get system PATH
    Descripción: Función con la que obtenemos el PATH del sistema operativo
    Parámetros: Ninguno
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de rutas en el PATH del sistema operativo
"""
def controllerGetSystemPath():

    # Ejecutamos la obtención del PATH
    return {
        "error": False,
        "value": os.environ["PATH"].split(":")
    }

"""
    Nombre: Controller | Editable root files search
    Descripción: Función con la que obtenemos todos los ficheros de root editables por cualquiera
    Parámetros:
        0: [STRING] Ruta en la que buscar los ficheros
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de ficheros encontrados
"""
def controllerEditableRootFilesSearch(path):

    # Realizamos la búsqueda de ficheros de root editables por cualquiera
    return executeCommand(["find", path, "-type", "f", "-uid", "0", "-perm", "/o=w"])

"""
    Nombre: Controller | Get capabilities
    Descripción: Función con la que obtenemos las capabilities del sistema
    Parámetros:
        0: [STRING] Ruta en la que buscar los ficheros con capabilities
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de ficheros encontrados
"""
def controllerGetCapabilities(path):

    # Realizamos la búsqueda de capabilities en la ruta del sistema indicada
    return executeCommand(["getcap", "-r", path])

"""
    Nombre: Controller | Get user groups
    Descripción: Función con la que obtenemos los grupos del usuario mediante el comando groups
    Parámetros: Ninguno
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de grupos del usuario
"""
def controllerGetUserGroups():

    # Obtenemos los grupos del usuario
    return executeCommand(["groups"])

"""
    Nombre: Controller | Get environment variables
    Descripción: Función con la que obtenemos las variables de entorno actuales
    Parámetros: Ninguno
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de variables de entorno
"""
def controllerGetEnvironmentVariables():

    # Obtenemos las variables de entorno del sistema
    return executeCommand(["printenv"])

"""
    Nombre: Controller | Get file stats
    Descripción: Función con la que obtenemos las stats de un fichero
    Parámetros:
        0: [STRING] Ruta del fichero del que obtener las stats
    Retorno: Stats del fichero
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def controllerGetFileStats(path):

    # Obtenemos las stats del fichero en la ruta indicada
    return os.stat(path)

"""
    Nombre: Controller | Full list path
    Descripción: Función con la que listamos de forma completa (ls -l) una ruta
    Parámetros:
        0: [STRING] Ruta a listar
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: El usuario tiene que poder tener permiso de listar esa ruta
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def controllerFullListPath(path):

    # Listamos de forma completa el contenido de la ruta
    return executeCommand(["ls", "-l", path])

"""
    Nombre: Controller | Get SUID binaries
    Descripción: Función con la que obtenemos los binarios con el bit SUID activado
    Parámetros:
        0: [STRING] Ruta desde la que buscar de forma recursiva los binarios
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de binarios con el bit SUID activado
"""
def controllerGetSUIDBinaries(path):

    # Obtenemos los binarios con SUID activado en la ruta indicada
    return executeCommand(["find", path, "-perm", "-4000", "-ls"])

"""
    Nombre: Controller | Get SGID binaries
    Descripción: Función con la que obtenemos los binarios con el bit SGID activado
    Parámetros:
        0: [STRING] Ruta desde la que buscar de forma recursiva los binarios
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de binarios con el bit SGID activado
"""
def controllerGetSGIDBinaries(path):

    # Obtenemos los binarios con SGID activado en la ruta indicada
    return executeCommand(["find", path, "-perm", "-2000", "-ls"])

"""
    Nombre: Controller | Get hostname
    Descripción: Función con la que obtenemos el nombre del equipo
    Parámetros: Ninguno
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def controllerGetHostname():

    # Obtenemos el hostname y lo devolvemos
    return executeCommand(["hostname"])

"""
    Nombre: Controller | Get date
    Descripción: Función con la que obtenemos la fecha del sistema
    Parámetros: Ninguno
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def controllerGetDate():

    # Obtenemos la fecha del sistema y la devolvemos
    return executeCommand(["date"])

"""
    Nombre: Controller | Get up time
    Descripción: Función con la que obtenemos el momento desde el que el sistema lleva activo
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def controllerGetUpTime():

    # Obtenemos el tiempo desde el que el sistema lleva activo y lo devolvemos
    return executeCommand(["uptime", "-s"])

"""
    Nombre: Controller | Get LSB release
    Descripción: Función con la que obtenemos información sobre la release del sistema
    Parámetros: Ninguno
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def controllerGetLsbRelease():

    # Obtenemos el output de lsb release y lo devolvemos
    return executeCommand(["lsb_release", "-a"])

"""
    Nombre: Controller | Get uname
    Descripción: Función con la que obtenemos información sobre la versión del sistema operativo
    Parámetros: Ninguno
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def controllerGetUname():

    # Obtenemos el output de uname y lo devolvemos
    return executeCommand(["uname", "-a"])

"""
    Nombre: Controller | Get CPU info
    Descripción: Función con la que obtenemos la información acerca de la CPU del sistema
    Parámetros: Ninguno
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def controllerGetCPUInfo():

    # Obtenemos la información que almacena el sistema de la CPU y la devolvemos
    return executeCommand(["/bin/cat", "/proc/cpuinfo"])

"""
    Nombre: Controller | Scan files
    Descripción: Función con la que mandamos una lista de ficheros a escanear en VirusTotal
    Parámetros:
        0: [LIST] Lista de rutas de ficheros a escanear
        1: [STRING] API Key de VirusTotal
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad de ficheros a escanear
    Complejidad Espacial: O(n) n -> Cantidad de ficheros a escanear
"""
def controllerScanFiles(files_path=[], api_key=""):

    # Parámetros de la solicitud
    params = {"apikey": api_key}

    # URL de la API de VirusTotal para escanear un archivo
    url_upload = "https://www.virustotal.com/vtapi/v2/file/scan"


    #Diccionario con el nombre del archivo y su md5
    files_dict={}

    contentToReturn = {
        "error": False,
        "value": ""
    }

    #Por cada archivo encontrado se lo mandamos a virus total, y para su posterior
    #y para su posterior analisis lo guardamos dentro de un diccionario con su md5

    for file_path in files_path:

        try:
            with open(file_path, "rb") as file:
                files = {"file": (file.name, file)}
                response = requests.post(url_upload, files=files, params=params)

                #Nos aseguramos de que sea una respuesta correcta
                if response.status_code == 200:
                    result=response.json()
                    files_dict[file.name]=result['md5']
                    
                else:
                    contentToReturn = {
                        "error": True,
                        "value": f"Error uploading file: {file_path}"
                    }
        except(Exception):
            contentToReturn = {
                        "error": True,
                        "value": f"Error uploading file: {file_path}"
                    }
    
    if not contentToReturn["error"]:
        contentToReturn = {
                        "error": False,
                        "value": files_dict
                    }

    return contentToReturn

"""
    Nombre: Controller | Check files
    Descripción: Función con la que comprobamos los resultados de los ficheros escaneados
    Parámetros:
        0: [DICT] Diccionario obtenido de la función controllerScanFiles
        1: [STRING] API Key de VirusTotal
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad de ficheros escaneados
    Complejidad Espacial: O(n) n -> Cantidad de ficheros escaneados
"""
def controllerCheckFiles(md5_dict={}, api_key=""):

    url_check = f"https://www.virustotal.com/vtapi/v2/file/report?apikey={api_key}&resource="


    sleep_interval = 4  # Número de vueltas antes de sleep (cada 4 vueltas). 4 peticiones por min
    positives_dict = {}
    time.sleep(60)

    contentToReturn = {
        "error": False,
        "value": ""
    }

    for index, md5 in enumerate(md5_dict, start=1):
        try:
            url_to_check = url_check + md5_dict[md5]
            response = requests.get(url_to_check)
            positives_dict[md5] = controllerGetPositives(response.json())["value"]

        except Exception:
            contentToReturn = {
                "error": True,
                "value": f"Error checking file: {md5}"
            }

        #Como la api tiene peticiones limitas, cada 4 petciones estamos obligados a para 1 min
        if index % sleep_interval == 0 and index != len(md5_dict):
            print("Esperando respuestas del servidor...")
            time.sleep(60)

    if not contentToReturn["error"]:
        contentToReturn = {
        "error": False,
        "value": positives_dict
    }

    return contentToReturn

"""
    Nombre: Controller | Get positives
    Descripción: Función con la que obtenemos la lista de resultados positivos de un escaneao
    Parámetros:
        0: [DICT] JSON del escaneo
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad de antivirus que han escaneado
    Complejidad Espacial: O(n) n -> Cantidad de antivirus que han escaneado
"""
def controllerGetPositives(scan_json={}):
    # Crear una lista para almacenar los nombres de los antivirus que dieron positivo
    antivirus_positivos = []

    # Recorrer el diccionario de escaneo
    for antivirus, detalles in scan_json['scans'].items():
        if detalles['detected']:
            antivirus_positivos.append(antivirus)

    return {
        "error": False,
        "value": antivirus_positivos
    }

"""
    Nombre: Execute command
    Descripción: Función con la que ejecutamos un comando del sistema y recibimos el output
    Parámetros:
        0: [LIST]: Comando con formato de subprocess
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna.
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Output del comando
"""
def executeCommand(subprocessCommand):

    # Ejecutamos el comando
    proc = subprocess.Popen(subprocessCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Obtenemos el output
    outs, errs = proc.communicate()
    output = str(outs, "UTF-8")

    # Preparamos el retorno
    contentToReturn = {
        "error": False,
        "value": output
    }

    return contentToReturn

"""
    Nombre: Read file content
    Descripción: Función con la que obtenemos el contenido de un fichero
    Parámetros:
        0: [STRING] Ruta del fichero a leer
    Retorno: [STRING] Contenido del fichero
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Tamaño del fichero
"""
def readFileContent(path):

    # Variables necesarias
    fileContent = ""

    # Abrimos el fichero y leemos el contenido
    with open(path, "r") as file:
        fileContent = file.read()
    
    # Retornamos el contenido del fichero
    return fileContent
