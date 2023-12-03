

"""
    Título: Controller
    Nombre: Héctor Paredes Benavides y Sergio Bermúdez Fernández
    Descripción: Controlador de InsightForensics
    Fecha: 16/10/2023
    Última Modificación: 09/11/2023
"""

# ========== IMPORTADO DE BIBLIOTECAS ==========
import subprocess, requests, time, os, re
from  datetime import datetime, timedelta
from collections import defaultdict
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
    Nombre: Controller | Get network interfaces
    Descripción: Función con la que obtenemos la información acerca de las interfaces de red
    Parámetros: Ninguno
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de interfaces de red
"""
def controllerGetNetworkInterfaces():

    # Obtenemos las interfaces de red y las devolvemos
    return executeCommand(["ip", "a"])

"""
    Nombre: Controller | Get network connections
    Descripción: Función con la que obtenemos las conexiones de red, en escucha o establecidas
    Parámetros:
        0: [BOOL] True para obtener las conexiones a la escucha y false para obtener las conexiones establecidas
    Retorno: Diccionario con formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de conexiones
"""
def controllerGetNetworkConnections(listening=False):

    # Variables necesarias
    command = []

    # Construimos el comando
    command.append("netstat")
    command.append("-t")
    command.append("-u")

    if listening:
        command.append("-l")

    # Obtenemos las conexiones de red a la escucha y las devolvemos
    return executeCommand(command)

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



"""
    Nombre: Controller | Get Path
    Descripción: Función con la que obtenemos el PATH
    Parámetros: Ninguno
    Retorno: Diccionario con formato {error: Boolena, value: PATH}
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def controllerGetPath():

    return executeCommand(['printenv','PATH'])


"""
    Nombre: Controller | Get File Acces
    Descripción: Funcion para verificar si se puede escribir en un fichero
    Parámetros: Ruta en la cual se quiere escribir
    Retorno: Booleano si tiene o no acceso
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def controllerGetFileAcces(ruta):

    try:
        # Intenta crear un archivo temporal en el directorio
        with open(os.path.join(ruta, 'temp_file.txt'), 'w') as temp_file:
            temp_file.write("holaaaa")
        # Elimina el archivo temporal
        os.remove(os.path.join(ruta, 'temp_file.txt'))
        return True  # Tienes permisos de escritura
    except OSError as e:
        print(f"No tienes permisos de escritura en {ruta}: {e}")
        return False  # No tienes permisos de escritura


"""
    Nombre: Controller | Get Total Time and Times Logged
    Descripción: Funcion para obetner el numero de veces que se a logeado un usuario y su tiempo de actividad total
    Parámetros: [LIST] Lista de la cual se recogera la información para analizarla
    Retorno: [DICT] Diccionario con el formato {"usuario",[veces logeado, tiempo total de actividad]}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Lineas de fichero de registro
    Complejidad Espacial: O(n) n -> Lineas de fichero de registro
"""
def controllerGetTotalTime_TimesLogged(registros):
    informacion_usuarios = defaultdict(lambda: [0, 0]) # Inicializar un diccionario con valores predeterminados

    for registro in registros:
        elementos = registro.split()
        usuario = elementos[0]
        tiempo = elementos[-1][1:-1]  # Eliminar los paréntesis

        informacion_usuarios[usuario][0] += 1

        # Extraer las horas y minutos del tiempo en formato (HH:MM)
        horas, minutos = map(int, tiempo.split(':'))
        tiempo_en_minutos = horas * 60 + minutos
        informacion_usuarios[usuario][1] += tiempo_en_minutos

    
    return dict(informacion_usuarios)



"""
    Nombre: Controller | Get Usernames On Last Log
    Descripción: Función para obtener los nombres de los usuarios que estan conectados actualmente
    Parámetros: [LIST] Lista de la cual se recogera la información para analizarla
    Retorno: Conjunto con los usuarios logeados actualmete
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Lineas de fichero de registro
    Complejidad Espacial: O(n) n -> Lineas de fichero de registro
"""
def controllerGetUsernamesOnLastLog(registros):
    nombres_usuarios = set()  # Usar un conjunto en lugar de una lista

    for registro in registros:
        elementos = registro.split()
        if len(elementos) > 0:
            nombre_usuario = elementos[0]
            nombres_usuarios.add(nombre_usuario)

    return list(nombres_usuarios)  # Convertir el conjunto en una lista antes de retornarlo



"""
    Nombre: Controller History Logged
    Descripción: Funcion para obtener y filtrar los inicios de sesision
    Parámetros: INT Dias desde los que se quiero analizar el registro (Default = 7).
    Retorno: [DICT] Diccionario con el formato {"error": Bool, "value": Resultado}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Lineas de fichero de registro
    Complejidad Espacial: O(n) n -> Lineas de fichero de registro
"""
def controllerHistoryLogged(days_since=7):


    # Obtén la fecha y hora actual
    fecha_actual = datetime.now()

    # Calcula la fecha hace un mes
    fecha_to_calculate = fecha_actual - timedelta(days=days_since)

    # Formatea la fecha en el formato necesario para -s
    since = fecha_to_calculate.strftime("%Y%m%d")
    
    #Loggin en el dia de hoy
    since=since+"000000"  

    #Ejecutamos el comando 
    lastLogon= executeCommand(["last","-s" ,since])

    if(lastLogon["error"]==False):
        
        output=lastLogon["value"].strip().split("\n")
        registro=list(filter(lambda x: "wtmp" not in x and "+" not in x, output))
        registro=registro[:-1]

        filteredLoggedUser=list(
            filter(
                lambda x: "still logged in" in x , registro))

        filteredList=list(
            filter(
                lambda x: "reboot" not in x and "wtmp" not in x and "+" not in x and "still logged in" not in x, registro))

        filteredRegist = list(
            map(
                lambda x: re.sub(' +', ' ', x), 
                filteredList
            )
        )

        filteredLoggedUser = list(
            map(
                lambda x: re.sub(' +', ' ', x), 
                filteredLoggedUser
            )
        )
        
        informacion_usuarios = controllerGetTotalTime_TimesLogged(filteredRegist)
        informacion_logeados = controllerGetUsernamesOnLastLog(filteredLoggedUser)
        

        #Tener en cuenta que puede ser que el diccionario de infomacion_usuarios este vacio por que aun no se haya desconectado nadie el dia de hoy.
        contentToReturn= {"error":False,
                "value": [informacion_usuarios, informacion_logeados]}


    else:

        contentToReturn= {"error":True,
                "value": f"Error executando el comando last -s {days_since}"}
    
    return contentToReturn



"""
    Nombre: Controller | Crontab
    Descripción: Funcion para obtener el listados de todas las tareas programadas del sistema y usuarios
    Parámetros: Ninguno
    Retorno: [DICT] Retorna 3 diccionarios con el formato {"error": Boolean, "value": Valores registrados}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Lineas de fichero de registro
    Complejidad Espacial: O(n) n -> Lineas de fichero de registro
"""
def controllerCrontab():

    crontrab_e=controllerCrontab_e()
    etcCrontab=controllerEtcCrontab()
    periodicCrontab=controllerGetPeriodic()
    
    return crontrab_e,etcCrontab,periodicCrontab


"""
    Nombre: Controller | Etc Crontab
    Descripción: Funcion para obtener el listados de todas las tareas programadas del sistema
    Parámetros: Ninguno
    Retorno: [DICT] Retorna un diccionario con el formato {"error": Boolean, "value": Valores registrados}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Lineas de fichero de registro
    Complejidad Espacial: O(n) n -> Lineas de fichero de registro
"""
def controllerEtcCrontab():

    etcCrontab=executeCommand(["cat","/etc/crontab"])
    crontabDict={}
    contentToReturn = {
        "error": False,
        "value": ""
    }


    if(etcCrontab["error"]==False):

        filteredCrontab=etcCrontab["value"].split("\n")
        
        filteredCrontab = list(
            filter(
            lambda x: len(x), filteredCrontab))

        filteredCrontab = list(
            filter(
            lambda x: x[0]!="#", filteredCrontab))
        

        crontabDict={"etcCrontab": filteredCrontab}
        contentToReturn = {"error":False,
                           "value": crontabDict}


    else:
        contentToReturn = {"error": True,
                           "value": "Error executing commnad cat /etc/crontab"}
    return contentToReturn


"""
    Nombre: Controller | Etc Crontab
    Descripción: Funcion para obtener el listados de todas las tareas programadas de los usuarios
    Parámetros: Ninguno
    Retorno: [DICT] Retorna un diccionario con el formato {"error": Boolean, "value": Valores registrados}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Lineas de fichero de registro
    Complejidad Espacial: O(n) n -> Lineas de fichero de registro
"""
def controllerCrontab_e():

    crontab_e=executeCommand(["ls","/var/spool/cron/crontabs/"])
    crontrabDict={}
    contentToReturn = {
        "error": False,
        "value": ""
    }
    if(crontab_e["error"]==False):
        usersWithCrontabs=crontab_e["value"].split("\n")
        usersWithCrontabs=usersWithCrontabs[:-1] #Sacamos la ultima linea
        

        if(len(usersWithCrontabs)>0):
            for user in usersWithCrontabs:
                catCrontab=executeCommand(["cat",f"/var/spool/cron/crontabs/{user}"])
                if(catCrontab["error"]==False):
                    catCrontab=catCrontab["value"].split("\n")
                    catCrontab=catCrontab[:-1]
                
                filteredCrontab = list(
                    filter(
                        lambda x: x[0]!="#", catCrontab))
                
                crontrabDict[user]=filteredCrontab

            contentToReturn = {"error": False,
                    "value": crontrabDict}
        else:
            contentToReturn = {"error":False,
                    "value":"There are no users in directory /var/spool/cron/crontabs"}
    else:
        contentToReturn = {"error":True,
                    "value":f"Error executing command ls /var/spool/cron/crontabs "}

    return contentToReturn


"""
    Nombre: Controller | Get Per
    Descripción: Funcion para obtener el listados de todas las tareas programadas periodicas d daily ...
    Parámetros: Ninguno
    Retorno: [DICT] Retorna un diccionario con el formato {"error": Boolean, "value": Valores registrados}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Lineas de fichero de registro
    Complejidad Espacial: O(n) n -> Lineas de fichero de registro
"""
def controllerGetPeriodic():

    d=executeCommand(["ls", "/etc/cron.d"])
    daily=executeCommand(["ls", "/etc/cron.daily"])
    hourly=executeCommand(["ls", "/etc/cron.hourly"])
    monthly=executeCommand(["ls", "/etc/cron.monthly"])
    weekly=executeCommand(["ls", "/etc/cron.weekly"])

    contentToReturn = {
        "error": False,
        "value": {"d":filterRegist(d["value"]),
                  "daily":filterRegist(daily["value"]),
                  "hourly":filterRegist(hourly["value"]),
                  "monthly":filterRegist(monthly["value"]),
                  "weekly":filterRegist(weekly["value"]),}
    }

    return contentToReturn



"""
    Nombre: filter Resgister
    Descripción:  Funcion para filtar los resultados de las tareas programadad periodicas
    Parámetros: String con los registros a filtrar
    Retorno: Lista con los archivos que se ejecutan
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Lineas de fichero de registro
    Complejidad Espacial: O(n) n -> Lineas de fichero de registro
"""
def filterRegist(resgist):
    resgist=resgist.split("\n")
    resgist=resgist[:-1] #Sacamos la ultima linea
    return resgist



"""
    Nombre: Controller | System Ctl
    Descripción: Funcion para obtener la salida del system clt y los archivos que se ejecutan al unicio
    Parámetros: Ninguno
    Retorno: [DICT] Retorna un diccionario con el formato {"error": Boolean, "value": Valores registrados}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Lineas de fichero de registro
    Complejidad Espacial: O(n) n -> Lineas de fichero de registro
"""
def controllerSystemCtl():


    return executeCommand(["systemctl","list-unit-files","--state=enabled"])


"""
    Nombre: Controller | Initd
    Descripción: Funcion para obtener la salida de todos los archivos que se ejecutan al unicio de la máquina
    Parámetros: Ninguno
    Retorno: [DICT] Retorna un diccionario con el formato {"error": Boolean, "value": Valores registrados}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Lineas de fichero de registro
    Complejidad Espacial: O(n) n -> Lineas de fichero de registro
"""
def controllerInitd():

    return executeCommand(["ls", "/etc/init.d"])

"""
    Nombre: Controller | authLog
    Descripción: Funcion para obtener la salida de todos los archivos que se ejecutan al unicio de la máquina
    Parámetros: 
        0 [String] rute en la cual se obtendra el archivo auth.log 
    Retorno: [DICT] Retorna un diccionario con el formato {"error": Boolean, "value": Valores registrados}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Lineas de fichero de registro
    Complejidad Espacial: O(n) n -> Lineas de fichero de registro
"""
def controllerAuthLog(rute):

    return executeCommand(["ls", f"{rute}"])