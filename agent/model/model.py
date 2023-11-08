

"""
    Título: Model
    Nombre: Héctor Paredes Benavides y Sergio Bermúdez Fernández
    Descripción: Modelo del agente de InsightForensics
    Fecha: 16/10/2023
    Última Modificación: 08/11/2023
"""

# ========== IMPORTADO DE BIBLIOTECAS ==========
import re
from colorama import Fore
from functools import reduce

# Controller
from controller.controller import controllerFindRecentModifiedFiles, controllerFindExecutableFiles, \
    controllerFindFilesByExtensions, readFileContent, controllerScanFiles, controllerCheckFiles, controllerGetSystemPath, \
    controllerEditableRootFilesSearch, controllerGetCapabilities, controllerGetUserGroups

# ========== DECLARACIONES GLOBALES ==========
RECENT_FILES_TIME = 20
SYSTEM_DIRECTORY_FILTER = [
    "proc",
    "run",
    "log",
    "sys",
    "dev"
]
EXECUTABLE_FILE_EXTENSIONS = [
    ".py",
    ".php",
    ".sh",
    ".exe",
    ".jsp",
    ".asp",
    ".aspx",
    ".pl",
    ".rb",
    ".js"
]
BACKDOORS_LISTS = {
    "asp": [],
    "aspx": [],
    "exe": [],
    "js": [],
    "jsp": [],
    "php": [],
    "pl": [],
    "py": [],
    "rb": [],
    "sh": []
}
DANGEROUS_CAPABILITIES = [
    {'capability': 'cap_sys_admin',         'infoTypeID': 3},
    {'capability': 'cap_sys_ptrace',        'infoTypeID': 3},
    {'capability': 'cap_sys_module',        'infoTypeID': 3},
    {'capability': 'cap_dac_reac_search',   'infoTypeID': 3},
    {'capability': 'cap_dac_override',      'infoTypeID': 3},
    {'capability': 'cap_chown',             'infoTypeID': 3},
    {'capability': 'cap_fowner',            'infoTypeID': 3},
    {'capability': 'cap_setuid',            'infoTypeID': 3},
    {'capability': 'cap_setgid',            'infoTypeID': 3},
    {'capability': 'cap_setfcap',           'infoTypeID': 3},
    {'capability': 'cap_sys_rawio',         'infoTypeID': 3},
    {'capability': 'cap_kill',              'infoTypeID': 3},
    {'capability': 'cap_net_bind_service',  'infoTypeID': 3},
    {'capability': 'cap_net_raw',           'infoTypeID': 3},
    {'capability': 'cap_linux_immutable',   'infoTypeID': 3},
    {'capability': 'cap_sys_chroot',        'infoTypeID': 3},
    {'capability': 'cap_sys_boot',          'infoTypeID': 3},
    {'capability': 'cap_syslog',            'infoTypeID': 3},
    {'capability': 'cap_mknod',             'infoTypeID': 3},
    {'capability': 'cap_setpcap',           'infoTypeID': 3},
    {'capability': 'cap_net_admin',         'infoTypeID': 2},
]
EXPLOITABLE_GROUPS = [
    "root",
    "sudo",
    "admin",
    "wheel",
    "video",
    "disk",
    "shadow",
    "adm",
    "docker",
    "lxc",
    "lxd"
]
DANGEROUS_GROUPS = [
    "sudo",
    "disk",
    "shadow",
    "docker"
]

# ========== CODIFICACIÓN DE FUNCIONES ==========
"""
    Nombre: Model | Search recently modified files
    Descripción: Función con la que obtenemos los ficheros modificados recientemente
    Parámetros: Ninguno.
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna.
    Complejidad Temporal: O(n) n -> Cantidad de ficheros obtenidos
    Complejidad Espacial: O(n) n -> Cantidad de ficheros obtenidos
"""
def modelSearchRecentlyModifiedFiles(recentlyModifiedFileTime=RECENT_FILES_TIME):

    # Variables necesarias
    filteredResult = []
    finalInformation = []
    
    # Obtenemos los ficheros modificados en los útlimos minutos
    result = controllerFindRecentModifiedFiles(recentlyModifiedFileTime)

    # Filtramos el input de find para quedarnos con los strings que no contengan directorios modificados por el sistema, separados por un único espacio
    filteredResult = list(
        map(
            lambda x: re.sub(' +', ' ', x), 
            filterFilesFound(result, SYSTEM_DIRECTORY_FILTER)
        )
    )

    # Para cada línea
    for line in filteredResult:
        
        # Separamos la línea en las diferentes columnas de información
        columns = line.split(" ")

        # Comprobamos que la línea tiene la longitud correspondiente
        if len(columns) != 12:
            continue

        # Añadimos al resultado final la línea con los datos:
        # 3: Permisos
        # 5: Owner
        # 6: Group
        # 8: Mes
        # 9: Día
        # 10: Hora
        # 11: Ruta
        finalInformation.append(
            {
                "info": f"{columns[3]} {columns[5]} {columns[6]} {columns[8]} {columns[9]} {columns[10]} {columns[11]}",
                "infoTypeID": 0
            }
        )
    
    # Retornamos la información
    return finalInformation

"""
    Nombre: Model | Search suspect files
    Descripción: Función con la que buscamos ficheros sospechosos en el sistema
    Parámetros: Ninguno.
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad de ficheros obtenidos
    Complejidad Espacial: O(n) n -> Cantidad de ficheros obtenidos
"""
def modelSearchSuspectFiles():

    # Variables necesarias
    finalInformation = []

    # --- Listado de ficheros ejecutables en rutas standard ajenas al sistema /opt... (INFO) ---
    # Obtenemos los ficheros
    usrLocalBinExecutableFiles = controllerFindExecutableFiles("/usr/local/bin")
    usrLocalSbinExecutableFiles = controllerFindExecutableFiles("/usr/local/sbin")
    optExecutableFiles = controllerFindExecutableFiles("/opt")
    allExecutableTrustableFiles = f"{usrLocalBinExecutableFiles['value']}\n{usrLocalSbinExecutableFiles['value']}\n{optExecutableFiles['value']}"

    # Agregamos los ficheros a la respuesta
    for line in allExecutableTrustableFiles.split("\n"):
        # Comprobamos que la línea tenga texto
        if not line:
            continue
        finalInformation.append(
            {
                "info": line,
                "infoTypeID": 0
            }
        )

    # --- Búsqueda de ficheros ejecutables en rutas extrañas /tmp, /etc... (WARNING) ---
    # Obtenemos los ficheros
    tmpExecutableFiles = controllerFindExecutableFiles("/tmp")
    etcExecutableFiles = controllerFindExecutableFiles("/etc")
    varExecutableFiles = controllerFindExecutableFiles("/var")
    allExecutableUntrustableFiles = f"{tmpExecutableFiles['value']}\n{etcExecutableFiles['value']}\n{varExecutableFiles['value']}"

    # Agregamos los ficheros a la respuesta
    for line in allExecutableUntrustableFiles.split("\n"):
        # Comprobamos que la línea tenga texto
        if not line:
            continue

        # Obtenemos la extensión del fichero
        extension = line.split(".")[::-1][0]

        # Comprobamos que el fichero sea de un programa ejecutable
        for extension in EXECUTABLE_FILE_EXTENSIONS:
            if extension in line:
                finalInformation.append(
                    {
                        "info": line,
                        "infoTypeID": 2
                    }
                )

    # --- Búsqueda de ficheros con extensiones ejecutables para el análisis del nombre con el diccionario de backdoors (DANGER) ---
    # Extensiones: .py .php .sh .exe .jsp .asp .aspx .pl .rb .js
    # Obtenemos los ficheros
    programExtensionFilesSearch = controllerFindFilesByExtensions("/", EXECUTABLE_FILE_EXTENSIONS)
    programExtensionFiles = programExtensionFilesSearch["value"].split("\n")

    # Agregamos los ficheros que den positivos como posibles backdoors
    for line in programExtensionFiles:

        # Comprobamos que la línea no esté vacía
        if not line:
            continue

        # Obtenemos la extensión del fichero
        extension = line.split(".")[::-1][0]

        # Comprobamos si la lista de backdoors para esta estensión está cargada, sino la cargamos
        if len(BACKDOORS_LISTS[extension]) == 0:
            BACKDOORS_LISTS[extension] = readFileContent(f"./resources/backdoors_{extension}_list.txt").split("\n")
        
        # Comprobamos si el fichero se llama como alguno de los backdoors
        for backdoor in BACKDOORS_LISTS[extension]:
            
            # Comprobamos que el backdoor no esté vacío
            if not backdoor:
                continue

            if backdoor in line:
                finalInformation.append(
                    {
                        "info": line,
                        "infoTypeID": 3
                    }
                )
                break

    # Retornamos la información
    return finalInformation

"""
    Nombre: Model | Analyze suspicious files
    Descripción: Función con la que analizamos ficheros para comprobar si son maliciosos o no
    Parámetros:
        0: [LIST] Lista con las rutas a los ficheros obtenidos
        1: [LIST] Lista con los índices de las rutas de ficheros a analizar
        2: [STRING] ApiKey de VirusTotal
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: La clave a la API debe ser correcta y funcionar correctamente
    Complejidad Temporal: O(n) n -> Ficheros a analizar
    Complejidad Espacial: O(n) n -> Ficheros a analizar
"""
def modelAnalyzeSuspiciousFiles(files, indexes, apiKey):

    # Variables necesarias
    filesToAnalyze = []
    filesMD5s = {}
    filesResults = {}
    finalInformation = []

    # Obtenemos todas las rutas de los ficheros a analizar en función de la lista de ficheros y los índices seleccionados
    for index in indexes:
        filesToAnalyze.append(files[index]["info"])
    
    # Mandamos las rutas de los ficheros a analizar al controlador
    filesMD5s = controllerScanFiles(filesToAnalyze, apiKey)

    # Si no tenemos errores mandamos a comprobar los hashes MD5 y preparamos el output
    if not filesMD5s["error"]:
        filesResults = controllerCheckFiles(filesMD5s["value"], apiKey)
        if not filesResults["error"]:
            for file in filesToAnalyze:
                numberOfPositives = len(filesResults['value'][file])
                if numberOfPositives == 0:
                    color = 1
                elif numberOfPositives < 3:
                    color = 2
                else:
                    color = 3
                finalInformation.append({
                    "info": f"[RESULTADO DEL ESCANEO] ({file}) - {numberOfPositives} antivirus han dado positivo.",
                    "infoTypeID": color
                })
        else:
            finalInformation.append({
                "info": filesResults["value"],
                "infoTypeID": 4
            })
    else:
        finalInformation.append({
            "info": filesMD5s["value"],
            "infoTypeID": 4
        })

    # Retornamos los resultados procesados
    return finalInformation

"""
    Nombre: Model | System PATH Analysis
    Descripción: Función con la que analizamos el PATH del sistema operativo en busca de ficheros .sh
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad de ficheros .sh en el PATH
    Complejidad Espacial: O(n) n -> Cantidad de ficheros .sh en el PATH
"""
def modelSystemPathAnalysis():

    # Variables necesarias
    finalInformation = []
    systemPath = []

    # Obtenemos el PATH del sistema
    systemPath = controllerGetSystemPath()["value"]

    # Obtenemos los ficheros .sh en las rutas del PATH y los preparamos para retornar
    for path in systemPath:
        shFiles = controllerFindFilesByExtensions(path, [".sh"])["value"]
        if shFiles:
            for shFile in shFiles.split("\n"):
                if shFile:
                    finalInformation.append(
                        {
                            "info": shFile,
                            "infoTypeID": 2
                        }
                    )

    return finalInformation

"""
    Nombre: Model | Editable root files search
    Descripción: Función con la que obtenemos todos los ficheros de root editables por cualquiera
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad de ficheros encontrados
    Complejidad Espacial: O(n) n -> Cantidad de ficheros encontrados
"""
def modelEditableRootFilesSearch():

    # Variables necesarias
    editableRootFiles = []
    finalInformation = []

    # Obtenemos los ficheros de root editables por cualquiera
    editableRootFiles = controllerEditableRootFilesSearch("/")

    # Agregamos los ficheros a la respuesta
    for rootFile in filterFilesFound(editableRootFiles, SYSTEM_DIRECTORY_FILTER):

        if not rootFile:
            continue
        
        finalInformation.append({
            "info": rootFile,
            "infoTypeID": 3
        })
    
    return finalInformation

"""
    Nombre: Model | Etc hosts check
    Descripción: Función con la que obtenemos los hosts de un sistema
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad de hosts
    Complejidad Espacial: O(n) n -> Cantidad de hosts
"""
def modelEtcHostsCheck():

    # Variables necesarias
    etcHostsContent = ""
    etcHostsContentNormalized = []
    etcHostsContentFiltered = []
    finalInformation = []

    # Obtenemos el contenido del fichero /etc/hosts
    etcHostsContent = readFileContent("/etc/hosts")

    # Normalizamos el contenido a IP HOST
    etcHostsContentNormalized = list(
        map(
            lambda x: re.sub(' +', ' ', x),
            map(
                lambda x: x.replace("\t", " "),
                etcHostsContent.split("\n")
            )
        )
    )
    
    # Filtramos el contenido normalizado para evitar líneas vacías y comentarios
    etcHostsContentFiltered = list(
        filter(
            lambda x: x and x[0] != "#" and x[1] != "#",
            etcHostsContentNormalized
        )
    )

    # Preparamos la información para retornarla
    for host in etcHostsContentFiltered:

        # Separamos la línea del /etc/hosts por espacios
        hostElements = host.split(" ")

        # Si el primer elemento está vacío lo eliminamos, ya que empieza la línea por espacio
        if not hostElements[0]:
            hostElements.pop(0)
        
        # Formateamos de la siguiente manera: IP - HOST, HOST, HOST...
        ipAddress = hostElements.pop(0)
        hostsString = ", ".join(hostElements)

        # Preparamos la información para retornarla
        finalInformation.append(
            {
                "info": f"{ipAddress} - {hostsString}",
                "infoTypeID": 0
            }
        )
    
    return finalInformation

"""
    Nombre: Model | Capabilities check
    Descripción: Función con la que obtenemos las capabilities del sistema y comprobamos si alguna es peligrosa
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna.
    Complejidad Temporal: O(n) n -> Cantidad de ficheros
    Complejidad Espacial: O(n) n -> Cantidad de ficheros
"""
def modelCapabilitiesCheck():

    # Variables necesarias
    capabilitiesOutput = ""
    finalInformation = []

    # Obtenemos las capabilities del sistema
    capabilitiesOutput = controllerGetCapabilities("/")

    # Interpretamos las capabilities
    for line in capabilitiesOutput["value"].split("\n"):
        if not line:
            continue
        path, caps = line.split(" ")
        dangerousCapabilityFound = False
        for dangerousCapability in DANGEROUS_CAPABILITIES:
            if dangerousCapability["capability"] in caps:
                dangerousCapabilityFound = True
                finalInformation.append({
                    "info": f"PATH: {path} | CAPABILITIES: {caps}",
                    "infoTypeID": dangerousCapability["infoTypeID"]
                })
                break
        if not dangerousCapabilityFound:
            finalInformation.append({
                "info": f"PATH: {path} | CAPABILITIES: {caps}",
                "infoTypeID": 1
            })
    
    return finalInformation

"""
    Nombre: Model | Groups check
    Descripción: Función con la que comprobamos los grupos del sistema
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad de grupos del fichero /etc/group
    Complejidad Espacial: O(n) n -> Cantidad de grupos del fichero /etc/group
"""
def modelGroupsCheck():

    # Variables necesarias
    userGroupsOutput = ""
    systemGroupsOutput = ""

    dangerList = []
    warningList = []
    safeList = []
    infoList = []

    finalInformation = []

    # Obtenemos los grupos del usuario
    userGroupsOutput = controllerGetUserGroups()

    # Obtenemos los grupos del sistema
    systemGroupsOutput = readFileContent("/etc/group")

    # Agregamos como información los grupos del usuario
    finalInformation.append({
        "info": f"GRUPOS DEL USUARIO: {userGroupsOutput['value']}",
        "infoTypeID": 0
    })
    finalInformation.append({"info": "", "infoTypeID": 0})  # Salto de línea

    # Agregamos la información del /etc/group
    finalInformation.append({
        "info": "----- /etc/group -----",
        "infoTypeID": 0
    })

    for line in systemGroupsOutput.split("\n"):
        # Si no tiene contenido pasamos
        if not line:
            continue

        # Separamos la línea en grupo:contraseña:gid:miembros
        group, password, gid, members = line.split(":")

        # Si el grupo tiene una contraseña especificada en el /etc/group lo marcamos como peligroso
        if password != 'x':
            dangerList.append({
                "info": f"[PELIGRO - CONTRASEÑA EXPLÍCITA] {line}",
                "infoTypeID": 3
            })
            continue

        # Si el grupo tiene GID 0 (es root) y tiene usuarios lo marcamos como peligroso o advertencia si es el grupo de root
        if gid == 0 and members:
            if group == "root":
                warningList.append({
                    "info": f"[AVISO - USUARIO EN GRUPO ROOT] {line}",
                    "infoTypeID": 2
                })
            else:
                dangerList.append({
                    "info": f"[PELIGRO - USUARIO EN GRUPO CON PRIVILEGIOS DE ROOT] {line}",
                    "infoTypeID": 3
                })
            continue
        
        # Si el grupo es un grupo peligroso y tiene usuarios lo marcamos como advertencia si es explotable y peligro si es peligroso
        if group in EXPLOITABLE_GROUPS and members:
            if group in DANGEROUS_GROUPS:
                dangerList.append({
                    "info": f"[PELIGRO - USUARIO EN GRUPO PELIGROSO] {line}",
                    "infoTypeID": 3
                })
            else:
                warningList.append({
                    "info": f"[AVISO - USUARIO EN GRUPO EXPLOTABLE] {line}",
                    "infoTypeID": 2
                })
            continue
        
        # EN ESTE CASO NO ES UN PRIVILEGIO PELIGROSO
        # Si el GID es mayor o igal que 1000 es una cuenta de usuario, sino es de servicio
        if (int(gid) >= 1000 and group != "nogroup") or int(gid) == 0:
            safeList.append({
                "info": f"[SIN PELIGRO - CUENTA DE USUARIO] {line}",
                "infoTypeID": 1
            })
        else:
            infoList.append({
                "info": f"[INFO - CUENTA DE SERVICIO] {line}",
                "infoTypeID": 0
            })

    finalInformation += dangerList + warningList + safeList + infoList
    return finalInformation

"""
    Nombre: Model | SSH Key Search
    Descripción: Función con la que obtenemos las claves SSH (.pem y .ppk) en un directorio (de forma recursiva)
    Parámetros:
        0: [STRING] Ruta en la que buscar
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad de claves encontradas
    Complejidad Espacial: O(n) n -> Cantidad de claves encontradas
"""
def modelSSHKeySearch(path):

    # Variables necesarias
    sshKeysFound = ""
    finalInformation = []

    # Buscamos claves SSH (.pem / .ppk)
    sshKeysFound = controllerFindFilesByExtensions(path, [".pem", ".ppk"])["value"]

    # Procesamos los ficheros encontrados
    if sshKeysFound:
        for sshKey in sshKeysFound.split("\n"):
            if sshKey:
                finalInformation.append({
                    "info": sshKey,
                    "infoTypeID": 2
                })
    
    return finalInformation

"""
    Nombre: Filter files found
    Descripción: Función con la que filtramos los ficheros encontrados para evitar rutas que usa el sistema operativo
    Parámetros: 
        0: [LIST] Lista (obtenida mediante el controlador) de ficheros a filtrar
        1: [LIST] Lista de strings de filtro para no dejar pasar
    Retorno: [LIST] Lista con los ficheros ya filtrados
    Precondición: Las listas tienen que tener el formato correcto (diccionario obtenido del controlador para los ficheros y string para los filtros)
    Complejidad Temporal: O(n) n -> Cantidad de ficheros a filtrar
    Complejidad Espacial: O(n) n -> Cantidad de ficheros a filtrar
"""
def filterFilesFound(filesFound, filesFilter):

    # Variables necesarias
    filteredResult = []

    # Filtramos los ficheros encontrados para evitar los que pertenezcan a los del filtro
    filteredResult = list(
        filter(
            lambda x: not any(directory in x for directory in filesFilter), 
            filesFound["value"].split("\n")
        )
    )

    return filteredResult
