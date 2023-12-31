

"""
    Título: Model
    Nombre: Héctor Paredes Benavides y Sergio Bermúdez Fernández
    Descripción: Modelo del agente de InsightForensics
    Fecha: 16/10/2023
    Última Modificación: 09/11/2023
"""

# ========== IMPORTADO DE BIBLIOTECAS ==========
import re, stat, pwd, grp
from colorama import Fore
from functools import reduce
from  datetime import datetime
from collections import defaultdict

# Controller
from controller.controller import controllerFindRecentModifiedFiles, controllerFindExecutableFiles, \
    controllerFindFilesByExtensions, readFileContent, controllerScanFiles, controllerCheckFiles, controllerGetSystemPath, \
    controllerEditableRootFilesSearch, controllerGetCapabilities, controllerGetUserGroups, controllerGetEnvironmentVariables, \
    controllerGetFileStats, controllerFullListPath, controllerGetSUIDBinaries, controllerGetSGIDBinaries, controllerGetDate, \
    controllerGetUpTime, controllerGetLsbRelease, controllerGetUname, controllerGetCPUInfo, controllerGetHostname, \
    controllerGetNetworkInterfaces, controllerGetNetworkConnections, controllerGetPath, controllerGetFileAcces, \
    controllerHistoryLogged, controllerCrontab, controllerSystemCtl,controllerInitd,controllerAuthLog

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
DANGEROUS_BINARIES = []

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
    Nombre: Model | Environment variables check
    Descripción: Función con la que comprobamos las variables de entorno del sistema
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad de variables de entorno
    Complejidad Espacial: O(n) n -> Cantidad de variables de entorno
"""
def modelEnvironmentVariablesCheck():

    # Variables necesarias
    environmentVariablesOutput = ""
    finalInformation = []

    # Obtenemos las variables de entorno
    environmentVariablesOutput = controllerGetEnvironmentVariables()

    # Preparamos la información para devolverla
    for line in environmentVariablesOutput["value"].split("\n"):
        if not line:
            continue
        lineSplitted = line.split("=")
        variable = lineSplitted[0]
        value = "=".join(lineSplitted[1:])
        if value:
            finalInformation.append({
                "info": f"{variable} = {value}",
                "infoTypeID": 0
            })
    
    return finalInformation

"""
    Nombre: Model | Sudoers file check
    Descripción: Función con la que comprobamos el contenido del fichero /etc/sudoers
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: El programa tiene que poder ejecutarse con privilegios de lectura sobre el fichero /etc/sudoers
    Complejidad Temporal: O(n) n -> Cantidad de líneas del fichero /etc/sudoers
    Complejidad Espacial: O(n) n -> Cantidad de líneas del fichero /etc/sudoers
"""
def modelSudoersFileCheck():

    # Variables necesarias
    sudoersFileContent = ""
    filteredSudoersFileContent = []

    sudoersDefaults = []
    sudoersHostAlias = []
    sudoersUserAlias = []
    sudoersCommandAlias = []
    sudoersUsersPrivileges = []
    sudoersGroupsPrivileges = []

    finalInformation = []

    # Obtenemos el fichero de sudoers
    sudoersFileContent = readFileContent("/etc/sudoers")

    # Filtramos el contenido del fichero para quedarnos únicamente con los que nos importa
    filteredSudoersFileContent = map(
        lambda x: re.sub('\t+', ' ', x),
        map(
            lambda x: re.sub(' +', ' ', x),
            filter(
                lambda x: x and "#" not in x and "include" not in x,
                sudoersFileContent.split("\n")
            )
        )
    )

    # Procesamos la información del fichero
    for line in filteredSudoersFileContent:
        # Si la línea contiene Defaults la consideramos como tal
        if "Defaults" in line:
            if len(sudoersDefaults) == 0:
                sudoersDefaults.append({
                    "info": "----- Configuración -----",
                    "infoTypeID": 0
                })
            sudoersDefaults.append({
                "info": line,
                "infoTypeID": 0
            })
            continue
        
        # Si la línea contiene Host_Alias la consideramos como tal
        if "Host_Alias" in line:
            if len(sudoersHostAlias) == 0:
                sudoersHostAlias.append({
                    "info": "----- Host Alias -----",
                    "infoTypeID": 0
                })
            splittedLine = line.split(" ")
            alias = splittedLine[1]
            value = " ".join(splittedLine[3:])
            sudoersHostAlias.append({
                "info": f"{alias} = {value}",
                "infoTypeID": 0
            })
            continue
        
        # Si la línea contiene User_Alias la consideramos como tal
        if "User_Alias" in line:
            if len(sudoersUserAlias) == 0:
                sudoersUserAlias.append({
                    "info": "----- User Alias -----",
                    "infoTypeID": 0
                })
            splittedLine = line.split(" ")
            alias = splittedLine[1]
            value = " ".join(splittedLine[3:])
            sudoersUserAlias.append({
                "info": f"{alias} = {value}",
                "infoTypeID": 0
            })
            continue
        
        # Si la línea contiene Cmnd_Alias la consideramos como tal
        if "Cmnd_Alias" in line:
            if len(sudoersCommandAlias) == 0:
                sudoersCommandAlias.append({
                    "info": "----- Command Alias -----",
                    "infoTypeID": 0
                })
            splittedLine = line.split(" ")
            alias = splittedLine[1]
            value = " ".join(splittedLine[3:])
            sudoersCommandAlias.append({
                "info": f"{alias} = {value}",
                "infoTypeID": 0
            })
            continue
        
        # Si la línea contiene el carácter % significa que son permisos aplicables a un grupo
        if "%" in line:
            if len(sudoersGroupsPrivileges) == 0:
                sudoersGroupsPrivileges.append({
                    "info": "----- Privilegios de grupos -----",
                    "infoTypeID": 0
                })
            splittedLine = line.split(" ")
            group = splittedLine[0]
            host, privileges = splittedLine[1].split("=")
            splittedPrivileges = privileges.split(":")
            targetUser = splittedPrivileges[0][1:]
            targetGroup = splittedPrivileges[1][:-1]
            commands = " ".join(splittedLine[2:])
            infoTypeID = 0
            
            # Si puede ejecutar los comandos como root o como todos lo marcamos como aviso, si además puede ejecutar todos los
            # comandos lo marcamos como peligro, sino, como información
            if ("root" in targetUser or "root" in targetGroup or "ALL" in targetUser or "ALL" in targetGroup) and "root" not in group and "sudo" not in group:
                if "ALL" in commands:
                    infoTypeID = 3
                else:
                    infoTypeID = 2
            sudoersGroupsPrivileges.append({
                "info": f"{group} {host}={privileges} {commands}",
                "infoTypeID": infoTypeID
            })
            continue

        # Sino, son permisos aplicables a un usuario o alias
        if len(sudoersUsersPrivileges) == 0:
            sudoersUsersPrivileges.append({
                "info": "----- Privilegios de usuarios -----",
                "infoTypeID": 0
            })
        splittedLine = line.split(" ")
        user = splittedLine[0]
        host, privileges = splittedLine[1].split("=")
        splittedPrivileges = privileges.split(":")
        targetUser = splittedPrivileges[0][1:]
        targetGroup = splittedPrivileges[1][:-1]
        commands = " ".join(splittedLine[2:])
        infoTypeID = 0

        # Si puede ejecutar los comandos como root o como todos lo marcamos como aviso, si además puede ejecutar todos los 
        # comandos lo marcamos como peligro, sino, como información
        if ("root" in targetUser or "root" in targetGroup or "ALL" in targetUser or "ALL" in targetGroup) and "root" not in user:
            if "ALL" in commands:
                infoTypeID = 3
            else:
                infoTypeID = 2
        sudoersUsersPrivileges.append({
            "info": f"{user} {host}={privileges} {commands}",
            "infoTypeID": infoTypeID
        })

    if len(sudoersDefaults):
        sudoersDefaults.append({
            "info": "",
            "infoTypeID": 0
        })
    if len(sudoersHostAlias):
        sudoersHostAlias.append({
            "info": "",
            "infoTypeID": 0
        })
    if len(sudoersUserAlias):
        sudoersUserAlias.append({
            "info": "",
            "infoTypeID": 0
        })
    if len(sudoersCommandAlias):
        sudoersCommandAlias.append({
            "info": "",
            "infoTypeID": 0
        })
    if len(sudoersUsersPrivileges):
        sudoersUsersPrivileges.append({
            "info": "",
            "infoTypeID": 0
        })
    if len(sudoersGroupsPrivileges):
        sudoersGroupsPrivileges.append({
            "info": "",
            "infoTypeID": 0
        })

    finalInformation = sudoersDefaults + sudoersHostAlias + sudoersUserAlias + sudoersCommandAlias + sudoersUsersPrivileges + sudoersGroupsPrivileges
    return finalInformation

"""
    Nombre: Model | Shadow file permissions check
    Descripción: Función con la que comprobamos los permisos del fichero /etc/shadow
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: El usuario tiene que tener permisos para poder listar el fichero /etc/shadow
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def modelShadowFilePermissionsCheck():

    # Variables necesarias
    fileListed = ""
    fileStats = ""
    fileMode = ""
    fileOwner = ""
    fileGroup = ""

    fileUserInDanger = False
    fileGroupInDanger = False

    finalInformation = []

    # Obtenemos las stats del fichero
    fileListed = controllerFullListPath("/etc/shadow")
    fileStats = controllerGetFileStats("/etc/shadow")
    fileMode = fileStats.st_mode

    finalInformation.append({
        "info": f"{fileListed['value']}\n",
        "infoTypeID": 0
    })

    # Comprobamos el propietario y el grupo del fichero
    fileOwner = pwd.getpwuid(fileStats.st_uid)[0]
    fileGroup = grp.getgrgid(fileStats.st_gid)[0]

    if fileOwner not in ["root", "shadow"]:
        fileUserInDanger = True
        finalInformation.append({
            "info": f"[!] Propietario del fichero: {fileOwner}",
            "infoTypeID": 3
        })
    else:
        finalInformation.append({
            "info": f"[+] Propietario del fichero: {fileOwner}",
            "infoTypeID": 1
        })

    if fileGroup not in ["root", "shadow"]:
        fileGroupInDanger = True
        finalInformation.append({
            "info": f"[!] Fichero en el grupo: {fileGroup}",
            "infoTypeID": 3
        })
    else:
        finalInformation.append({
            "info": f"[+] Fichero en el grupo: {fileGroup}",
            "infoTypeID": 1
        })

    # Comprobamos que los permisos del fichero correspondan con rw- r-- ---
    # USER
    # Si el usuario puede leer o escribir en el fichero pero no debería - Peligro
    if fileUserInDanger and ((fileMode & stat.S_IRUSR) or (fileMode & stat.S_IWUSR)):
        finalInformation.append({
            "info": f"[!] El usuario {fileOwner} puede leer o escribir en el fichero",
            "infoTypeID": 3
        })
    # Si el usuario no puede leer y escribir debiendo poder hacerlo - Aviso
    elif not fileUserInDanger and not ((fileMode & stat.S_IRUSR) and (fileMode & stat.S_IWUSR)):
        finalInformation.append({
            "info": f"[-] El usuario {fileOwner} no puede leer y escribir en el fichero",
            "infoTypeID": 2
        })
    # Si el usuario puede leer y escribir en el fichero y debería hacerlo - Sin peligro
    else:
        finalInformation.append({
            "info": f"[+] El usuario {fileOwner} puede leer y escribir en el fichero",
            "infoTypeID": 1
        })
    
    # Si el usuario puede ejecutar el fichero - Aviso
    if fileMode & stat.S_IXUSR:
        finalInformation.append({
            "info": f"[-] El usuario {fileOwner} puede ejecutar el fichero",
            "infoTypeID": 2
        })
    else:
        finalInformation.append({
            "info": f"[+] El usuario {fileOwner} no puede ejecutar el fichero",
            "infoTypeID": 1
        })
    
    # GROUP
    # Si el grupo puede leer el fichero pero no debería - Peligro
    if fileGroupInDanger and (fileMode & stat.S_IRGRP):
        finalInformation.append({
            "info": f"[!] El grupo {fileGroup} puede leer el fichero",
            "infoTypeID": 3
        })
    # Si el grupo no puede leer el fichero pero debería - Aviso
    elif not fileGroupInDanger and not (fileMode & stat.S_IRGRP):
        finalInformation.append({
            "info": f"[-] El grupo {fileGroup} no puede leer el fichero",
            "infoTypeID": 2
        })
    # Si el grupo puede leer el fichero y debería - Sin peligro
    else:
        finalInformation.append({
            "info": f"[+] El grupo {fileGroup} puede leer el fichero",
            "infoTypeID": 1
        })
    
    # Si el grupo puede escribir el fichero y es un grupo peligroso - Peligro
    if fileGroupInDanger and (fileMode & stat.S_IWGRP):
        finalInformation.append({
            "info": f"[!] El grupo {fileGroup} puede escribir en el fichero",
            "infoTypeID": 3
        })
    # Si el grupo puede escribir en el fichero pero no es un grupo peligroso - Aviso
    elif not fileGroupInDanger and (fileMode & stat.S_IWGRP):
        finalInformation.append({
            "info": f"[-] El grupo {fileGroup} puede escribir en el fichero",
            "infoTypeID": 2
        })
    # Si el grupo no puede escribir en el fichero - Sin peligro
    else:
        finalInformation.append({
            "info": f"[+] El grupo {fileGroup} no puede escribir en el fichero",
            "infoTypeID": 1
        })
    
    # Si el grupo puede ejecutar el fichero - Aviso
    if fileMode & stat.S_IXGRP:
        finalInformation.append({
            "info": f"[-] El grupo {fileGroup} puede ejecutar el fichero",
            "infoTypeID": 2
        })
    # Si el grupo no puede ejecutar el fichero - Sin peligro
    else:
        finalInformation.append({
            "info": f"[+] El grupo {fileGroup} no puede ejecutar el fichero",
            "infoTypeID": 1
        })
    
    # OTHER
    # Si cualquiera puede leer o escribir el fichero - Peligro
    if (fileMode & stat.S_IROTH) or (fileMode & stat.S_IWOTH):
        finalInformation.append({
            "info": f"[!] Cualquier usuario puede leer o escribir en el fichero",
            "infoTypeID": 3
        })
    # Si cualquier usuario no puede leer o escribir el fichero - Sin peligro
    else:
        finalInformation.append({
            "info": f"[+] No cualquier usuario puede leer o escribir en el fichero",
            "infoTypeID": 1
        })
    
    # Si cualquier usuario puede ejecutar el fichero - Aviso
    if fileMode & stat.S_IXOTH:
        finalInformation.append({
            "info": f"[-] El fichero es ejecutable por cualquiera",
            "infoTypeID": 2
        })
    # Si el fichero no es ejecutable por cualquiera - Sin peligro
    else:
        finalInformation.append({
            "info": f"[+] El fichero no es ejecutable por cualquiera",
            "infoTypeID": 1
        })
    
    return finalInformation

"""
    Nombre: Model | Bit SUID check
    Descripción: Función con la que obtenemos los binarios con el bit SUID activado y analizamos si son una posible amenaza
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad de binarios con el bit SUID activado
    Complejidad Espacial: O(n) n -> Cantidad de binarios con el bit SUID activado
"""
def modelBitSUIDCheck():

    # Variables necesarias
    bitSUIDOutput = ""
    filteredResult = []

    dangerousBinaries = []
    warningBinaries = []
    safeBinaries = []

    finalInformation = []

    # Obtenemos los binarios con SUID activado
    bitSUIDOutput = controllerGetSUIDBinaries("/")
    
    # Filtramos solo la información que nos interesa
    filteredResult = list(
        map(
            lambda x: re.sub(' +', ' ', x),
            bitSUIDOutput["value"].split("\n")
        )
    )

    # Si no hemos cargado la lista de binarios peligrosos la cargamos
    if len(DANGEROUS_BINARIES) <= 0:
        for binary in readFileContent("./resources/dangerous_binaries.txt").split("\n"):
            if binary:
                DANGEROUS_BINARIES.append(binary)

    # Iteramos sobre cada línea obteniendo las columnas que nos interesen y evaluando si es una posible amenaza
    for line in filteredResult:
        
        if not line:
            continue

        # Filtramos la información que nos interesa
        splittedLine = line.split(" ")

        binaryPermissions = splittedLine[3]
        binaryOwner = splittedLine[5]
        binaryGroup = splittedLine[6]
        binaryMonth = splittedLine[8]
        binaryDay = splittedLine[9]
        binaryYear = splittedLine[10]
        binaryPath = splittedLine[11]

        binaryName = binaryPath.split("/")[-1]

        # Comprobamos si el binario es peligroso que tenga el SUID activado
        # Es peligroso y propietario root -> Peligro
        # Es peligroso y propietario otro que no es root -> Advertencia
        # No es peligroso -> Sin peligro
        info = f"{binaryPermissions} {binaryOwner} {binaryGroup} {binaryMonth} {binaryDay} {binaryYear} {binaryPath}"
        if binaryName in DANGEROUS_BINARIES:
            if binaryOwner == "root":
                dangerousBinaries.append({
                    "info": f"[PELIGRO] {info}",
                    "infoTypeID": 3
                })
            else:
                warningBinaries.append({
                    "info": f"[AVISO] {info}",
                    "infoTypeID": 2
                })
        else:
            safeBinaries.append({
                "info": f"[SIN PELIGRO] {info}",
                "infoTypeID": 1
            })
    
    finalInformation = dangerousBinaries + warningBinaries + safeBinaries
    return finalInformation

"""
    Nombre: Model | Bit SGID check
    Descripción: Función con la que obtenemos los binarios con el bit SGID activado y analizamos si son una posible amenaza
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad de binarios con el bit SGID activado
    Complejidad Espacial: O(n) n -> Cantidad de binarios con el bit SGID activado
"""
def modelBitSGIDCheck():

    # Variables necesarias
    bitSGIDOutput = ""
    filteredResult = []

    dangerousBinaries = []
    warningBinaries = []
    safeBinaries = []

    finalInformation = []

    # Obtenemos los binarios con permiso SGID activado
    bitSGIDOutput = controllerGetSGIDBinaries("/")

    # Filtramos solo la información que nos interesa
    filteredResult = list(
        map(
            lambda x: re.sub(' +', ' ', x),
            bitSGIDOutput["value"].split("\n")
        )
    )

    # Si no hemos cargado la lista de binarios peligrosos la cargamos
    if len(DANGEROUS_BINARIES) <= 0:
        for binary in readFileContent("./resources/dangerous_binaries.txt").split("\n"):
            if binary:
                DANGEROUS_BINARIES.append(binary)

    # Iteramos sobre cada línea obteniendo las columnas que nos interesen y evaluando si es una posible amenaza
    for line in filteredResult:
        
        if not line:
            continue

        # Filtramos la información que nos interesa
        splittedLine = line.split(" ")

        binaryPermissions = splittedLine[3]
        binaryOwner = splittedLine[5]
        binaryGroup = splittedLine[6]
        binaryMonth = splittedLine[8]
        binaryDay = splittedLine[9]
        binaryYear = splittedLine[10]
        binaryPath = splittedLine[11]

        binaryName = binaryPath.split("/")[-1]

        # Comprobamos si el binario es peligroso que tenga el SUID activado
        # Es peligroso y propietario root -> Peligro
        # Es peligroso y propietario otro que no es root -> Advertencia
        # No es peligroso -> Sin peligro
        info = f"{binaryPermissions} {binaryOwner} {binaryGroup} {binaryMonth} {binaryDay} {binaryYear} {binaryPath}"
        if binaryName in DANGEROUS_BINARIES:
            if binaryGroup == "root":
                dangerousBinaries.append({
                    "info": f"[PELIGRO] {info}",
                    "infoTypeID": 3
                })
            else:
                warningBinaries.append({
                    "info": f"[AVISO] {info}",
                    "infoTypeID": 2
                })
        else:
            safeBinaries.append({
                "info": f"[SIN PELIGRO] {info}",
                "infoTypeID": 1
            })
    
    finalInformation = dangerousBinaries + warningBinaries + safeBinaries
    return finalInformation

"""
    Nombre: Model | System info check
    Descripción: Función con la que obtenemos información del sistema
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def modelSystemInfoCheck():

    # Variables necesarias
    hostnameOutput = ""
    dateOutput = ""
    lsbReleaseOutput = ""
    unameOutput = ""
    cpuInfoOutput = ""
    upTimeOutput = ""

    finalInformation = []

    # Obtenemos la información del sistema y la añadimos al resultado
    hostnameOutput = controllerGetHostname()["value"]
    finalInformation.append({
        "info": f"Hostname: {hostnameOutput}",
        "infoTypeID": 0
    })

    dateOutput = controllerGetDate()["value"]
    finalInformation.append({
        "info": f"Fecha: {dateOutput}",
        "infoTypeID": 0
    })

    upTimeOutput = controllerGetUpTime()["value"]
    finalInformation.append({
        "info": f"Inicio del sistema: {upTimeOutput}",
        "infoTypeID": 0
    })

    lsbReleaseOutput = controllerGetLsbRelease()["value"]
    finalInformation.append({
        "info": f"----- Información de la release -----\n{lsbReleaseOutput}",
        "infoTypeID": 0
    })

    unameOutput = controllerGetUname()["value"]
    finalInformation.append({
        "info": f"Información del sistema operativo: {unameOutput}",
        "infoTypeID": 0
    })

    cpuInfoOutput = controllerGetCPUInfo()["value"]
    finalInformation.append({
        "info": f"----- Información de la CPU -----\n{cpuInfoOutput}",
        "infoTypeID": 0
    })

    return finalInformation

"""
    Nombre: Model | Network interfaces check
    Descripción: Función con la que comprobamos la información de las interfaces de red
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de interfaces de red
"""
def modelNetworkInterfacesCheck():

    # Variables necesarias
    networkInterfacesOutput = ""
    finalInformation = []

    # Obtenemos la información de las interfaces de red y la añadimos para devolverla
    networkInterfacesOutput = controllerGetNetworkInterfaces()["value"]
    finalInformation.append({
        "info": networkInterfacesOutput,
        "infoTypeID": 0
    })

    return finalInformation

"""
    Nombre: Model | Network connections check
    Descripción: Función con la que comprobamos las conexiones de red tanto a la escucha como establecidas
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad de conexiones
    Complejidad Espacial: O(n) n -> Cantidad de conexiones
"""
def modelNetworkConnectionsCheck():

    # Variables necesarias
    listeningConnectionsOutput = ""
    establishedConnectionsOutput = ""

    filteredListeningConnectionsOutput = ""
    filteredEstablishedConnectionsOutput = ""

    allConnections = []

    finalInformation = []

    # Obtenemos las conexiones a la escucha
    listeningConnectionsOutput = controllerGetNetworkConnections(listening=True)["value"]
    filteredListeningConnectionsOutput = filterNetworkConnections(listeningConnectionsOutput)

    # Obtenemos las conexiones establecidas
    establishedConnectionsOutput = controllerGetNetworkConnections()["value"]
    filteredEstablishedConnectionsOutput = filterNetworkConnections(establishedConnectionsOutput)

    # Juntamos la información en una misma lista
    allConnections = filteredListeningConnectionsOutput + filteredEstablishedConnectionsOutput

    # Procesamos la información antes de agregarla
    for line in allConnections:

        splittedLine = line.split(" ")

        protocol = splittedLine[0]
        localIP = splittedLine[3]
        foreignIP = splittedLine[4]
        connectionStatus = splittedLine[5]

        finalInformation.append({
            "info": f"Conexión: {protocol} | {localIP} <-> {foreignIP} ({connectionStatus})",
            "infoTypeID": 0
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

"""
    Nombre Filter network connections
    Descripción: Función con la que filtramos el output de las conexiones de red
    Parámetros:
        0: [STRING] Output de la obtención de las conexiones de red
    Retorno: [List] Lista con las líneas filtradas
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad de conexiones de red
    Complejidad Espacial: O(n) n -> Cantidad de conexiones de red
"""
def filterNetworkConnections(networkConnections):

    # Variables necesarias
    filteredNetworkConnections = []

    filteredNetworkConnections = list(
        # Omitimos espacios innecesarios
        map(
            lambda x: re.sub(' +', ' ', x),
            # Comprobamos que la línea de las conexiones contenga información útil
            filter(
                lambda x: "tcp" in x or "udp" in x,
                # Comprobamos que la línea de las conexiones no esté vacía
                filter(
                    lambda x: x,
                    networkConnections.split("\n")
                )
            )
        )
    )

    return filteredNetworkConnections



"""
    Nombre: model | ETC passwd
    Descripción: Funcion con la que filtraremos los datos del etc/passwd
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad lineas en el fichero
    Complejidad Espacial: O(n) n -> Cantidad lineas en el fichero
"""
def modelEtcPasswd():

    ##PARA EL MODELO
    etcPasswdOutPut=readFileContent("/etc/passwd")

    finalInformation = [{
                "info": "----- RIESGOS EN EL ETC/PASSWD ----- ",
                "infoTypeID": 3
            }]

    #Info
    dangerList=[]
    
    adminUsers=[{
                "info": "----- CUENTAS DE ADMINISTRADORES ----- ",
                "infoTypeID": 0
            }]
    serviceUsers = [{
                "info": "----- CUENTAS DE SERVICIO ----- ",
                "infoTypeID": 0
            }]
    normalUsers = [{
                "info": "----- CUENTAS DE USUARIO ----- ",
                "infoTypeID": 0
            }]
    
    usersWithShell = [{
                "info": "----- CUENTAS CON TERMINAL ----- ",
                "infoTypeID": 0
            }]


    for line in etcPasswdOutPut.split("\n"):


        if not line:
            continue

        try:
            user, passwd, uid, gid, fullName, home, shell = line.split(":")

        except:
            continue


        if(passwd!="x" ):
            dangerList.append({
                "info": f"[PELIGRO] Usuario {user}, con credenciales {passwd}",
                "infoTypeID": 3
            })
        if(int(uid)==0 and user !="root"):
            dangerList.append({
                "info": f"[PELIGRO] Usuario {user}, con UID {uid}",
                "infoTypeID": 3
            })
        if(int(gid)==0 and user !="root"):
            dangerList.append({
                "info": f"[PELIGRO] Usuario {user}, con GID {uid}",
                "infoTypeID": 3
            })


        if(int(uid)==0):
            adminUsers.append({
                "info": f"[INFO] Servicio {user}, UID {uid}",
                "infoTypeID": 0
            })
        elif(int(uid)>0 and int(uid)<1000):
            serviceUsers.append({
                "info": f"[INFO] Servicio {user}, UID {uid}",
                "infoTypeID": 0
            })
        elif(int(uid)>=1000):
            normalUsers.append({
                "info": f"[INFO] Usuario {user}, UID {uid}",
                "infoTypeID": 0
            })

        if("sh" in shell):
            usersWithShell.append({
                "info": f"[INFO] Usuario {user}, UID {uid}, con Shell {shell}",
                "infoTypeID": 0
            })

    finalInformation = finalInformation + dangerList + adminUsers + serviceUsers + normalUsers + usersWithShell

    return finalInformation

        
"""
    Nombre: model | ETC passwd permission check
    Descripción: Funcion con la que comprobaremos permisos del etcpass
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad lineas en el fichero
    Complejidad Espacial: O(n) n -> Cantidad lineas en el fichero
"""
def modelEtcFilePermissionsCheck():

    # Variables necesarias
    fileListed = ""
    fileStats = ""
    fileMode = ""
    fileOwner = ""
    fileGroup = ""

    fileUserInDanger = False
    fileGroupInDanger = False

    finalInformation = []

    # Obtenemos las stats del fichero
    fileListed = controllerFullListPath("/etc/passwd")
    fileStats = controllerGetFileStats("/etc/passwd")
    fileMode = fileStats.st_mode

    finalInformation.append({
        "info": f"{fileListed['value']}\n",
        "infoTypeID": 0
    })

    # Comprobamos el propietario y el grupo del fichero
    fileOwner = pwd.getpwuid(fileStats.st_uid)[0]
    fileGroup = grp.getgrgid(fileStats.st_gid)[0]

    if fileOwner not in ["root"]:
        fileUserInDanger = True
        finalInformation.append({
            "info": f"[!] Propietario del fichero: {fileOwner}",
            "infoTypeID": 3
        })
    else:
        finalInformation.append({
            "info": f"[+] Propietario del fichero: {fileOwner}",
            "infoTypeID": 1
        })

    if fileGroup not in ["root"]:
        fileGroupInDanger = True
        finalInformation.append({
            "info": f"[!] Fichero en el grupo: {fileGroup}",
            "infoTypeID": 3
        })
    else:
        finalInformation.append({
            "info": f"[+] Fichero en el grupo: {fileGroup}",
            "infoTypeID": 1
        })

    # Comprobamos que los permisos del fichero correspondan con -rw- r-- r--
    # USER
    # Si el usuario puede leer o escribir en el fichero pero no debería - Peligro
    if fileUserInDanger and ((fileMode & stat.S_IRUSR) or (fileMode & stat.S_IWUSR)):
        finalInformation.append({
            "info": f"[!] El usuario {fileOwner} puede leer o escribir en el fichero",
            "infoTypeID": 3
        })
    # Si el usuario no puede leer y escribir debiendo poder hacerlo - Aviso
    elif not fileUserInDanger and not ((fileMode & stat.S_IRUSR) and (fileMode & stat.S_IWUSR)):
        finalInformation.append({
            "info": f"[-] El usuario {fileOwner} no puede leer y escribir en el fichero",
            "infoTypeID": 2
        })
    # Si el usuario puede leer y escribir en el fichero y debería hacerlo - Sin peligro
    else:
        finalInformation.append({
            "info": f"[+] El usuario {fileOwner} puede leer y escribir en el fichero",
            "infoTypeID": 1
        })
    
    # Si el usuario puede ejecutar el fichero - Aviso
    if fileMode & stat.S_IXUSR:
        finalInformation.append({
            "info": f"[-] El usuario {fileOwner} puede ejecutar el fichero",
            "infoTypeID": 2
        })
    else:
        finalInformation.append({
            "info": f"[+] El usuario {fileOwner} no puede ejecutar el fichero",
            "infoTypeID": 1
        })
    
    # GROUP
    # Si el grupo puede leer el fichero pero no debería - Peligro
    if fileGroupInDanger and (fileMode & stat.S_IRGRP):
        finalInformation.append({
            "info": f"[!] El grupo {fileGroup} puede leer el fichero",
            "infoTypeID": 3
        })
    # Si el grupo no puede leer el fichero pero debería - Aviso
    elif not fileGroupInDanger and not (fileMode & stat.S_IRGRP):
        finalInformation.append({
            "info": f"[-] El grupo {fileGroup} no puede leer el fichero",
            "infoTypeID": 2
        })
    # Si el grupo puede leer el fichero y debería - Sin peligro
    else:
        finalInformation.append({
            "info": f"[+] El grupo {fileGroup} puede leer el fichero",
            "infoTypeID": 1
        })
    
    # Si el grupo puede escribir el fichero y es un grupo peligroso - Peligro
    if fileGroupInDanger and (fileMode & stat.S_IWGRP):
        finalInformation.append({
            "info": f"[!] El grupo {fileGroup} puede escribir en el fichero",
            "infoTypeID": 3
        })
    # Si el grupo puede escribir en el fichero pero no es un grupo peligroso - Aviso
    elif not fileGroupInDanger and (fileMode & stat.S_IWGRP):
        finalInformation.append({
            "info": f"[-] El grupo {fileGroup} puede escribir en el fichero",
            "infoTypeID": 2
        })
    # Si el grupo no puede escribir en el fichero - Sin peligro
    else:
        finalInformation.append({
            "info": f"[+] El grupo {fileGroup} no puede escribir en el fichero",
            "infoTypeID": 1
        })
    
    # Si el grupo puede ejecutar el fichero - Aviso
    if fileMode & stat.S_IXGRP:
        finalInformation.append({
            "info": f"[-] El grupo {fileGroup} puede ejecutar el fichero",
            "infoTypeID": 2
        })
    # Si el grupo no puede ejecutar el fichero - Sin peligro
    else:
        finalInformation.append({
            "info": f"[+] El grupo {fileGroup} no puede ejecutar el fichero",
            "infoTypeID": 1
        })
    
    # OTHER
    # Si cualquiera puede escribir el fichero - Peligro
    if (fileMode & stat.S_IWOTH):
        finalInformation.append({
            "info": f"[!] Cualquier usuario puede escribir en el fichero",
            "infoTypeID": 3
        })
    # Si cualquier usuario no escribir el fichero - Sin peligro
    else:
        finalInformation.append({
            "info": f"[+] No cualquier usuario puede escribir en el fichero",
            "infoTypeID": 1
        })
    
    # Si cualquier usuario puede ejecutar el fichero - Aviso
    if fileMode & stat.S_IXOTH:
        finalInformation.append({
            "info": f"[-] El fichero es ejecutable por cualquiera",
            "infoTypeID": 2
        })
    # Si el fichero no es ejecutable por cualquiera - Sin peligro
    else:
        finalInformation.append({
            "info": f"[+] El fichero no es ejecutable por cualquiera",
            "infoTypeID": 1
        })
    
    return finalInformation
        



"""
    Nombre: model | check path
    Descripción: funcion para comprobar la seguridad del path
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad rutas en el path
    Complejidad Espacial: O(n) n -> Cantidad rutas en el path
"""
def modelCheckPath():

    finalInformation=[]
    
    pathOutPut = controllerGetPath()


    if(pathOutPut["error"]==True):
        finalInformation.append({
                    "info": f"[ERROR] No se ha podido ejecutar el path",
                    "infoTypeID": 4
        })
        return finalInformation
    # Dividir el path en una lista de directorios
    directories = pathOutPut["value"].split(":")
    
    # Encontrar el índice del último "bin" en la lista
    last_bin_index = max((i for i, d in enumerate(directories) if d.endswith("bin")), default=None)

    # Guardar las rutas inválidas antes del último "bin"
    invalid_paths_before_last_bin = [d for i, d in enumerate(directories[:last_bin_index]) if not d.endswith("bin")]
    invalid_paths_after_last_bin = [d for i, d in enumerate(directories[last_bin_index + 1:]) if not d.endswith("bin")]
    
    for rute in invalid_paths_after_last_bin:
        if controllerGetFileAcces(rute):
                finalInformation.append({
                    "info": f"[AVISO] Se puede escribir en la ruta: {rute}",
                    "infoTypeID": 2
                })


    if len(finalInformation)==0:
        finalInformation.append({
                "info": "No se han encontrado rutas maliciosas en el path",
                "infoTypeID": 0
        })


    for rute in directories:
        if rute not in invalid_paths_after_last_bin:
            if controllerGetFileAcces(rute):
                    finalInformation.append({
                        "info": f"[PELIGRO] Se puede escribir en la ruta: {rute}",
                        "infoTypeID": 3
                    })

    
    return finalInformation



"""
    Nombre: model | check history logged
    Descripción: Funcion para comprobar los inicios de sesion
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad rutas en el path
    Complejidad Espacial: O(n) n -> Cantidad rutas en el path
"""
def modelCheckHistoryLogged(days_since=7):

    finalInformation=[]
    

    ##PARA EL MODELO
    etcPasswdOutPut=readFileContent("/etc/passwd")
    serviceUsers=[]

    #Obtenemos las cuentas de servicio
    for line in etcPasswdOutPut.split("\n"):

        if not line:
            continue

        try:
            user, passwd, uid, gid, fullName, home, shell = line.split(":")

        except:
            continue


        if(int(uid)>0 and int(uid)<1000):
            serviceUsers.append(user)

        

    historyLoggedOutPut = controllerHistoryLogged(days_since)
    
    if(historyLoggedOutPut["error"]==True):
        finalInformation.append({
                        "info": f"[ERROR] Error ejecutando el historial de loggeos",
                        "infoTypeID": 4
        })
    else:

        dictTimeLogged= historyLoggedOutPut["value"][0]
        listLoggedUsers=historyLoggedOutPut["value"][1]

        finalInformation.append({
                "info": f"----- USUARIOS LOGEADOS -----",
                "infoTypeID": 0
            })
        for user in listLoggedUsers:
            if user in serviceUsers:
                finalInformation.append({
                    "info": f"[PELIGRO] Usuario {user} is logged cuenta de servicio",
                    "infoTypeID": 3
                })
            else:
                finalInformation.append({
                    "info": f"[INFO] Usuario {user} is logged",
                    "infoTypeID": 0
                })

        finalInformation.append({
                "info": f"----- Tiempos y veces logeados en los ultimos {days_since} dias-----",
                "infoTypeID": 0
            })
        for user , data in dictTimeLogged.items():
            if user in serviceUsers:
                finalInformation.append({
                    "info": f"[PELIGRO] Usuario {user} se loggeo un total de {data[0]} veces durante un total de  {data[1]} minutos cuenta de servcio",
                    "infoTypeID": 3
                })
            else:
                finalInformation.append({
                    "info": f"[INFO] Usuario {user} se loggeo un total de {data[0]} veces durante un total de  {data[1]} minutos",
                    "infoTypeID": 0
                })


    return finalInformation



"""
    Nombre: model | check etc crontab
    Descripción: Funcion para comprobar los inicios de sesion
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad rutas en el path
    Complejidad Espacial: O(n) n -> Cantidad rutas en el path
"""
def modelCheckCrontab():


    finalInformation=[]
    contrabInformation=[]
    etcCrontabInformation=[]
    etcPeriodicCrontab=[]


    crontrab_eResult, etcCrontabResult, periodicCrontabResult = controllerCrontab()

    contrabInformation.append({
                    "info": f"----- CRONTAB_E -----",
                    "infoTypeID": 0
    })

    if(crontrab_eResult["value"]==True):
        contrabInformation.append({
                    "info": f"[ERROR] Error intentaod ejeutar el comando para ver los usuario con tareas programadas",
                    "infoTypeID": 4
        })
    else:

        crontab_e = crontrab_eResult["value"]  

        if "There are no users"  in crontab_e:
            contrabInformation.append({
                        "info": f"[INFO] No hay usuarios con tareas programadas en /var/spool/cron/crontabs",
                        "infoTypeID": 0
            })
        else:
            for user in crontab_e:
                for tarea in crontab_e[user]:
                    contrabInformation.append({
                                "info": f"[INFO] Tarea programada para el usurio {user} ejecutando : {tarea}",
                                "infoTypeID": 0
                    })

    etcCrontabInformation.append({
                    "info": f"\n----- ETC CRONTAB -----",
                    "infoTypeID": 0
    })

    if(etcCrontabResult["value"]==True):
        etcCrontabInformation.append({
                    "info": f"[ERROR] Error intentaod ejeutar comando para ver ETC CRONTAB",
                    "infoTypeID": 4
        })
    else:

        etcCrontab = etcCrontabResult["value"]  


        etcCrontabInformation.append({
                    "info": f"Archivo ETC CRONTAB",
                    "infoTypeID": 0
        })

        for line in etcCrontab["etcCrontab"]:
            etcCrontabInformation.append({
                    "info": f"{line}",
                    "infoTypeID": 0
         })

    etcPeriodicCrontab.append({
                    "info": f"\n----- PERIODIC CRONTABS -----",
                    "infoTypeID": 0
    })


    
    if(periodicCrontabResult["value"]==True):
        etcPeriodicCrontab.append({
                    "info": f"[ERROR] Error intentaod ver archivos periodicos de crontab",
                    "infoTypeID": 4
        })
    else:

        etcCrontab = periodicCrontabResult["value"]  

        for periodic in etcCrontab:
            files=[]
            for file in etcCrontab[periodic]:
                files.append(file)

            etcPeriodicCrontab.append({
                    "info": f"Files in CRON.{periodic}: {files}",
                    "infoTypeID": 0
            }) 


    finalInformation = contrabInformation + etcCrontabInformation + etcPeriodicCrontab
    return finalInformation
    



"""
    Nombre: model | check init proccess
    Descripción: Funcion para comprobar los archivos que se ejecutan al inicio
    Parámetros: Ninguno
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad rutas en el path
    Complejidad Espacial: O(n) n -> Cantidad rutas en el path
"""
def modelCheckInitProccess():


    finalInformation=[]
    systemctl=controllerSystemCtl()


    finalInformation.append({
        "info": f"----- SYSTEM CTL -----",
        "infoTypeID": 0
    })


    if(systemctl["error"]==False):
        

        systemctl=systemctl["value"].strip().split("\n")
        systemctl=list(filter(lambda x: "unit files listed" not in x , systemctl))
        systemctl=systemctl[:-1]
        systemctl=systemctl[1:]

        systemctl = list(
            map(
                lambda x: re.sub(' +', ' ', x), 
                systemctl
            )
        )
        finalInformation.append({
            "info": f"{'Unit File':<30} {'State':<10} {'Preset'}\n",
            "infoTypeID": 0
        })
        for line in systemctl:

            if not line:
                continue


            unitFile, state, preset = line.split()


            finalInformation.append({
                "info": f"{unitFile:<30} {state:<10} {preset}",
                "infoTypeID": 0
            })

    else:
        finalInformation.append({
                "info": "[ERROR] No se ha podido ejecutar systemctl",
                "infoTypeID": 4
        })


    finalInformation.append({
        "info": f"\n----- INIT D -----",
        "infoTypeID": 0
    })


    initd=controllerInitd()

    files=""
    if(initd["error"]==False):

        initd=initd["value"].split("\n")
        print(initd)
        for line in initd:
            print()
            if not line:
                continue
            
            files=files+line+", "

        finalInformation.append({
                "info": f"Archivos ejecutados al inicio: {files}",
                "infoTypeID": 0
        })

    else:
        finalInformation.append({
                "info": "[ERROR] No se ha podido ejecutar ls initd",
                "infoTypeID": 4
        })
    return finalInformation


"""
    Nombre: model | check authLog
    Descripción: Funcion para comprobar el archivo auth.log
    Parámetros: 
        [string] rute Ruta del archivo por defecto /var/log/auth.log
        [int] dias_check int dias desde lo cuales se realizaran pruebas
    Retorno: [DICT] Diccionario con el formato {"info": String, "infoTypeID": ID del tipo de escaneo}
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad rutas en el path
    Complejidad Espacial: O(n) n -> Cantidad rutas en el path
"""
def modelCheckAuthLog(rute="/var/log/auth.log", dias_check=30, max_tries=100):

    authLog=controllerAuthLog(rute)

    fecha_actual = datetime.now()
    change_passwd=[]
    users_sudo=[]
    ipInfo=[]
    tries_filed_ip = defaultdict(int)

    change_passwd.append({
        "info": "\n----- CAMBIOS DE CONTRASEÑAS -----",
        "infoTypeID": 0
    })

    ipInfo.append({
        "info": "\n----- USOS DE SUDO -----",
        "infoTypeID": 0
    })

    users_sudo.append({
        "info": "\n----- Inicios Fallidos -----",
        "infoTypeID": 0
    })


    if(authLog["error"]==False):
        authLog=authLog["value"].split("\n")
        for line in authLog:
            if not line:
                continue

            if 'passwd' in line and 'password changed' in line:
                match=re.search(r'for\s+([^:\s]+)', line)

                if match:
                    user = match.group(1)

                    fecha_cambio_match = re.search(r'(\w{3} \d+ \d+:\d+:\d+)', line) 
                    if fecha_cambio_match:
                        fecha_cambio_str = f"{fecha_cambio_match.group(1)} {fecha_actual.year}"
                        fecha_cambio = datetime.strptime(fecha_cambio_str, '%b %d %H:%M:%S %Y')

                        diferencia = fecha_actual - fecha_cambio
                        if 0 <= diferencia.days <= dias_check:
                            fecha_cambio_str_formato = fecha_cambio.strftime('%Y-%m-%d %H:%M:%S')
                            change_passwd.append({
                                "info": f"[AVISO] El usuario {user} ha cambiado la contrasela el: {fecha_cambio_str_formato}",
                                "infoTypeID": 2
                            })

            if 'sudo' in line and 'COMMAND' in line:
                match = re.search(r'sudo: (.+) :', line)
                if match:
                    user = match.group(1)
                    fecha_cambio_match = re.search(r'(\w{3} \d+ \d+:\d+:\d+)', line) 
                    if fecha_cambio_match:
                        fecha_cambio_str = f"{fecha_cambio_match.group(1)} {fecha_actual.year}"
                        fecha_cambio = datetime.strptime(fecha_cambio_str, '%b %d %H:%M:%S %Y')

                        diferencia = fecha_actual - fecha_cambio
                        if 0 <= diferencia.days <= dias_check:
                            fecha_cambio_str_formato = fecha_cambio.strftime('%Y-%m-%d %H:%M:%S')
                            users_sudo.append({
                                "info": f"[AVISO] El usuario {user} ha usado SUDO a las {fecha_cambio_str_formato}" ,
                                "infoTypeID": 2
                            })


            if 'ssh' in line and 'Failed' in line:
                match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(1)
                    fecha_cambio_match = re.search(r'(\w{3} \d+ \d+:\d+:\d+)', line) 
                    if fecha_cambio_match:
                        fecha_cambio_str = f"{fecha_cambio_match.group(1)} {fecha_actual.year}"
                        fecha_cambio = datetime.strptime(fecha_cambio_str, '%b %d %H:%M:%S %Y')

                        diferencia = fecha_actual - fecha_cambio
                        if 0 <= diferencia.days <= dias_check:
                            fecha_cambio_str_formato = fecha_cambio.strftime('%Y-%m-%d %H:%M:%S')
                            tries_filed_ip[ip] += 1
       

        ip_failed = {ip: tries for ip, tries in tries_filed_ip.items() if tries > max_tries}


        for ip_fail in ip_failed:
            users_sudo.append({
                        "info": f"[PELIGRO] La IP {ip_fail} tiene {ip_failed[ip_fail]} intentos fallidos",
                        "infoTypeID": 3
            })


        finalInformation = change_passwd + users_sudo + ipInfo

        return finalInformation 
