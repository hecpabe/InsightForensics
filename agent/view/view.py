

"""
    Título: View
    Nombre: Héctor Paredes Benavides y Sergio Bermúdez Fernández
    Descripción: Vista del agente de InsightForensics
    Fecha: 16/10/2023
    Última Modificación: 09/11/2023
"""

# ========== IMPORTADO DE BIBLIOTECAS ==========
from colorama import Fore
import os

from model.model import modelSearchRecentlyModifiedFiles, modelSearchSuspectFiles, modelAnalyzeSuspiciousFiles, \
    modelSystemPathAnalysis, modelEditableRootFilesSearch, modelEtcHostsCheck, modelCapabilitiesCheck, modelGroupsCheck, \
    modelSSHKeySearch, modelEnvironmentVariablesCheck

# ========== FUNCIÓN PRINCIPAL MAIN ==========
"""
    Nombre: Start interactive mode
    Descripción: Función con la que inicializamos la aplicación en modo interactivo (por CLI en vez de por API)
    Parámetros:
        0: [STRING] API Key de VirusTotal
    Retorno: Ninguno
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def startInteractiveMode(virusTotalAPIKey):
    
    # Almacenamos la clave de la API de VirusTotal
    global GLOB_virusTotalAPIKey
    GLOB_virusTotalAPIKey = virusTotalAPIKey

    # Ejecutamos el menú principal
    mainMenu()

# ========== CODIFICACIÓN DE FUNCIONES ==========
"""
    Nombre: Main menu
    Descripción: Función con la que gestionamos la ejecución del menu principal de la aplicación
    Parámetros: Ninguno
    Retorno: Ninguno
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad de ejecuciones
    Complejidad Espacial: O(1)
"""
def mainMenu():

    # Variables necesarias
    executing = True
    select = 0

    while executing:

        # Imprimimos el menú principal
        printSpacer("Menú Principal")
        try:
            
            # Imprimimos las opciones del menú principal
            for option in MAIN_MENU_OPTIONS:
                print(option["name"])
            
            # Recogemos la selección
            select = int(input("Selección: "))
            select -= 1

            # Ejecutamos la selección
            if select >= 0 and select < len(MAIN_MENU_OPTIONS):
                executing = MAIN_MENU_OPTIONS[select]["function"]()
            else:
                printError("Se ha introducido un valor fuera de rango")

        except Exception as e:
            printError("Error al recoger la selección", e)
        
        # Limpiamos la terminal
        if executing:
            clearConsole()

"""
    Nombre: Print Spacer
    Descripción: Función para imprimir un separador
    Parámetros:
        0: [STRING] Texto a imprimir en el separador
    Retorno: Ninguno
    Precondición: El
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def printSpacer(textInSpacer):

    # Obtenemos la longitud del texto
    textLength = len(textInSpacer)

    # Imprimimos el spacer
    print()
    print(Fore.BLUE + "                              ╔" + ("═" * (textLength + 2)) + "╗")
    print("══════════════════════════════╣ " + Fore.GREEN + textInSpacer + Fore.BLUE + " ╠══════════════════════════════")
    print("                              ╚" + ("═" * (textLength + 2)) + "╝" + Fore.RESET)
    print()

"""
    Nombre: Print Error
    Descripción: Función con la que imprimimos un error
    Parámetros:
        0: [STRING] Texto de error
        1: [EXCEPTION] Excepción causante
        2: [BOOL] Necesidad de finalizar el programa
    Retorno: Ninguno
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def printError(errorString, exception=None, exitNeeded=False):
    print(Fore.MAGENTA + "[X] ERROR: " + errorString + Fore.RESET)
    if exception:
        print(Fore.MAGENTA + "Exception: " + str(exception) + Fore.RESET)
    if exitNeeded:
        exit(1)

"""
    Nombre: Clear console
    Descripción: Función con la que limpiamos la terminal
    Parámetros: Ninguno
    Retorno: Ninguno
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def clearConsole():
    input("Pulsa la tecla INTRO para continuar...")
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")

"""
    Nombre: Print Scan Info
    Descripción: Función con la que mostramos la leyenda del escaneo
    Parámetros: Ninguno
    Retorno: Ninguno
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad de tipos de información
    Complejidad Espacial: O(1)
"""
def printScanInfo():

    # Limpiamos la pantalla para empezar el escaneo
    clearConsole()

    # Mostramos la cabecera de la leyenda
    printSpacer("Leyenda")

    # Mostramos la leyenda
    for scanInfoType in SCAN_INFO_TYPES:
        color = scanInfoType["color"]
        colorString = scanInfoType["colorString"]
        infoType = scanInfoType["type"]
        print(f"{color}[-] {colorString}: {infoType}{Fore.RESET}")

"""
    Nombre: Full scan
    Descripción: Función con la que realizamos el escaneo completo del sistema
    Parámetros: Ninguno
    Retorno: [BOOL] Si el menu principal continua o no
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def fullScan():

    # Mostramos la leyenda del escaneo
    printScanInfo()

    # Escaneamos el sistema
    fileSystemAnalysis(False)
    systemPathAnalysis(False)
    editableRootFilesSearch(False)
    etcHostsCheck(False)
    capabilitiesCheck(False)
    groupsCheck(False)
    sshKeySearch(False)
    environmentVariablesCheck(False)

    return True

"""
    Nombre: Filesystem analysis
    Descripción: Función con la que escaneamos el sistema de ficheros
    Parámetros:
        0: [BOOL] Parámetro que indica si se debe de mostrar la leyenda de información o no
    Retorno: [BOOL] Si el menu principal continua o no
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de ficheros obtenidos
"""
def fileSystemAnalysis(showInfo=True):

    # Variables necesarias
    recentlyModifiedFiles = []
    suspectFiles = []

    try:
        recentlyModifiedFileTime = int(input("Introduzca la cantidad de minutos desde que se ha modificado un archivo para considerarlo reciente: "))
    except:
        printError("No se ha podido interpretar el tiempo introducido, estableciendo el por defecto...")
        recentlyModifiedFileTime = -1

    # Mostramos la leyenda del escaneo
    if showInfo:
        printScanInfo()

    # Realizamos el escaneo de ficheros modificados recientemente
    printSpacer("Ficheros modificados recientemente")
    recentlyModifiedFiles = modelSearchRecentlyModifiedFiles(recentlyModifiedFileTime) if recentlyModifiedFileTime > 0 else modelSearchRecentlyModifiedFiles()
    printObtainedInfo(recentlyModifiedFiles)

    # Realizamos el escaneo de ficheros sospechosos
    printSpacer("Aplicaciones de terceros [INFO] y ejecutables sospechosos [WARN/DANGER]")
    suspectFiles = modelSearchSuspectFiles()
    printObtainedInfo(suspectFiles)

    # Agregamos a los ficheros sospechosos para posible escaneo la ruta de los ficheros modificados recientemente y los ficheros
    # sospechosos
    global GLOB_suspectFiles
    GLOB_suspectFiles = \
        list(map(lambda x: {"info": x["info"].split(" ")[::-1][0], "infoTypeID": x["infoTypeID"]}, recentlyModifiedFiles)) \
        + suspectFiles

    return True

"""
    Nombre: System PATH Analysis
    Descripción: Función con la que analizamos el PATH del sistema operativo en busca de ficheros .sh
    Parámetros:
        0: [BOOL] Si se muestra la leyenda o no
    Retorno: [BOOL] Si el menu principal continua o no
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de ficheros .sh en el PATH
"""
def systemPathAnalysis(showInfo=True):
    
    # Variables necesarias
    shFilesInPath = []

    # Mostramos la leyenda del escaneo
    if showInfo:
        printScanInfo()
    
    # Realizamos el escaneo de ficheros .sh en el PATH
    printSpacer("Ficheros .sh en el PATH")
    shFilesInPath = modelSystemPathAnalysis()
    printObtainedInfo(shFilesInPath)

    # Agregamos los ficheros encontrados
    global GLOB_shFilesInPath
    GLOB_shFilesInPath = shFilesInPath

    return True

"""
    Nombre: Editable root files search
    Descripción: Función con la que obtenemos todos los ficheros de root editables por cualquiera
    Parámetros: 
        0: [BOOL] Si se muestra la leyenda o no
    Retorno: [BOOL] Si el menu principal continua o no
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de ficheros encontrados
"""
def editableRootFilesSearch(showInfo=True):
    
    # Variables necesarias
    editableRootFiles = []

    # Mostramos la leyenda del escaneo
    if showInfo:
        printScanInfo()
    
    # Realizamos el escaneo de ficheros de root editables por cualquiera
    printSpacer("Ficheros de root editables por cualquiera")
    editableRootFiles = modelEditableRootFilesSearch()
    printObtainedInfo(editableRootFiles)

    return True

"""
    Nombre: Etc hosts check
    Descripción: Función con la que obtenemos y mostramos los hosts de un sistema
    Parámetros:
        0: [BOOL] Si se muestra la leyenda o no
    Retorno: [BOOL] Si el menu principal continua o no
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de hosts
"""
def etcHostsCheck(showInfo=True):

    # Variables necesarias
    hosts = []

    # Mostramos la leyenda del escaneo
    if showInfo:
        printScanInfo()

    # Realizamos el escaneo del fichero /etc/hosts
    printSpacer("Hosts del sistema")
    hosts = modelEtcHostsCheck()
    printObtainedInfo(hosts)
    
    return True

"""
    Nombre: Capabilities check
    Descripción: Función con la que obtenemos las capabilities en función de si son peligrosas o no y las mostramos por pantalla
    Parámetros: 
        0: [BOOL] Si se muestra la leyenda o no
    Retorno: [BOOL] Si el menu principal continua o no
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de programas con capabilities
"""
def capabilitiesCheck(showInfo=True):
    
    # Variables necesarias
    capabilities = []

    # Mostramos la leyenda del escaneo
    if showInfo:
        printScanInfo()
    
    # Realizamos la comprobación de las capabilities
    printSpacer("Capabilities")
    capabilities = modelCapabilitiesCheck()
    printObtainedInfo(capabilities)

    return True

"""
    Nombre: Groups check
    Descripción: Función con la que comprobamos los grupos del sistema y mostramos la información
    Parámetros: 
        0: [BOOL] Si se muestra la leyenda o no
    Retorno: [BOOL] Si el menu principal continua o no
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de grupos en el fichero /etc/group
"""
def groupsCheck(showInfo=True):
    
    # Variables necesarias
    groups = []

    # Mostramos la leyenda del escaneo
    if showInfo:
        printScanInfo()
    
    # Realizamos la comprobación de los grupos
    printSpacer("Grupos del sistema")
    groups = modelGroupsCheck()
    printObtainedInfo(groups)

    return True

"""
    Nombre: SSH key search
    Descripción: Función con la que buscamos claves SSH (.pem y .ppk) en el sistema y las mostramos
    Parámetros: 
        0: [BOOL] Si se muestra la leyenda o no
    Retorno: [BOOL] Si el menu principal continua o no
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de claves encontradas
"""
def sshKeySearch(showInfo=True):

    # Variables necesarias
    sshKeys = []

    # Mostramos la leyenda del escaneo
    if showInfo:
        printScanInfo()
    
    # Realizamos la búsqueda de claves SSH
    printSpacer("Claves SSH")
    sshKeys = modelSSHKeySearch("/")
    printObtainedInfo(sshKeys)

    return True

"""
    Nombre: Environment variables check
    Descripción: Función con la que comprobamos las variables de entorno del sistema y las mostramos
    Parámetros: 
        0: [BOOL] Si se muestra la leyenda o no
    Retorno: [BOOL] Si el menu principal continua o no
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de variables de entorno
"""
def environmentVariablesCheck(showInfo=True):

    # Variables necesarias
    environmentVariables = []

    # Mostramos la leyenda del escaneo
    if showInfo:
        printScanInfo()

    # Realizamos la comprobación de variables de entorno
    printSpacer("Variables de entorno")
    environmentVariables = modelEnvironmentVariablesCheck()
    printObtainedInfo(environmentVariables)

    return True

"""
    Nombre: Suspect file analysis
    Descripción: Función con la que analizamos uno o más ficheros mediante la API de VirusTotal
    Parámetros: Ninguno
    Retorno: [BOOL] Si el menu principal continua o no
    Complejidad Temporal: O(n) n -> Cantidad de ficheros obtenidos
    Complejidad Espacial: O(n) n -> Cantidad de ficheros obtenidos
"""
def suspectFileAnalysis():
    
    # Variables necesarias
    infoFiles = []
    warningFiles = []
    dangerFiles = []

    sortedFiles = []
    sortedFilesLength = 0

    choose = 0
    filesToAnalyze = []

    analyzedFilesResults = []

    # Separamos todos los ficheros detectados en las diferentes categorias
    for file in GLOB_suspectFiles + GLOB_shFilesInPath:
        infoTypeID = file["infoTypeID"]
        if infoTypeID == 0:
            infoFiles.append(file)
        elif infoTypeID == 2:
            warningFiles.append(file)
        else:
            dangerFiles.append(file)
    
    sortedFiles = infoFiles + warningFiles + dangerFiles
    sortedFilesLength = len(sortedFiles)

    # Mostramos todos los ficheros detectados
    printSpacer("Conjunto de ficheros detectados")

    for i in range(sortedFilesLength):
        index = i+1
        file = sortedFiles[i]
        fileInfo = file["info"]
        fileInfoTypeID = file["infoTypeID"]
        color = SCAN_INFO_TYPES[fileInfoTypeID]["color"]
        fileInfoType = SCAN_INFO_TYPES[fileInfoTypeID]["type"]
        print(f"{color}{index}.- [{fileInfoType}] {fileInfo}{Fore.RESET}")

    # Obtenemos la selección de ficheros a analizar
    choose = input("Seleccione los ficheros a analizar (1 | 1,2,3,... | 1-5 | 1-5,7-10 | 1-5,7): ")

    # Evaluamos la selección de ficheros a analizar
    # Transformamos el formato a una única lista de enteros con los índices de los ficheros a analizar
    filesToAnalyze = evalFilesToAnalyze(choose)

    # Analizamos los ficheros seleccionados y obtenemos el resultado para mostrarlo
    analyzedFilesResults = modelAnalyzeSuspiciousFiles(sortedFiles, filesToAnalyze, GLOB_virusTotalAPIKey)

    # Mostramos la información obtenida
    clearConsole()
    printScanInfo()
    printSpacer("Resultados del escaneo")
    printObtainedInfo(analyzedFilesResults)

    return True

"""
    Nombre: Print obtained info
    Descripción: Función con la que mostramos de forma correcta el output de las funciones
    Parámetros:
        0: [LIST] Lista con la información obtenida de las funciones
    Retorno: Ninguno
    Precondición: Ninguna
    Complejidad Temporal: O(n) n -> Cantidad de líneas a printear
    Complejidad Espacial: O(1)
"""
def printObtainedInfo(infoList):

    # Mostramos la información con su correspondiente color
    for info in infoList:
        infoString = info["info"]
        infoTypeID = info["infoTypeID"]
        color = SCAN_INFO_TYPES[infoTypeID]["color"]
        print(f"{color}{infoString}{Fore.RESET}")

"""
    Nombre: Eval files to analyze
    Descripción: Función con la que parseamos el string con los índices de ficheros a escaneas en una lista numérica con estos
    Parámetros: [STRING] String con los índices a parsear
    Retorno: [LIST] Lista numérica con los índices a parsear
    Precondición: El string debe estar correctamente formateado
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(n) n -> Cantidad de ficheros a analizar
"""
def evalFilesToAnalyze(files):

    # Variables necesarias
    singleFiles = []

    # Si hay comas separamos cada parte y las evaluamos por separado
    if "," in files:
        for fileSplitted in files.split(","):
            singleFiles += evalFilesToAnalyze(fileSplitted)
    # Sino, preparamos el array de enteros a retornar, en caso de que haya - es un rango
    elif "-" in files:
        rangeStart, rangeEnd = map(lambda x: int(x), files.split("-"))
        singleFiles = list(range(rangeStart - 1, rangeEnd))
    # Sino, es un número suelto, por lo que lo añadimos convertido a entero
    else:
        singleFiles.append(int(files))
    
    # Retornamos la lista de índices de ficheros a analizar eliminando posibles duplicados
    return list(set(singleFiles))

"""
    Nombre: Main Menu Exit
    Descripción: Función con la que nos salimos del menú principal
    Parámetros: Ninguno
    Retorno: [BOOL] Continuación del menú principal (False)
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def mainMenuExit():
    print("Finalizando programa...")
    return False

# ========== DECLARACIONES GLOBALES ==========
MAIN_MENU_OPTIONS = [
    {
        "name": "1.- [SCAN] Análisis total",
        "function": fullScan
    },
    {
        "name": "2.- [SCAN] Análisis del sistema de ficheros",
        "function": fileSystemAnalysis
    },
    {
        "name": "3.- [SCAN] Búsqueda de ficheros .sh en el path",
        "function": systemPathAnalysis
    },
    {
        "name": "4.- [SCAN] Búsqueda de ficheros de root editables por cualquiera",
        "function": editableRootFilesSearch
    },
    {
        "name": "5.- [SCAN] Hosts del equipo",
        "function": etcHostsCheck
    },
    {
        "name": "6.- [SCAN] Capabilities del equipo",
        "function": capabilitiesCheck
    },
    {
        "name": "7.- [SCAN] Grupos del sistema",
        "function": groupsCheck
    },
    {
        "name": "8.- [SCAN] Claves SSH en el sistema",
        "function": sshKeySearch
    },
    {
        "name": "9.- [SCAN] Variables de entorno del sistema",
        "function": environmentVariablesCheck
    },
    {
        "name": "10.- [ANÁLISIS] Análisis de ficheros sospechosos",
        "function": suspectFileAnalysis
    },
    {
        "name": "11.- Salir",
        "function": mainMenuExit
    }
]

SCAN_INFO_TYPES = [
    {
        "id": 0,
        "type": "Info",
        "color": Fore.BLUE,
        "colorString": "Azul"
    },
    {
        "id": 1,
        "type": "Sin peligro",
        "color": Fore.GREEN,
        "colorString": "Verde"
    },
    {
        "id": 2,
        "type": "Advertencia",
        "color": Fore.YELLOW,
        "colorString": "Amarillo"
    },
    {
        "id": 3,
        "type": "Peligro",
        "color": Fore.RED,
        "colorString": "Rojo"
    },
    {
        "id": 3,
        "type": "ERROR",
        "color": Fore.MAGENTA,
        "colorString": "Morado"
    }
]

GLOB_virusTotalAPIKey = ""
GLOB_suspectFiles = []
GLOB_shFilesInPath = []