

"""
    Título: Model
    Nombre: Héctor Paredes Benavides y Sergio Bermúdez Fernández
    Descripción: Modelo del agente de InsightForensics
    Fecha: 16/10/2023
    Última Modificación: 20/10/2023
"""

# ========== IMPORTADO DE BIBLIOTECAS ==========
import re
from colorama import Fore

# Controller
from controller.controller import controllerFindRecentModifiedFiles, controllerFindExecutableFiles, \
    controllerFindFilesByExtensions, readFileContent

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

# ========== CODIFICACIÓN DE FUNCIONES ==========
def modelSearchRecentlyModifiedFiles():

    # Variables necesarias
    filteredResult = []
    finalInformation = []
    
    # Obtenemos los ficheros modificados en los útlimos minutos
    result = controllerFindRecentModifiedFiles(RECENT_FILES_TIME)

    # Filtramos el input de find para quedarnos con los strings que no contengan directorios modificados por el sistema, separados por un único espacio
    filteredResult = list(
        map(
            lambda x: re.sub(' +', ' ', x), 
            filter(
                lambda x: not any(directory in x for directory in SYSTEM_DIRECTORY_FILTER), 
                result["value"].split("\n")
            )
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

def modelAnalyzeSuspiciousFiles(files, indexes):

    # Variables necesarias
    filesToAnalyze = []
    filesResults = []
    finalInformation = []

    # Obtenemos todas las rutas de los ficheros a analizar en función de la lista de ficheros y los índices seleccionados
    for index in indexes:
        filesToAnalyze.append(files[index])
    
    # Mandamos las rutas de los ficheros a analizar al controlador y obtenemos los resultados de los ficheros
    
    # Preparamos el resultado para devolverlo a la vista

    # Retornamos los resultados procesados
    return finalInformation