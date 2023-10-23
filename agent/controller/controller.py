

"""
    Título: Controller
    Nombre: Héctor Paredes Benavides y Sergio Bermúdez Fernández
    Descripción: Controlador de InsightForensics
    Fecha: 16/10/2023
    Última Modificación: 20/10/2023
"""

# ========== IMPORTADO DE BIBLIOTECAS ==========
import subprocess

# ========== DECLARACIONES GLOBALES ==========

# ========== CODIFICACIÓN DE FUNCIONES ==========
def controllerFindRecentModifiedFiles(time):

    # Realizamos la búsqueda de ficheros modificados recientemente
    return executeCommand(["find", "/", "-cmin", "-" + str(time), "-ls"])

def controllerFindExecutableFiles(path):

    # Realizamos la búsqueda de archivos ejecutables en la ruta que se pasa como argumento
    return executeCommand(["find", path, "-executable", "-type", "f"])

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

def executeCommand(subprocessCommand):

    # Ejecutamos el comando
    proc = subprocess.Popen(subprocessCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Obtenemos el output
    output = str(proc.stdout.read(), "UTF-8")

    # Preparamos el retorno
    contentToReturn = {
        "error": False,
        "value": output
    }

    return contentToReturn

def readFileContent(path):

    # Variables necesarias
    fileContent = ""

    # Abrimos el fichero y leemos el contenido
    with open(path, "r") as file:
        fileContent = file.read()
    
    # Retornamos el contenido del fichero
    return fileContent
