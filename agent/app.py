

"""
    Título: App (InsightForensics)
    Nombre: Héctor Paredes Benavides y Sergio Bermúdez Fernández
    Descripción: Script para ejecutar el agente de InsightForensics
    Fecha: 16/10/2023
    Última Modificación: 25/10/2023
"""

# ========== IMPORTADO DE BIBLIOTECAS ==========
import argparse
import os

from view.view import startInteractiveMode

# ========== DECLARACIONES GLOBALES ==========

# ========== FUNCIÓN PRINCIPAL MAIN ==========
"""
    Nombre: Main
    Descripción: Función con la que inicializamos el programa
    Parámetros: Ninguno
    Retorno: Ninguno
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def main():
    
    # Variables necesarias
    args = getArgs()

    interactive = args.interactive
    virusTotalAPIKey = args.virustotal_key

    # Comprobamos que no estemos en un sistema Windows
    if os.name == "nt":
        print("ERROR: Este programa no está pensado para ejecutarse en Windows...")
        exit(1)

    # Si se selecciona interactive inicializamos la vista, sino, el conector con la API
    if interactive:
        startInteractiveMode(virusTotalAPIKey)
    else:
        print("API - Not implemented yet...")

"""
    Nombre: Get Args
    Descripción: Función con la que obtenemos los argumentos del programa
    Parámetros: Ninguno
    Retorno: [OBJECT] Objeto con los argumentos
    Precondición: Ninguna
    Complejidad Temporal: O(1)
    Complejdiad Espacial: O(1)
"""
def getArgs():

    # Variables necesarias
    parser = argparse.ArgumentParser(description="InsightForensics - Framework de análisis forense en Linux")

    # Argumentos
    parser.add_argument("-I", "--interactive", required=False, action="store_true", help="Modo interactivo - Interacción por CLI, sin conexión con API")
    parser.add_argument("-K", "--virustotal-key", required=False, help="API Key de VirusTotal")

    return parser.parse_args()

# ========== CODIFICACIÓN DE FUNCIONES ==========

# ========== EJECUCIÓN PRINCIPAL ==========
if __name__ == "__main__":
    main()