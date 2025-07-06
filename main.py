# api/code_analyzer/main.py

import os
import json
from handleListeners.HandleListeners import AntlrListenerHandler


ROOT_DIR_FOR_TESTS = os.path.abspath(os.path.join(os.path.dirname(__file__), 'codeSamples')) 


# Para tu estructura que me indicaste
JAVA_SAMPLE_FILE = os.path.join(ROOT_DIR_FOR_TESTS, 'Java', 'SuspiciousSample.java')
JAVA_SAMPLE_FILE_2 = os.path.join(ROOT_DIR_FOR_TESTS, 'Java', 'vulnerable_sample.java') # Otro archivo de prueba Java
PYTHON_SAMPLE_FILE = os.path.join(ROOT_DIR_FOR_TESTS, 'Python', 'vulnerable_sample.py')
UNSUPPORTED_FILE = os.path.join(ROOT_DIR_FOR_TESTS, 'unsupported.xyz') # Archivo de prueba para lenguaje no soportado
MALFORMED_PYTHON_FILE = os.path.join(ROOT_DIR_FOR_TESTS, 'Python', 'malformed_sample.py') # Archivo para probar errores de parsing
C_SAMPLE_FILE = os.path.join(ROOT_DIR_FOR_TESTS, 'C', 'vulnerable_sample.c') # Archivo de prueba C
CPP_SAMPLE_FILE = os.path.join(ROOT_DIR_FOR_TESTS, 'Cpp', 'vulnerable_sample.cpp') # Archivo de prueba C++


def run_analysis_tests():
    handler = AntlrListenerHandler()

    reports_to_run = [
        # JAVA_SAMPLE_FILE,
        # JAVA_SAMPLE_FILE_2,  # Añadido otro archivo Java para pruebas
        # PYTHON_SAMPLE_FILE,
        # UNSUPPORTED_FILE,
        # MALFORMED_PYTHON_FILE,
        # C_SAMPLE_FILE
        CPP_SAMPLE_FILE
    ]

    for file_path in reports_to_run:
        print(f"\n\n===== Analizando archivo: {file_path} =====")
        try:
            report = handler.analyze_file(file_path)
            print(json.dumps(report, indent=4, ensure_ascii=False))
        except Exception as e:
            print(f"ERROR FATAL al procesar {file_path}: {e}")

    # --- Opcional: Ejecutar análisis de un directorio completo ---
    # print(f"\n\n===== Analizando directorio: {ROOT_DIR_FOR_TESTS} =====")
    # all_reports = handler.analyze_directory(ROOT_DIR_FOR_TESTS)
    # for report in all_reports:
    #     print(json.dumps(report, indent=4, ensure_ascii=False))
    #     print("\n-------------------------------------------------\n")

    print("\nAnálisis de ANTLR4 de prueba finalizado.")


if __name__ == "__main__":
    run_analysis_tests()