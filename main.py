import sys
import json # Usaremos json para imprimir el diccionario de forma legible
from handleListeners.HandleListeners import HandleListeners



if __name__ == '__main__':
    path_list = ['codeSamples/Java/SuspiciousSample.java', 'codeSamples/Python/vulnerable_sample.py', 'jandle.hn']

    # Analizamos el nuevo archivo
    for file_path in path_list:
        try:
            handle_object = HandleListeners(file_path=file_path)
            print(f"Language detected: {handle_object.language}")
            print(f"Report for {file_path}:")
            report = handle_object.report
            print(json.dumps(report, indent=4, ensure_ascii=False))  # Imprimimos el reporte de forma legible
            
        except ValueError as e:
            print(f"Error: {e}")
            continue
        except NotImplementedError as e:
            print(f"Error: {e}")
        # except Exception as e:
        #     print(f"An unexpected error occurred: {e}")