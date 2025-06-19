import os
import subprocess
import pickle


# Hallazgo: Nombre de clase corto
class a:
    # Hallazgo: Secreto en el código
    api_key = "SECRET_KEY_12345"

    # Hallazgo: Nombre de función corto
    def r(self, cmd):
        # Hallazgo: Llamada peligrosa
        os.system(cmd) 
        
        # Hallazgo: Llamada peligrosa (especialmente con shell=True)
        subprocess.run("ls -l", shell=True) 

# Hallazgo: Bloque except vacío/inútil
try:
    # Algo que podría fallar
    data = {'key': 'value'}
    pickle.loads(data) # Esto dará error, pero lo ignoramos
except:
    pass

# Hallazgo: Punto de entrada principal
if __name__ == "__main__":
    app = a()
    # Hallazgo: Acceso a ruta sensible
    user_home = "/home/user"
    app.r("echo 'hello'")
    os.path.abspath(__file__)