import re

# --- 1. DEFINICIONES DE TIPOS DE HALLAZGOS ESTANDARIZADOS (GLOBALES) ---
# Estos son los 'finding_type's que se usarán en todos los informes de SAST.

FINDING_TYPE_CODE_EXECUTION = "CODE_EXECUTION"
FINDING_TYPE_FILE_SYSTEM_ACCESS = "FILE_SYSTEM_ACCESS"
FINDING_TYPE_NETWORK_COMMUNICATION = "NETWORK_COMMUNICATION"
FINDING_TYPE_CRYPTOGRAPHIC_USE = "CRYPTOGRAPHIC_USE"
FINDING_TYPE_HARDCODED_CREDENTIALS = "HARDCODED_CREDENTIALS"
FINDING_TYPE_OBFUSCATION_TECHNIQUE = "OBFUSCATION_TECHNIQUE"
FINDING_TYPE_IMPROPER_ERROR_HANDLING = "IMPROPER_ERROR_HANDLING"
FINDING_TYPE_SELF_AWARE_BEHAVIOR = "SELF_AWARE_BEHAVIOR"
FINDING_TYPE_SENSITIVE_DATA_ACCESS = "SENSITIVE_DATA_ACCESS"
FINDING_TYPE_SYSTEM_INFO_ACCESS = "SYSTEM_INFO_ACCESS"

# --- 2. REGEX GLOBAL PARA RUTAS SENSIBLES (UNIFICADO) ---
# Este regex se usará en todos los listeners que necesiten detectar rutas sensibles.
# Se define una vez aquí y se comparte entre las clases.
SENSITIVE_PATH_REGEX_GLOBAL = re.compile(
    r"(C:\\\\|C:/|/)(Windows|Users|System32|Program Files|etc|root|home|var/log|bin|passwd|s?bin|usr|opt|srv|mnt|media|dev|proc|tmp|var|run|lib|usr/local|usr/share|var/tmp|var/run|sys|boot|init|lost\\+found|sbin|var/spool|var/mail|var/cache|var/lib|var/backups|etc/ssh|etc/passwd|etc/shadow|~/\.ssh)", 
    re.IGNORECASE
)

# --- 3. CLASE BASE PARA LAS DEFINICIONES DE FIRMAS ---
class BaseSignatures:
    """
    Clase base abstracta para definir la estructura común de las firmas de seguridad
    por lenguaje.
    """
    # Estos diccionarios deben ser sobrescritos por las clases hijas en caso de que se necesiten
    # firmas específicas para el lenguaje.
    
    IMPORTS = {}
    METHOD_CALLS = {}
    STRING_KEYWORDS = { # Para buscar en strings literales
        "password": {"type": FINDING_TYPE_HARDCODED_CREDENTIALS, "severity": "HIGH", "desc": "Posible secreto/credencial."},
        "secret": {"type": FINDING_TYPE_HARDCODED_CREDENTIALS, "severity": "HIGH", "desc": "Posible secreto/credencial."},
        "apikey": {"type": FINDING_TYPE_HARDCODED_CREDENTIALS, "severity": "HIGH", "desc": "Posible secreto/credencial."},
        "privatekey": {"type": FINDING_TYPE_HARDCODED_CREDENTIALS, "severity": "HIGH", "desc": "Posible secreto/credencial."},
        "token": {"type": FINDING_TYPE_HARDCODED_CREDENTIALS, "severity": "HIGH", "desc": "Posible secreto/credencial."}
    }
    NAMING_CONVENTIONS = { # Estos patrones son detectados por lógica en el listener, no por un diccionario directo
        "OBFUSCATED_CLASS_SHORT_NAME": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "desc": "Nombre de clase sospechosamente corto o generado dinámicamente."},
        "OBFUSCATED_METHOD_SHORT_NAME": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "desc": "Nombre de método sospechosamente corto."},
    }
    STRUCTURAL_PATTERNS = {}

    def __init__(self):
        # La regex global se accede directamente desde la clase BaseSignatures
        # o desde cualquier clase que herede de ella.
        pass

# --- 4. CLASES DE FIRMAS ESPECÍFICAS POR LENGUAJE ---

class JavaSignatures(BaseSignatures):
    """
    Define las firmas de seguridad específicas para el lenguaje Java.
    """
    IMPORTS = {
        "java.io.File": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "desc": "Capacidad de manipulación de archivos."},
        "java.io.FileOutputStream": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "desc": "Capacidad de escritura de archivos, potencial para cifrado/sobreescritura."},
        "java.nio.file.Files": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "desc": "Capacidades avanzadas de manipulación de archivos (escritura, borrado)."},
        "javax.crypto": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "desc": "Uso de la API de Criptografía de Java (potencial para cifrado de archivos)."},
        "java.net": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "desc": "Capacidad de comunicación por red (potencial para exfiltración o C2)."}
    }

    METHOD_CALLS = {
        "Runtime.getRuntime().exec": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "desc": "Ejecución de comandos nativos del sistema operativo."},
        "System.exit": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "LOW", "desc": "Llamada para terminar la ejecución del programa (control de flujo)."},
        ".delete": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "desc": "Llamada a la eliminación de archivos."},
        "getClass().getProtectionDomain().getCodeSource().getLocation": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "HIGH", "desc": "Código que intenta localizar su propia ruta de ejecución."}
    }

    STRUCTURAL_PATTERNS = { # Estos patrones son detectados por lógica en el listener, no por un diccionario directo
        "EMPTY_CATCH_BLOCK": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "MEDIUM", "desc": "Bloque catch vacío que puede ocultar errores críticos."},
        "SUSPICIOUS_OVERRIDE": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "desc": "Método sobreescrito con cuerpo vacío o muy simple, posible técnica de evasión."},
        "SELF_AWARE_CODE_FILE_DOT": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "MEDIUM", "desc": "El código accede al directorio actual ('new File(\".\")'), posible preludio a auto-modificación."},
        "SENSITIVE_PATH_ACCESS": {"type": FINDING_TYPE_SENSITIVE_DATA_ACCESS, "severity": "HIGH", "desc": "Acceso a rutas sensibles del sistema (ej. /etc/passwd, C:\\Windows)."}
    }
    

class PythonSignatures(BaseSignatures):
    """
    Define las firmas de seguridad específicas para el lenguaje Python.
    """
    IMPORTS = {
        "os": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "desc": "Capacidad de interactuar con el sistema de archivos/SO."},
        "subprocess": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "desc": "Capacidad de crear y gestionar subprocesos, potencial para ejecución de comandos."},
        "socket": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "desc": "Capacidad de comunicación por red de bajo nivel."},
        "urllib": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "desc": "Capacidad de realizar peticiones de red."},
        "requests": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "desc": "Capacidad de realizar peticiones HTTP/S."},
        "cryptography": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "desc": "Uso de una librería de criptografía popular."},
        "shutil": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "desc": "Capacidad de realizar operaciones de archivo destructivas (ej. rmtree)."},
        "sys": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "LOW", "desc": "Acceso a parámetros del sistema e intérprete."},
        "io": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "desc": "Capacidad de manipular streams de E/S."}
    }

    METHOD_CALLS = { # Aquí incluimos los patrones como 'eval(', 'exec(', 'os.system('
        "eval(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "desc": "Ejecución de código dinámico a partir de un string."},
        "exec(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "desc": "Ejecución de código dinámico."},
        "os.system(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "desc": "Ejecución de un comando en el shell del sistema."},
        "subprocess.run": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "desc": "Ejecución de un comando externo (riesgoso si se usa con shell=True)."},
        "pickle.load": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "desc": "Deserialización de datos con pickle, puede llevar a ejecución de código arbitrario."},
        "open(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "desc": "Acceso genérico a archivos."}
    }

    STRUCTURAL_PATTERNS = {
        "EMPTY_EXCEPT_BLOCK": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "MEDIUM", "desc": "Bloque 'except' vacío que puede ocultar errores críticos."},
        "SUSPICIOUS_PASS_BODY": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "desc": "Función con cuerpo 'pass', posible evasión o técnica de ofuscación."},
        "SELF_AWARE_CODE_PATH": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "HIGH", "desc": "El código intenta acceder a su propia ruta de ejecución."},
        "SENSITIVE_PATH_ACCESS": {"type": FINDING_TYPE_SENSITIVE_DATA_ACCESS, "severity": "HIGH", "desc": "Acceso a rutas sensibles del sistema (ej. /etc/passwd, C:\\Windows)."},
    }