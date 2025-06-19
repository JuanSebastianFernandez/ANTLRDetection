# Tipos de Hallazgos Estandarizados (Globales para VESTA SAST):

# CODE_EXECUTION: Ejecución de comandos o código arbitrario (alta severidad).
# FILE_SYSTEM_ACCESS: Acceso o manipulación de archivos (lectura, escritura, borrado).
# NETWORK_ACTIVITY: Comunicación a través de la red (envío/recepción de datos, conexiones).
# CRYPTOGRAPHIC_USE: Uso de APIs criptográficas (para cifrado/descifrado).
# HARDCODED_CREDENTIALS: Credenciales sensibles presentes directamente en el código.
# OBFUSCATION_TECHNIQUE: Técnicas para ocultar el código o dificultar el análisis.
# IMPROPER_ERROR_HANDLING: Manejo de errores que podría ocultar fallos de seguridad.
# SELF_AWARE_BEHAVIOR: El código intenta interactuar con su propio entorno de ejecución o ubicación.
# SENSITIVE_DATA_ACCESS: Acceso a rutas o datos sensibles del sistema.
# RESOURCE_MANIPULATION: Operaciones con compresión, descompresión o manipulación de recursos del programa.



SUSPICIOUS_IMPORTS = {
    "java.io.File": {"type": "FILE_SYSTEM_ACCESS", "severity": "INFO", "desc": "Capacidad de manipulación de archivos."},
    "java.io.FileOutputStream": {"type": "FILE_SYSTEM_ACCESS", "severity": "MEDIUM", "desc": "Capacidad de escritura de archivos, potencial para cifrado/sobreescritura."},
    "java.nio.file.Files": {"type": "FILE_SYSTEM_ACCESS", "severity": "MEDIUM", "desc": "Capacidades avanzadas de manipulación de archivos (escritura, borrado)."},
    "javax.crypto": {"type": "CRYPTOGRAPHIC_USE", "severity": "HIGH", "desc": "Uso de la API de Criptografía de Java (potencial para cifrado de archivos)."},
    "java.net": {"type": "NETWORK_COMMUNICATION", "severity": "MEDIUM", "desc": "Capacidad de comunicación por red (potencial para exfiltración o C2)."}
}

SUSPICIOUS_METHOD_CALLS = {
    "Runtime.getRuntime().exec": {"type": "CODE_EXECUTION", "severity": "CRITICAL", "desc": "Ejecución de comandos nativos del sistema operativo."},
    "System.exit": {"type": "CODE_EXECUTION", "severity": "LOW", "desc": "Llamada para terminar la ejecución del programa."}, # Considerado CODE_EXECUTION por control de flujo
    ".delete": {"type": "FILE_SYSTEM_ACCESS", "severity": "HIGH", "desc": "Llamada a la eliminación de archivos."},
    "getClass().getProtectionDomain().getCodeSource().getLocation": {"type": "SELF_AWARE_BEHAVIOR", "severity": "HIGH", "desc": "Código que intenta localizar su propia ruta de ejecución."}
}