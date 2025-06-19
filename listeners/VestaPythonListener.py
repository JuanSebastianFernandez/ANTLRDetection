# Este código iría en tu archivo: api/code_analyzer/listeners/VestaPythonListener.py

import re
import numpy as np
from antlr4 import CommonTokenStream, ParserRuleContext
from antlr4.tree.Tree import TerminalNode # Importar TerminalNode
# ¡IMPORTACIONES CORREGIDAS!
# Ajusta las rutas relativas según tu estructura de carpetas
from grammars.Python.PythonLexer import PythonLexer # Lexer para acceder a los tipos de token (ej. PythonLexer.NAME)
from grammars.Python.PythonParser import PythonParser # Parser para los tipos de contexto (ej. PythonParser.Class_defContext)
from grammars.Python.PythonParserListener import PythonParserListener # La clase base de la que heredamos


# --- Función de Entropía (se mantiene igual) ---
def calculate_entropy(data: bytes) -> float:
    if not data: return 0.0
    occurences = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = occurences / len(data)
    entropy = -np.sum([p * np.log2(p) for p in probabilities if p > 0])
    return entropy

# --- Base de Datos de Firmas de Seguridad para Python ---
SUSPICIOUS_IMPORTS_PYTHON = {
    "os": {"type": "SYSTEM_CAPABILITY", "severity": "INFO", "desc": "Capacidad de interactuar con el sistema operativo."},
    "subprocess": {"type": "PROCESS_CAPABILITY", "severity": "MEDIUM", "desc": "Capacidad de crear y gestionar subprocesos, potencial para ejecución de comandos."},
    "socket": {"type": "NETWORK_CAPABILITY", "severity": "MEDIUM", "desc": "Capacidad de comunicación por red de bajo nivel."},
    "urllib": {"type": "NETWORK_CAPABILITY", "severity": "MEDIUM", "desc": "Capacidad de realizar peticiones de red."},
    "requests": {"type": "NETWORK_CAPABILITY", "severity": "MEDIUM", "desc": "Capacidad de realizar peticiones HTTP/S."},
    "cryptography": {"type": "CRYPTO_CAPABILITY", "severity": "HIGH", "desc": "Uso de una librería de criptografía popular."},
    "shutil": {"type": "FILE_SYSTEM_DESTRUCTIVE_CAPABILITY", "severity": "HIGH", "desc": "Capacidad de realizar operaciones de archivo destructivas (ej. rmtree)."},
    "sys": {"type": "SYSTEM_INFO_ACCESS", "severity": "LOW", "desc": "Acceso a parámetros del sistema e intérprete."}, # Añadido por el uso de sys.argv
    "io": {"type": "FILE_IO_CAPABILITY", "severity": "INFO", "desc": "Capacidad de manipular streams de E/S."} # Añadido por open
}

DANGEROUS_PATTERNS_PYTHON = {
    "eval(": {"type": "DANGEROUS_FUNCTION_CALL", "severity": "CRITICAL", "desc": "Ejecución de código dinámico a partir de un string."},
    "exec(": {"type": "DANGEROUS_FUNCTION_CALL", "severity": "CRITICAL", "desc": "Ejecución de código dinámico."},
    "os.system(": {"type": "DANGEROUS_FUNCTION_CALL", "severity": "HIGH", "desc": "Ejecución de un comando en el shell del sistema."},
    "subprocess.run": {"type": "DANGEROUS_FUNCTION_CALL", "severity": "HIGH", "desc": "Ejecución de un comando externo (riesgoso si se usa con shell=True)."},
    "pickle.load": {"type": "DANGEROUS_FUNCTION_CALL", "severity": "HIGH", "desc": "Deserialización de datos con pickle, puede llevar a ejecución de código arbitrario."},
    "open(": {"type": "FILE_IO_ACCESS", "severity": "INFO", "desc": "Acceso genérico a archivos."} # Añadido por open
}

SENSITIVE_PATH_REGEX_PYTHON = re.compile(r"(/etc/|/root/|/home/|/var/log/|~/\.ssh)", re.IGNORECASE)


class VestaPythonListener(PythonParserListener):
    """
    Listener ANTLR4 diseñado para extraer un informe enriquecido del código fuente de Python,
    adaptado a la estructura de los parsers y lexers proporcionados.
    """
    def __init__(self, token_stream: CommonTokenStream):
        self.token_stream = token_stream
        self.static_findings = []
        
        # Recolección de datos para las 12 features
        self.function_entropies = []
        self.function_sizes = []
        self.string_entropies = []
        self.import_count = 0
        self.class_and_function_count = 0
        self.has_main_entry_point = 0
        self._finding_ids = set()

    def add_finding(self, finding: dict):
        # Usamos una tupla para comprobar la unicidad del hallazgo
        finding_id = (finding['finding_type'], finding['line'], finding['description'])
        if finding_id not in self._finding_ids:
            self.static_findings.append(finding)
            self._finding_ids.add(finding_id)

    # --- Métodos del Listener Adaptados ---

    # Regla: import_stmt
    def enterImport_stmt(self, ctx: PythonParser.Import_stmtContext):
        self.import_count += 1
        import_text = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)
        for pattern, details in SUSPICIOUS_IMPORTS_PYTHON.items():
            # re.escape para patrones con puntos (ej. os.path)
            if re.search(r'\b' + re.escape(pattern) + r'\b', import_text): 
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Import sospechoso detectado: '{pattern}'. Indica: {details['desc']}",
                    "line": ctx.start.line, "severity": details["severity"]
                })

    # Regla: class_def_raw (representa la definición cruda de la clase sin decoradores)
    def enterClass_def_raw(self, ctx: PythonParser.Class_def_rawContext):
        self.class_and_function_count += 1
        class_name = None
        # Accedemos al token NAME a través del método name() del contexto
        name_ctx = ctx.name()
        if name_ctx:
            class_name = name_ctx.getText()
        
        if class_name:
            if len(class_name) <= 2:
                self.add_finding({
                    "finding_type": "OBFUSCATED_CODE",
                    "description": f"Nombre de clase sospechosamente corto: '{class_name}'",
                    "line": ctx.start.line, "severity": "LOW"
                })
        else:
            self.add_finding({
                "finding_type": "OBFUSCATED_CODE", 
                "description": "Clase con nombre no identificable o estructura inesperada (posible ofuscación).",
                "line": ctx.start.line, "severity": "MEDIUM"
            })

    # Regla: function_def_raw (representa la definición cruda de la función sin decoradores)
    def exitFunction_def_raw(self, ctx: PythonParser.Function_def_rawContext):
        self.class_and_function_count += 1
        function_name = None
        name_ctx = ctx.name() # Accedemos al token NAME a través del método name()
        if name_ctx:
            function_name = name_ctx.getText()

        if function_name:
            if len(function_name) <= 2:
                self.add_finding({
                    "finding_type": "OBFUSCATED_CODE",
                    "description": f"Nombre de función sospechosamente corto: '{function_name}()'",
                    "line": ctx.start.line, "severity": "LOW"
                })
            # --- Detección: Polimorfismo y override sospechoso (adaptado para Python) ---
            # Un cuerpo de función que solo contiene 'pass' o es muy simple
            # La regla 'block' contiene una lista de 'statement'
            if ctx.block() and ctx.block().statements(): # Verifica que el bloque y statements existan
                statements = ctx.block().statements().statement()
                if len(statements) == 1:
                    stmt_text = self.token_stream.getText(statements[0].start.tokenIndex, statements[0].stop.tokenIndex)
                    if stmt_text.strip() == 'pass': # Si el único statement es 'pass'
                        self.add_finding({
                            "finding_type": "SUSPICIOUS_OVERRIDE", 
                            "description": f"Función '{function_name}' con cuerpo 'pass', posible evasión o técnica de ofuscación.",
                            "line": ctx.start.line, "severity": "MEDIUM"
                        })
        else:
            self.add_finding({
                "finding_type": "OBFUSCATED_CODE", 
                "description": "Función con nombre no identificable o estructura inesperada (posible ofuscación).",
                "line": ctx.start.line, "severity": "MEDIUM"
            })
            
        # Obtener el texto original de la función completa para entropía y tamaño
        start_index = ctx.start.tokenIndex
        stop_index = ctx.stop.tokenIndex
        function_text = self.token_stream.getText(start_index, stop_index)
        self.function_entropies.append(calculate_entropy(function_text.encode('utf-8')))
        self.function_sizes.append(len(function_text))

    # Regla: strings (que agrupa tokens STRING y FSTRING)
    def enterStrings(self, ctx: PythonParser.StringsContext):
        full_string_content = ""
        # La regla 'strings' puede contener 'fstring' o 'string' individuales
        for child in ctx.children:
            if isinstance(child, PythonParser.FstringContext):
                # Para f-strings, necesitamos obtener el texto del 'FSTRING_MIDDLE' y otros.
                # Simplificamos obteniendo el texto completo del fstring.
                full_string_content += self.token_stream.getText(child.start.tokenIndex, child.stop.tokenIndex)
            elif isinstance(child, PythonParser.StringContext):
                # Para strings normales, usamos getText() y luego eval para desquote.
                full_string_content += eval(child.getText())

        if full_string_content:
            self.string_entropies.append(calculate_entropy(full_string_content.encode('utf-8')))
            
            # Búsqueda de secretos y rutas sensibles
            if SENSITIVE_PATH_REGEX_PYTHON.search(full_string_content):
                self.add_finding({
                    "finding_type": "SENSITIVE_SYSTEM_PATH_ACCESS",
                    "description": "El código contiene un string que parece una ruta a un archivo/directorio sensible del sistema.",
                    "line": ctx.start.line, "severity": "MEDIUM"
                })
            sensitive_keywords = ['password', 'secret', 'apikey', 'privatekey', 'token']
            for keyword in sensitive_keywords:
                if re.search(keyword, full_string_content, re.IGNORECASE):
                    self.add_finding({
                        "finding_type": "HARDCODED_SECRET",
                        "description": f"Posible secreto/credencial encontrado en un string literal que contiene '{keyword}'",
                        "line": ctx.start.line, "severity": "HIGH"
                    })
    
    # Regla: simple_stmt (una sentencia simple)
    def enterSimple_stmt(self, ctx: PythonParser.Simple_stmtContext):
        statement_text = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)
        
        for pattern, details in DANGEROUS_PATTERNS_PYTHON.items(): # Corregido typo
            if pattern in statement_text:
                if pattern == "subprocess.run" and "shell=True" not in statement_text:
                    continue 
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Uso detectado de una llamada/patrón potencialmente peligroso: '{pattern}'",
                    "line": ctx.start.line, "severity": details["severity"]
                })
        
        # --- NUEVA DETECCIÓN: Acceso a su propia ruta de ejecución (Self-Aware Code) ---
        # Patrones para Python: Path(__file__), os.path.abspath(__file__), sys.argv[0], open(__file__)
        if "Path(__file__)" in statement_text or "os.path.abspath(__file__)" in statement_text or \
            "sys.argv[0]" in statement_text or "open(__file__)" in statement_text:
            self.add_finding({
                "finding_type": "SELF_AWARE_CODE",
                "description": "El código intenta acceder a su propia ruta de ejecución (posible preludio a auto-modificación/cifrado).",
                "line": ctx.start.line, "severity": "HIGH"
            })
            
    # Regla: if_stmt
    def enterIf_stmt(self, ctx: PythonParser.If_stmtContext):
        # La condición del 'if' está en ctx.named_expression() que a su vez contiene la 'expression'
        condition_text = self.token_stream.getText(ctx.named_expression().start.tokenIndex, ctx.named_expression().stop.tokenIndex)
        
        if "__name__" in condition_text and ("'__main__'" in condition_text or '"__main__"' in condition_text):
            self.has_main_entry_point = 1

    # Regla: except_block
    def enterExcept_block(self, ctx: PythonParser.Except_blockContext):
        # La regla 'block' contiene una lista de 'statement'
        if ctx.block() and ctx.block().simple_stmts(): # block puede contener simple_stmts o statements complejos
            # Recorrer los simple_stmts para buscar 'pass'
            for simple_stmt_ctx in ctx.block().simple_stmts():
                stmt_text = self.token_stream.getText(simple_stmt_ctx.start.tokenIndex, simple_stmt_ctx.stop.tokenIndex)
                print(f"Checking simple statement in except block: {stmt_text}")  # Debugging
                if stmt_text.strip() == 'pass':
                    self.add_finding({
                        "finding_type": "EMPTY_CATCH_BLOCK", 
                        "description": "Se ha detectado un bloque 'except' que solo contiene 'pass'. Ignorar excepciones puede ocultar errores.",
                        "line": ctx.start.line, "severity": "MEDIUM"
                    })
                    break # Solo necesitamos encontrar uno

    # --- Método Final para Obtener las Características Calculadas (se mantiene igual) ---
    def get_analysis_report(self) -> dict:
        sections_max_entropy = np.max(self.function_entropies) if self.function_entropies else 0.0
        sections_min_entropy = np.min(self.function_entropies) if self.function_entropies else 0.0
        sections_min_virtualsize = np.min(self.function_sizes) if self.function_sizes else 0.0
        resources_min_entropy = np.min(self.string_entropies) if self.string_entropies else 0.0

        feature_vector = {
            'SectionsMaxEntropy': sections_max_entropy,
            'SizeOfStackReserve': float(self.class_and_function_count),
            'SectionsMinVirtualsize': float(sections_min_virtualsize),
            'ResourcesMinEntropy': resources_min_entropy,
            'MajorLinkerVersion': 1.0,  # Placeholder
            'SizeOfOptionalHeader': float(self.import_count),
            'AddressOfEntryPoint': float(self.has_main_entry_point),
            'SectionsMinEntropy': sections_min_entropy,
            'MinorOperatingSystemVersion': 0.0,  # Placeholder
            'SectionAlignment': 0.0,  # Placeholder
            'SizeOfHeaders': float(self.import_count),
            'LoaderFlags': 0.0,  # Placeholder
        }
        
        final_report = {
            "feature_vector": feature_vector,
            "static_findings": self.static_findings
        }
        
        return final_report