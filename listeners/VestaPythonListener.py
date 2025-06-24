import re
import numpy as np
from antlr4 import CommonTokenStream, ParserRuleContext
from antlr4.tree.Tree import TerminalNode # Importar TerminalNode
from grammars.Python.PythonLexer import PythonLexer # Lexer para acceder a los tipos de token (ej. PythonLexer.NAME)
from grammars.Python.PythonParser import PythonParser # Parser para los tipos de contexto (ej. PythonParser.Class_defContext)
from grammars.Python.PythonParserListener import PythonParserListener # La clase base de la que heredamos
from signatures.finding_types import PythonSignatures, SENSITIVE_PATH_REGEX_GLOBAL


# --- Función de Entropía (se mantiene igual) ---
def calculate_entropy(data: bytes) -> float:
    if not data: return 0.0
    occurences = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = occurences / len(data)
    entropy = -np.sum([p * np.log2(p) for p in probabilities if p > 0])
    return entropy


class VestaPythonListener(PythonParserListener):
    """
    Listener ANTLR4 diseñado para extraer un informe enriquecido del código fuente de Python,
    adaptado a la estructura de los parsers y lexers proporcionados.
    """
    def __init__(self, token_stream: CommonTokenStream):
        self.token_stream = token_stream
        self.static_findings = []
        self.python_signatures = PythonSignatures()
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


    def enterImport_stmt(self, ctx: PythonParser.Import_stmtContext):
        self.import_count += 1
        import_text = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)
        for pattern, details in self.python_signatures.IMPORTS.items():
            # re.escape para patrones con puntos (ej. os.path)
            if re.search(r'\b' + re.escape(pattern) + r'\b', import_text): 
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Import sospechoso detectado: '{pattern}'. Indica: {details['desc']}",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })


    def enterClass_def_raw(self, ctx: PythonParser.Class_def_rawContext):
        self.class_and_function_count += 1
        class_name = None
        name_ctx = ctx.name()

        if name_ctx:
            class_name = name_ctx.getText()

        details = self.python_signatures.NAMING_CONVENTIONS["OBFUSCATED_CLASS_SHORT_NAME"]
        if class_name:
            if len(class_name) <= 2:
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Nombre de clase sospechosamente corto: '{class_name}'",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })
        else:
            self.add_finding({
                "finding_type": details["type"], 
                "description": "Clase con nombre no identificable, sin nombre o estructura inesperada (posible ofuscación).",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })

    def exitFunction_def_raw(self, ctx: PythonParser.Function_def_rawContext):
        self.class_and_function_count += 1
        function_name = None
        name_ctx = ctx.name()
        if name_ctx:
            function_name = name_ctx.getText()
            # print(f"Function name detected: {function_name}")  # Debugging

        details = self.python_signatures.NAMING_CONVENTIONS["OBFUSCATED_METHOD_SHORT_NAME"]
        if function_name:
            if len(function_name) <= 2:
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Nombre de función sospechosamente corto: '{function_name}()'",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })
            # --- Detección: Polimorfismo y override sospechoso (adaptado para Python) ---
            # Un cuerpo de función que solo contiene 'pass' o es muy simple
            # La regla 'block' contiene una lista de 'statement'
            if ctx.block() and ctx.block().statements(): # Verifica que el bloque y statements existan
                statements = ctx.block().statements().statement()
                # print(f"Statements in function '{function_name}': {statements}")  # Debugging
                if self._detected_pass_in_statements(statements):
                    # Si hay un único statement 'pass', lo consideramos sospechoso
                    details = self.python_signatures.STRUCTURAL_PATTERNS["SUSPICIOUS_PASS_BODY"]
                    self.add_finding({
                        "finding_type": details["type"], 
                        "description": f"Función '{function_name}' con unico cuerpo 'pass', posible evasión o técnica de ofuscación.",
                        "line": ctx.start.line, 
                        "severity": details["severity"]
                        })
        else:
            self.add_finding({
                "finding_type": details["type"], 
                "description": "Función con nombre no identificable o estructura inesperada (posible ofuscación).",
                "line": ctx.start.line, 
                "severity": details["severity"]
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
        # print(f"Full string content: {full_string_content}")  # Debugging
        if full_string_content:
            self.string_entropies.append(calculate_entropy(full_string_content.encode('utf-8')))
            
            # Búsqueda de secretos y rutas sensibles
            if SENSITIVE_PATH_REGEX_GLOBAL.search(full_string_content):
                details = self.python_signatures.STRUCTURAL_PATTERNS["SENSITIVE_PATH_ACCESS"]
                self.add_finding({
                    "finding_type": details["type"],
                    "description": "El código contiene un string que parece una ruta a un archivo/directorio sensible del sistema.",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })
            
            for keyword, details in self.python_signatures.STRING_KEYWORDS.items(): 
                if re.search(keyword, full_string_content, re.IGNORECASE):
                    self.add_finding({
                        "finding_type": details["type"],
                        "description": f"Posible secreto/credencial encontrado en un string literal que contiene '{keyword}'",
                        "line": ctx.start.line, 
                        "severity": details["severity"]
                    })
    
    # Regla: simple_stmt (una sentencia simple)
    def enterSimple_stmt(self, ctx: PythonParser.Simple_stmtContext):
        statement_text = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)
        # print(f"Simple statement text: {statement_text}")  # Debugging
        for pattern, details in self.python_signatures.METHOD_CALLS.items():
            if pattern in statement_text:
                # print(f"Pattern found in simple statement: {pattern}")  # Debugging
                if pattern == "subprocess.run" and "shell=True" not in statement_text: # Evitar falsos positivos
                    continue 
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Uso detectado de una llamada/patrón potencialmente peligroso: '{pattern}'",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })
        
        patterns_self_modification = ["Path(__file__)", "os.path.abspath(__file__)", "sys.argv[0]", "open(__file__)"]
            
        for pattern in patterns_self_modification:
            if pattern in statement_text:
                # print(f"Self-aware code pattern found: {pattern}")  # Debugging
                # Si se encuentra un patrón de auto-modificación, se agrega un hallazgo
                details = self.python_signatures.STRUCTURAL_PATTERNS["SELF_AWARE_CODE_PATH"]
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"El código intenta acceder a su propia ruta de ejecución mediante: {pattern} (posible preludio a auto-modificación/cifrado).",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })
            
    # Regla: if_stmt
    def enterIf_stmt(self, ctx: PythonParser.If_stmtContext):
        # La condición del 'if' está en ctx.named_expression() que a su vez contiene la 'expression'
        condition_text = self.token_stream.getText(ctx.named_expression().start.tokenIndex, ctx.named_expression().stop.tokenIndex)
        # print(f"Condition text in if statement: {condition_text}")  # Debugging
        if "__name__" in condition_text and ("'__main__'" in condition_text or '"__main__"' in condition_text):
            self.has_main_entry_point = 1

    # Regla: except_block
    def enterExcept_block(self, ctx: PythonParser.Except_blockContext):
        if ctx.block() and ctx.block().statements():
            statements = ctx.block().statements().statement()
            # Verificamos si hay un único statement 'pass' en el bloque except
            if self._detected_pass_in_statements(statements):
                details = self.python_signatures.STRUCTURAL_PATTERNS["EMPTY_EXCEPT_BLOCK"]
                self.add_finding({
                    "finding_type": details["type"],
                    "description": "Bloque 'except' vacío o con cuerpo 'pass', puede ocultar errores críticos.",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })

    def _detected_pass_in_statements(self, statements: list):
        """
        Verifica si hay un único statement 'pass' en una lista de statements.
        """
        if len(statements) == 1:
            stmt_text = self.token_stream.getText(statements[0].start.tokenIndex, statements[0].stop.tokenIndex)
            stmt_text = stmt_text.splitlines() # Aseguramos que el texto se maneje correctamente
            stmt_text = [line.strip() for line in stmt_text if line.strip() and  not line.startswith("#")]  # Limpiar líneas vacías y de comentarios subsecuentes lineas abajo
            # print(f"Checking statement text: {stmt_text}, len: {len(stmt_text)}")  # Debugging
            if len(stmt_text) == 1 and stmt_text[0].startswith('pass'):
                return True




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