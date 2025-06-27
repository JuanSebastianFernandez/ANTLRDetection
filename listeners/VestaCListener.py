import re
import numpy as np
from antlr4 import CommonTokenStream, ParserRuleContext, Token
from antlr4.tree.Tree import TerminalNode 
from grammars.C.CLexer import CLexer # Lexer para acceder a los tipos de token (ej. CLexer.Identifier)
from grammars.C.CParser import CParser # Parser para los tipos de contexto
from grammars.C.CListener import CListener # La clase base de la que heredamos
from signatures.finding_types import CSignatures, SENSITIVE_PATH_REGEX_GLOBAL

# --- Función de Entropía (se mantiene igual) ---
def calculate_entropy(data: bytes) -> float:
    if not data: return 0.0
    occurences = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = occurences / len(data)
    entropy = -np.sum([p * np.log2(p) for p in probabilities if p > 0])
    return entropy

class VestaCListener(CListener):
    """
    Listener ANTLR4 diseñado para extraer un informe enriquecido del código fuente de C,
    adaptado a la estructura de los parsers y lexers proporcionados.
    """
    def __init__(self, token_stream: CommonTokenStream):
        self.token_stream = token_stream
        self.static_findings = []
        self.c_signatures = CSignatures() # Instancia de las firmas específicas de C

        # Recolección de datos para las 12 features
        self.function_entropies = []
        self.function_sizes = []
        self.string_entropies = []
        self.include_count = 0 # Conteo de #include #para asemejar a import
        self.function_count = 0
        self.has_main_function = 0 # Para AddressOfEntryPoint
        self._finding_ids = set()
        self._pre_analyze_includes()  # Análisis previo para detectar #include
    
    def _pre_analyze_includes(self):
        """
        Realiza un análisis previo del token_stream para detectar directivas #include.
        """
        # print("Entrer en _pre_analyze_includes")  # Debugging
        # Reiniciar el token_stream para recorrerlo desde el principio
        self.token_stream.seek(0)
        
        # Iterar por todos los tokens, incluyendo los del canal oculto
        for token in self.token_stream.tokens:
            if token.channel == Token.HIDDEN_CHANNEL and token.text.strip().startswith('#include'):
                self.include_count += 1
                import_text = token.text.strip() # El texto completo de la directiva
                
                for pattern, details in self.c_signatures.IMPORTS.items():
                    # Buscar el patrón de la cabecera (ej. "stdio.h")
                    if pattern in import_text: 
                        self.add_finding({
                            "finding_type": details["type"],
                            "description": f"Inclusión sospechosa de cabecera detectada: '{import_text}'. Indica: {details['desc']}",
                            "line": token.line, 
                            "severity": details["severity"]
                        })
        # Volver al inicio para el ParserTreeWalker
        self.token_stream.seek(0)


    def add_finding(self, finding: dict):
        finding_id = (finding['finding_type'], finding['line'], finding['description'])
        if finding_id not in self._finding_ids:
            self.static_findings.append(finding)
            self._finding_ids.add(finding_id)

    # Regla: functionDefinition - para funciones
    def exitFunctionDefinition(self, ctx: CParser.FunctionDefinitionContext):
        # print("Enter en exitFunctionDefinition")
        # print(ctx.getText())  # Debugging: Imprimir el texto de la función
        self.function_count += 1
        function_name = "UNKNOWN_FUNCTION"
        try:
            for child in ctx.declarator().directDeclarator().children:
                if type(child).__name__ == "DirectDeclaratorContext":
                    function_name = child.getText()
                    break
        except AttributeError:
            pass # No se pudo extraer el nombre, usar UNKNOWN_FUNCTION        
        
        # print(f"Function name detected: {function_name}")  # Debugging

        # Detección: Nombres de función sospechosamente cortos (ofuscación)
        details = self.c_signatures.NAMING_CONVENTIONS["OBFUSCATED_METHOD_SHORT_NAME"]
        
        if function_name != "UNKNOWN_FUNCTION" and len(function_name) <= 2:
            self.add_finding({
                "finding_type": details["type"],
                "description": f"Nombre de función sospechosamente corto: '{function_name}()'",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })
        elif function_name == "UNKNOWN_FUNCTION":
            self.add_finding({
                "finding_type": details["type"],
                "description": "Función con nombre no identificable o estructura inesperada (posible ofuscación).",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })

        # Detección: Punto de entrada principal 'main'
        if function_name == 'main':
            # print("Detected main function")  # Debugging
            self.has_main_function = 1
        
        # Detección: Cuerpo de función simple o vacío
        for child in ctx.compoundStatement().children:
            if type(child).__name__ == "BlockItemListContext":
                body = child.getText()
                # print(f"Function body: {body}")  # Debugging 
                body_list = body.split(";")
                body_list = [item.strip() for item in body_list if item.strip()]  # Limpiar espacios
                if len(body_list) <= 1:
                    if body_list[0] == "return":
                        # Si el cuerpo es solo un 'return;' o similar simple
                        details_simple_body = self.c_signatures.STRUCTURAL_PATTERNS["SIMPLE_FUNCTION_BODY"]
                        self.add_finding({
                            "finding_type": details_simple_body["type"],
                            "description": f"Función '{function_name}' con cuerpo vacio o muy simple, posible técnica de evasión o placeholder.",
                            "line": ctx.start.line, 
                            "severity": details_simple_body["severity"]
                        })


        # Obtener el texto original de la función completa para entropía y tamaño
        start_index = ctx.start.tokenIndex
        stop_index = ctx.stop.tokenIndex
        function_text = self.token_stream.getText(start_index, stop_index)
        self.function_entropies.append(calculate_entropy(function_text.encode('utf-8')))
        self.function_sizes.append(len(function_text))

    # Regla: primaryExpression (donde pueden aparecer StringLiteral)
    def enterPrimaryExpression(self, ctx: CParser.PrimaryExpressionContext):
        if ctx.StringLiteral():
            string_content = ctx.getText()[1:-1] # Quitar las comillas
            # print("Detected StringLiteral:", string_content)  # Debugging
            if string_content:
                self.string_entropies.append(calculate_entropy(string_content.encode('utf-8')))
                if SENSITIVE_PATH_REGEX_GLOBAL.search(string_content):
                    details = self.c_signatures.STRUCTURAL_PATTERNS["SENSITIVE_PATH_ACCESS"]
                    self.add_finding({
                        "finding_type": details["type"],
                        "description": f"Acceso a ruta sensible detectado: '{string_content}'",
                        "line": ctx.start.line, 
                        "severity": details["severity"]
                    })       
                for keyword, details in self.c_signatures.STRING_KEYWORDS.items():
                    if re.search(re.escape(keyword), string_content, re.IGNORECASE):
                        self.add_finding({
                            "finding_type": details["type"],
                            "description": f"Posible secreto/credencial encontrado en un string literal que contiene '{keyword}'",
                            "line": ctx.start.line, 
                            "severity": details["severity"]
                        })

    # Regla: postfixExpression (para llamadas a función, ej. myFunction())
    def enterPostfixExpression(self, ctx: CParser.PostfixExpressionContext):
        # Buscamos llamadas a funciones. Un postfixExpression puede ser un ID(...), obj.method(...), etc.
        # Si tiene un argumento list (LPAR arguments RPAR), es una llamada a función.
        if ctx.LeftParen() and ctx.RightParen():
            call_text = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)
            for pattern, details in self.c_signatures.METHOD_CALLS.items():
                if pattern in call_text:
                    self.add_finding({
                        "finding_type": details["type"],
                        "description": f"Uso detectado de una llamada potencialmente peligrosa: '{pattern}'",
                        "line": ctx.start.line, 
                        "severity": details["severity"]
                    })
        # Detección: Código auto-consciente (SELF_AWARE_BEHAVIOR) - argv[0]
        # Esto se puede encontrar en expresiones o llamadas.
        call_text = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)
        # Buscar patrones como argv[0]  
        if "argv[0]" in call_text or "self" in call_text:
            details = self.c_signatures.STRUCTURAL_PATTERNS["SELF_AWARE_CODE_ARGV0"]
            self.add_finding({
                "finding_type": details["type"],
                "description": "El código intenta acceder a su propio nombre de ejecución (argv[0])/self.",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })


    # C no tiene try-catch/except como Java/Python.
    # Así que enterCatchClause, enterExcept_block, enterIf_stmt (para main) no aplican.
    # Se omiten estos métodos de los listeners de Java/Python que no tienen análogo directo.

    def get_analysis_report(self) -> dict:
        """
        Calcula y ensambla el informe final, que incluye tanto el vector de 12
        características como la lista de hallazgos de seguridad estáticos.
        """
        sections_max_entropy = np.max(self.function_entropies) if self.function_entropies else 0.0
        sections_min_entropy = np.min(self.function_entropies) if self.function_entropies else 0.0
        sections_min_virtualsize = np.min(self.function_sizes) if self.function_sizes else 0.0
        resources_min_entropy = np.min(self.string_entropies) if self.string_entropies else 0.0

        feature_vector = {
            'SectionsMaxEntropy': sections_max_entropy,
            'SizeOfStackReserve': float(self.function_count), # Solo funciones para C
            'SectionsMinVirtualsize': float(sections_min_virtualsize),
            'ResourcesMinEntropy': resources_min_entropy,
            'MajorLinkerVersion': 1.0,  # Placeholder
            'SizeOfOptionalHeader': float(self.include_count), # Conteo de #include
            'AddressOfEntryPoint': float(self.has_main_function),
            'SectionsMinEntropy': sections_min_entropy,
            'MinorOperatingSystemVersion': 0.0,  # Placeholder
            'SectionAlignment': 0.0,  # Placeholder
            'SizeOfHeaders': float(self.include_count), # Conteo de #include
            'LoaderFlags': 0.0,  # Placeholder
        }
        
        final_report = {
            "feature_vector": feature_vector,
            "static_findings": self.static_findings
        }
        
        return final_report