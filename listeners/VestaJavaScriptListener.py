# api/code_analyzer/listeners/VestaJavaScriptListener.py

import re
import numpy as np
from antlr4 import CommonTokenStream, ParserRuleContext, Token
from antlr4.tree.Tree import TerminalNode 
from grammars.JavaScript.JavaScriptLexer import JavaScriptLexer # Lexer para acceder a los tipos de token
from grammars.JavaScript.JavaScriptParser import JavaScriptParser # Parser para los tipos de contexto
from grammars.JavaScript.JavaScriptParserListener import JavaScriptParserListener # La clase base de la que heredamos
from signatures.finding_types import JavaScriptSignatures, SENSITIVE_PATH_REGEX_GLOBAL

# --- Función de Entropía (se mantiene igual) ---
def calculate_entropy(data: bytes) -> float:
    if not data: return 0.0
    occurences = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = occurences / len(data)
    entropy = -np.sum([p * np.log2(p) for p in probabilities if p > 0]) # type: ignore
    return entropy

class VestaJavaScriptListener(JavaScriptParserListener):
    """
    Listener ANTLR4 diseñado para extraer un informe enriquecido del código fuente de JavaScript.
    """
    def __init__(self, token_stream: CommonTokenStream):
        self.token_stream = token_stream
        self.static_findings = []
        self.js_signatures = JavaScriptSignatures() # Instancia de las firmas específicas de JS
        self.function_entropies = []
        self.function_sizes = []
        self.string_entropies = []
        self.import_count = 0 # Conteo de imports/requires
        self.class_and_function_count = 0
        self.has_main_function = 0 # Para AddressOfEntryPoint (proxy)
        self._finding_ids = set()

    def add_finding(self, finding: dict):
        finding_id = (finding['finding_type'], finding['line'], finding['description'])
        if finding_id not in self._finding_ids:
            self.static_findings.append(finding)
            self._finding_ids.add(finding_id)

    # Regla: importStatement (para 'import ...')
    def enterImportStatement(self, ctx: JavaScriptParser.ImportStatementContext):
        self.import_count += 1
        # El string literal del 'from' contiene la ruta del módulo
        if ctx.importFromBlock():
            import_path = ctx.importFromBlock().getText().strip("'\"")
            for pattern, details in self.js_signatures.IMPORTS.items():
                if pattern in import_path: # Buscar el patrón del módulo
                    self.add_finding({
                        "finding_type": details["type"],
                        "description": f"Importación de módulo sospechosa: {import_path}. Indica: {details['desc']}",
                        "line": ctx.start.line, 
                        "severity": details["severity"]
                    })

    # Regla: classDeclaration (para clases)
    def enterClassDeclaration(self, ctx: JavaScriptParser.ClassDeclarationContext):
        self.class_and_function_count += 1 # Contamos clases
        class_name = ctx.identifier().getText()
        details = self.js_signatures.NAMING_CONVENTIONS["OBFUSCATED_CLASS_SHORT_NAME"]
        # print(f"Class detected: {class_name}") # debugging

        if class_name and len(class_name) <= 2:
            self.add_finding({
                "finding_type": details["type"],
                "description": f"Nombre de clase sospechosamente corto: '{class_name}'",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })
        elif not class_name:
            self.add_finding({
                "finding_type": details["type"],
                "description": "Clase con nombre no identificable o estructura inesperada (posible ofuscación).",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })

    # Regla: functionDeclaration (para funciones declaradas globalmente o como métodos de clase)
    def exitFunctionDeclaration(self, ctx: JavaScriptParser.FunctionDeclarationContext):
        self.class_and_function_count += 1 # Contamos funciones
        function_name = ctx.identifier().getText()
        # print(f"Function detected: {function_name}") # debbuging
        
        details = self.js_signatures.NAMING_CONVENTIONS["OBFUSCATED_METHOD_SHORT_NAME"]
        if function_name and len(function_name) <= 2:
            self.add_finding({
                "finding_type": details["type"],
                "description": f"Nombre de función sospechosamente corto: '{function_name}()'",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })
        elif not function_name:
            self.add_finding({
                "finding_type": details["type"],
                "description": "Función con nombre no identificable o estructura inesperada (posible ofuscación).",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })

        # Detección: Punto de entrada 'main' (proxy)
        if function_name == 'main':
            self.has_main_function = 1
        
        # Entropía y tamaño del cuerpo de la función
        if ctx.functionBody():
            start_index = ctx.functionBody().start.tokenIndex
            stop_index = ctx.functionBody().stop.tokenIndex
            function_body_text = self.token_stream.getText(start_index, stop_index)
            self.function_entropies.append(calculate_entropy(function_body_text.encode('utf-8')))
            self.function_sizes.append(len(function_body_text))

    # Regla: methodDefinition (para métodos dentro de clases en ES6+)
    def exitMethodDefinition(self, ctx: JavaScriptParser.MethodDefinitionContext):
        self.class_and_function_count += 1 # Contamos métodos como funciones
        method_name = ctx.classElementName().getText()
        # print(f"Method detected: {method_name}") # debbuging
        
        details = self.js_signatures.NAMING_CONVENTIONS["OBFUSCATED_METHOD_SHORT_NAME"]
        if method_name and len(method_name) <= 2:
            self.add_finding({
                "finding_type": details["type"],
                "description": f"Nombre de método sospechosamente corto: '{method_name}()'",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })
        elif not method_name:
            self.add_finding({
                "finding_type": details["type"],
                "description": "Método con nombre no identificable o estructura inesperada (posible ofuscación).",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })

        # Detección: Polimorfismo y override sospechoso (para JS)
        # En JS, no hay un '@override' directo. Se busca un cuerpo de método vacío o muy simple.
        if ctx.functionBody() and ctx.functionBody().sourceElements() is None: # Cuerpo vacío
            details = self.js_signatures.STRUCTURAL_PATTERNS["SUSPICIOUS_OVERRIDE"]
            self.add_finding({
                "finding_type": details["type"],
                "description": f"El método '{method_name}' tiene un cuerpo vacío, posible técnica de evasión o placeholder.",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })
        
        # Entropía y tamaño del cuerpo del método
        if ctx.functionBody():
            start_index = ctx.functionBody().start.tokenIndex
            stop_index = ctx.functionBody().stop.tokenIndex
            method_body_text = self.token_stream.getText(start_index, stop_index)
            self.function_entropies.append(calculate_entropy(method_body_text.encode('utf-8')))
            self.function_sizes.append(len(method_body_text))

    # Regla: literal (incluye StringLiteral y TemplateStringLiteral)
    def enterLiteral(self, ctx: JavaScriptParser.LiteralContext):
        string_content = None
        if ctx.StringLiteral():
            string_content = ctx.StringLiteral().getText().strip("'\"")  # Elimina comillas dobles y simples
        elif ctx.templateStringLiteral():
            # Para template literals (backticks ` `), obtenemos el texto completo
            string_content = ctx.templateStringLiteral().getText().strip("`")
        if string_content:
            self.string_entropies.append(calculate_entropy(string_content.encode('utf-8')))
            
            # Búsqueda de secretos y rutas sensibles (usa regex GLOBAL)
            if SENSITIVE_PATH_REGEX_GLOBAL.search(string_content):
                details = self.js_signatures.STRUCTURAL_PATTERNS["SENSITIVE_PATH_ACCESS"]
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Acceso a ruta sensible detectado: {string_content}",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })
            
            for keyword, details in self.js_signatures.STRING_KEYWORDS.items():
                if re.search(re.escape(keyword), string_content, re.IGNORECASE):
                    self.add_finding({
                        "finding_type": details["type"],
                        "description": f"Posible secreto/credencial encontrado en un string literal que contiene '{keyword}'",
                        "line": ctx.start.line, 
                        "severity": details["severity"]
                    })
                    
    # Regla: singleExpression (para llamadas a funciones como eval(), etc.)
    # Esta es una regla muy general.
    def enterExpressionStatement(self, ctx: JavaScriptParser.ExpressionStatementContext):
        # Buscamos patrones de llamadas peligrosas en el texto de la expresión
        expression_text = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)
        # print(expression_text) # debugging
        for pattern, details in self.js_signatures.METHOD_CALLS.items():
            if pattern in expression_text:
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Uso detectado de una llamada/patrón potencialmente peligroso: '{pattern}'",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })
                # No 'break' aquí, ya que una expresión puede contener múltiples llamadas peligrosas

        # Detección: Código auto-consciente (SELF_AWARE_BEHAVIOR)
        # Patrones comunes en JS para self-aware code (Node.js)
        patterns_self_modification = ["__dirname", "process.argv[0]", "module.filename"]
        for pattern in patterns_self_modification:
            if pattern in expression_text:
                details = self.js_signatures.STRUCTURAL_PATTERNS["SELF_AWARE_CODE_PATH"]
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"El código intenta acceder a su propia ruta de ejecución mediante: '{expression_text}' (posible preludio a auto-modificación/cifrado).",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })

    # Regla: catchProduction (para bloques catch)
    def enterCatchProduction(self, ctx: JavaScriptParser.CatchProductionContext):
        # print(ctx.block().statementList()) # debugging
        
        if ctx.block() and ctx.block().statementList() is None: # Si el bloque está vacío
            details = self.js_signatures.STRUCTURAL_PATTERNS["EMPTY_CATCH_BLOCK"]
            self.add_finding({
                "finding_type": details["type"],
                "description": "Se ha detectado un bloque catch vacío. Ignorar excepciones puede ocultar errores críticos de seguridad.",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })

    def get_analysis_report(self) -> dict:
        """
        Calcula y ensambla el informe final, que incluye tanto el vector de 12
        características como la lista de hallazgos de seguridad estáticos.
        """
        # Calcular agregados de las listas recolectadas
        sections_max_entropy = np.max(self.function_entropies) if self.function_entropies else 0.0
        sections_min_entropy = np.min(self.function_entropies) if self.function_entropies else 0.0
        sections_min_virtualsize = np.min(self.function_sizes) if self.function_sizes else 0.0
        resources_min_entropy = np.min(self.string_entropies) if self.string_entropies else 0.0

        feature_vector = {
            'SectionsMaxEntropy': sections_max_entropy,
            'SizeOfStackReserve': float(self.class_and_function_count), # JS tiene clases y funciones
            'SectionsMinVirtualsize': float(sections_min_virtualsize),
            'ResourcesMinEntropy': resources_min_entropy,
            'MajorLinkerVersion': 1.0,  # Placeholder
            'SizeOfOptionalHeader': float(self.import_count), # Conteo de imports
            'AddressOfEntryPoint': float(self.has_main_function),
            'SectionsMinEntropy': sections_min_entropy,
            'MinorOperatingSystemVersion': 0.0,  # Placeholder
            'SectionAlignment': 0.0,  # Placeholder
            'SizeOfHeaders': float(self.import_count), # Conteo de imports
            'LoaderFlags': 0.0,  # Placeholder
        }
        
        final_report = {
            "feature_vector": feature_vector,
            "static_findings": self.static_findings
        }
        
        return final_report