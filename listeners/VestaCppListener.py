import re
import numpy as np
from antlr4 import CommonTokenStream, ParserRuleContext, Token
from antlr4.tree.Tree import TerminalNode 
from grammars.CPP.CPP14Lexer import CPP14Lexer # Lexer para acceder a los tipos de token
from grammars.CPP.CPP14Parser import CPP14Parser # Parser para los tipos de contexto
from grammars.CPP.CPP14ParserListener import CPP14ParserListener # La clase base de la que heredamos
from signatures.finding_types import CppSignatures, SENSITIVE_PATH_REGEX_GLOBAL 

# --- Función de Entropía (se mantiene igual) ---
def calculate_entropy(data: bytes) -> float:
    if not data: return 0.0
    occurences = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = occurences / len(data)
    entropy = -np.sum([p * np.log2(p) for p in probabilities if p > 0])
    return entropy

class VestaCppListener(CPP14ParserListener):
    """
    Listener ANTLR4 diseñado para extraer un informe enriquecido del código fuente de C++.
    """
    def __init__(self, token_stream: CommonTokenStream):
        self.token_stream = token_stream
        self.static_findings = []
        self.cpp_signatures = CppSignatures() # Instancia de las firmas específicas de C++

        # Recolección de datos para las 12 features
        self.function_entropies = []
        self.function_sizes = []
        self.string_entropies = []
        self.include_count = 0 # Conteo de #include
        self.class_count = 0
        self.function_count = 0
        self.has_main_function = 0 # Para AddressOfEntryPoint
        self._finding_ids = set()
        self._pre_analyze_includes()

    def _pre_analyze_includes(self):
        """
        Realiza un análisis previo del token_stream para detectar directivas #include.
        """
        self.token_stream.seek(0)
        for token in self.token_stream.tokens:
            if token.channel == Token.HIDDEN_CHANNEL and token.text.strip().startswith('#include'):
                self.include_count += 1
                include_text = token.text.strip()

                for pattern, details in self.cpp_signatures.IMPORTS.items():
                    # Buscar el patrón de la cabecera (ej. "iostream", "windows.h")
                    if pattern in include_text: 
                        self.add_finding({
                            "finding_type": details["type"],
                            "description": f"Inclusión sospechosa de cabecera detectada: '{include_text}'. Indica: {details['desc']}",
                            "line": token.line, 
                            "severity": details["severity"]
                        })
        self.token_stream.seek(0)

    def add_finding(self, finding: dict):
        finding_id = (finding['finding_type'], finding['line'], finding['description'])
        if finding_id not in self._finding_ids:
            self.static_findings.append(finding)
            self._finding_ids.add(finding_id)


    # --- Métodos del Listener Adaptados para C++ ---

    # Regla: class_specifier (para clases)
    def enterClassSpecifier(self, ctx: CPP14Parser.ClassSpecifierContext):
        self.class_count += 1
        class_name = "UNKNOWN_CLASS"
        if ctx.classHead().classHeadName():
            class_name = ctx.classHead().classHeadName().getText()
    
        details = self.cpp_signatures.NAMING_CONVENTIONS["OBFUSCATED_CLASS_SHORT_NAME"]
        if class_name != "UNKNOWN_CLASS" and len(class_name) <= 2:
            self.add_finding({
                "finding_type": details["type"],
                "description": f"Nombre de clase sospechosamente corto: '{class_name}', posible técnica de evasión.",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })
        elif class_name == "UNKNOWN_CLASS":
            self.add_finding({
                "finding_type": details["type"],
                "description": "Clase con nombre no identificable o estructura inesperada (posible ofuscación).",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })

    # Regla: function_definition (para funciones)
    def exitFunctionDefinition(self, ctx: CPP14Parser.FunctionDefinitionContext):
        self.function_count += 1
        function_name = "UNKNOWN_FUNCTION"
        try:
            for child in ctx.declarator().pointerDeclarator().noPointerDeclarator().children:
                if type(child).__name__ == "NoPointerDeclaratorContext":
                    function_name = child.getText()
                    break
        except AttributeError:
            pass
        #print(function_name) #debugging

        details = self.cpp_signatures.NAMING_CONVENTIONS["OBFUSCATED_METHOD_SHORT_NAME"]
        if function_name != "UNKNOWN_FUNCTION" and len(function_name) <= 2:
            self.add_finding({
                "finding_type": details["type"],
                "description": f"Nombre de función sospechosamente corto: '{function_name}()', posible técnica de evasión.",
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
            self.has_main_function = 1

        # Detección: Cuerpos de función muy simples (proxy de "override" sospechoso/evasión)
        # Un cuerpo de función puede ser un compoundStatement (un bloque {...})

        # Función vacía: el caso es especial dado que según las pruebas realizadas en C++ no se genera error de compilación por funciones vacias sin cuerpo y sin retorno.
        if ctx.functionBody().getText() == "{}":  
            details = self.cpp_signatures.STRUCTURAL_PATTERNS["EMPTY_FUNCTION_BODY"]
            self.add_finding({
                "finding_type": details["type"],
                "description": f"Función '{function_name}()' con cuerpo vacío, posible técnica de evasión o placeholder.",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })
        
        for child in ctx.functionBody().compoundStatement().children:
            if type(child).__name__ == "StatementSeqContext":
                body = child.getText()
                body_list = body.split(";")
                body_list = [item.strip() for item in body_list if item.strip()]  # Limpiar espacios
                # print(body_list) # debugging
                if len(body_list) <= 1:
                    if body_list[0] == "return":
                        # Si el cuerpo es solo un 'return;' o similar simple
                        # Detección: Polimorfismo y override sospechoso (para C++)
                        if ')override{' in ctx.getText():  # Miramos si tiene override como texto plano en la delcaración
                            # print(f"Hay override en la delcaración: {ctx.start.line}") # debugging
                            # Si es override y el cuerpo es muy simple (vacío o una sola sentencia simple)
                            details = self.cpp_signatures.STRUCTURAL_PATTERNS["SUSPICIOUS_OVERRIDE"]
                            self.add_finding({
                                "finding_type": details["type"],
                                "description": f"El método sobreescrito '{function_name}' tiene un cuerpo vacío o muy simple, posible técnica de evasión.",
                                "line": ctx.start.line, 
                                "severity": details["severity"]
                            })
                        else:
                            # Si no es override, pero el cuerpo es muy simple
                            details = self.cpp_signatures.STRUCTURAL_PATTERNS["SIMPLE_FUNCTION_BODY"]

                            self.add_finding({
                                "finding_type": details["type"],
                                "description": f"Función '{function_name}()' con cuerpo vacio o muy simple, posible técnica de evasión o placeholder.",
                                "line": ctx.start.line, 
                                "severity": details["severity"]
                            })

        start_index = ctx.start.tokenIndex
        stop_index = ctx.stop.tokenIndex
        function_text = self.token_stream.getText(start_index, stop_index)
        self.function_entropies.append(calculate_entropy(function_text.encode('utf-8')))
        self.function_sizes.append(len(function_text))

    # Regla: Stringliteral (para strings literales)
    def enterLiteral(self, ctx: CPP14Parser.LiteralContext):
        string_text = ctx.getText()
        # Los strings en C++ pueden tener prefijos L"", u"", U"", R"", u8""
        # y pueden ser concatenados. getText() debería dar el literal completo.
        # Quitamos las comillas y prefijos para el contenido
        string_content = re.sub(r'^[LuU]?R?"', '', string_text) # Quita prefijos y comilla inicial
        string_content = re.sub(r'"$', '', string_content) # Quita comilla final
        string_content = string_content.replace("'", "")

        # Para raw strings R"delimiter(...)delimiter", quitar el delimiter
        if string_text.startswith('R"'):
            match = re.match(r'R"(.*?)\((.*)\)\1"', string_text, re.DOTALL)
            if match:
                string_content = match.group(2)
            else:
                string_content = string_text # Fallback si no coincide con raw string

        if string_content and not string_content.isdigit():
            # print(string_content) # debugging
            self.string_entropies.append(calculate_entropy(string_content.encode('utf-8')))
            
            # Búsqueda de secretos y rutas sensibles (usa regex GLOBAL)
            if SENSITIVE_PATH_REGEX_GLOBAL.search(string_content):
                details = self.cpp_signatures.STRUCTURAL_PATTERNS["SENSITIVE_PATH_ACCESS"]
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Acceso a ruta sensible detectado: '{string_content}'",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })
            
            for keyword, details in self.cpp_signatures.STRING_KEYWORDS.items():
                if re.search(re.escape(keyword), string_content, re.IGNORECASE):
                    self.add_finding({
                        "finding_type": details["type"],
                        "description": f"Posible secreto/credencial encontrado en un string literal que contiene '{keyword}'",
                        "line": ctx.start.line, 
                        "severity": details["severity"]
                    })
    # utilizar esta funci{on unicamente para detectar clases que sirvan para llamadas especificas que no conocemos
    # El ejemplo contiene la busqueda de clases que encuentren a system

    # def enterEveryRule(self, ctx):
    #     founded_methods = []
    #     text = ctx.getText()
    #     if 'system(' in text and ctx.start.line == 37:
    #         founded_methods.append(type(ctx).__name__)
    #     for method in founded_methods:
    #         print(f"Found class: {method}")


    def enterStatement(self, ctx: CPP14Parser.StatementContext):
        # Una postfixExpression es una llamada a función si tiene un 'expressionList' entre paréntesis.
        # O si es un 'primaryExpression' seguido de 'LPAR' y 'RPAR'.
        if ctx.declarationStatement():
            call_text = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)

            for pattern, details in self.cpp_signatures.METHOD_CALLS.items():
                if pattern in call_text:
                    self.add_finding({
                        "finding_type": details["type"],
                        "description": f"Uso detectado de una llamada potencialmente peligrosa: '{pattern}'",
                        "line": ctx.start.line, 
                        "severity": details["severity"]
                    })
                    break

        # Detección: Código auto-consciente (SELF_AWARE_BEHAVIOR) - argv[0], __FILE__, etc.
        statement_text = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)
        patterns_self_modification = ['argv[0]', '__FILE__', 'GetModuleFileName']  # Windows API
        # Patrones comunes en C/C++ para self-aware code
        for pattern in patterns_self_modification: # Windows API
            if pattern in statement_text:
                # print(statement_text) # debugging
                details = self.cpp_signatures.STRUCTURAL_PATTERNS["SELF_AWARE_CODE_ARGV0"]
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"El código intenta acceder a su propia ruta de ejecución (posible preludio a auto-modificación/cifrado) mediante {pattern}.",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })

    # Regla: handler (para bloques catch en C++)
    def enterHandler(self, ctx: CPP14Parser.HandlerContext):
        # Un handler tiene un 'compoundStatement' como cuerpo
        if ctx.compoundStatement() and not ctx.compoundStatement().statementSeq():  # statemenytSeq es None si el bloque está vacío
            # print(ctx.compoundStatement().getText()) # debugging
            details = self.cpp_signatures.STRUCTURAL_PATTERNS["EMPTY_CATCH_BLOCK"]
            self.add_finding({
                "finding_type": details["type"],
                "description": "Se ha detectado un bloque catch vacío en C++. Ignorar excepciones puede ocultar errores críticos de seguridad.",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })

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
            'SizeOfStackReserve': float(self.class_count + self.function_count), # C++ tiene clases y funciones
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