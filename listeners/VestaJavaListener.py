import re
import numpy as np
from antlr4 import CommonTokenStream
from grammars.Java.JavaParser import JavaParser
from grammars.Java.JavaParserListener import JavaParserListener
from signatures.finding_types import JavaSignatures, SENSITIVE_PATH_REGEX_GLOBAL

# --- Función de Entropía (se mantiene igual) ---
# ... (código de la función calculate_entropy)
def calculate_entropy(data: bytes) -> float:
    if not data: return 0.0
    occurences = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = occurences / len(data)
    entropy = -np.sum([p * np.log2(p) for p in probabilities if p > 0])
    return entropy




class VestaJavaListener(JavaParserListener):
    def __init__(self, token_stream: CommonTokenStream):
        self.token_stream = token_stream
        self.static_findings = []
        self.method_entropies = []
        self.method_sizes = []
        self.string_entropies = []
        self.import_count = 0
        self.class_and_method_count = 0
        self.has_main_method = 0
        self._finding_ids = set()
        self.java_signatures = JavaSignatures()

    def add_finding(self, finding: dict):
        finding_id = (finding['finding_type'], finding['line'], finding['description'])
        if finding_id not in self._finding_ids:
            self.static_findings.append(finding)
            self._finding_ids.add(finding_id)

    # --- Métodos del Listener Actualizados con Nuevas Detecciones ---

    def enterClassDeclaration(self, ctx: JavaParser.ClassDeclarationContext):
        self.class_and_method_count += 1
        class_name = ctx.identifier().getText()
        
        # --- NUEVA DETECCIÓN: Nombres de clase sospechosos (ofuscación) ---
        if '$' in class_name or len(class_name) <= 2:
            details = self.java_signatures.NAMING_CONVENTIONS["OBFUSCATED_CLASS_SHORT_NAME"]
            finding = {
                "finding_type": details["type"],
                "description": f"Nombre de clase sospechoso o generado dinámicamente: '{class_name}'",
                "line": ctx.start.line,
                "severity": details["severity"]
            }
            self.add_finding(finding)

    def exitMethodDeclaration(self, ctx: JavaParser.MethodDeclarationContext):
        self.class_and_method_count += 1
        method_name = ctx.identifier().getText()
        
        if method_name == 'main':
            self.has_main_method = 1
        
        # --- NUEVA DETECCIÓN: Nombres de método sospechosos (ofuscación) ---
        if len(method_name) <= 2:
            details = self.java_signatures.NAMING_CONVENTIONS["OBFUSCATED_METHOD_SHORT_NAME"]
            finding = {
                "finding_type": details["type"],
                "description": f"Nombre de método sospechosamente corto (posible ofuscación): '{method_name}()'",
                "line": ctx.start.line,
                "severity": details["severity"]
            }
            self.add_finding(finding)

        # --- NUEVA DETECCIÓN: Polimorfismo y override sospechoso ---
        is_override = False
        if ctx.parentCtx.parentCtx and hasattr(ctx.parentCtx.parentCtx, 'modifier'):
            for mod_ctx in ctx.parentCtx.parentCtx.modifier():
                if mod_ctx.classOrInterfaceModifier() and mod_ctx.classOrInterfaceModifier().annotation() and '@Override' in mod_ctx.classOrInterfaceModifier().annotation().getText():
                    is_override = True
                    break
        
        # Si es un override y su cuerpo es muy simple (vacío o una sola sentencia simple como 'return;')
        if is_override and ctx.methodBody() and ctx.methodBody().block() and len(ctx.methodBody().block().blockStatement()) <= 1:
            details = self.java_signatures.STRUCTURAL_PATTERNS["SUSPICIOUS_OVERRIDE"]
            finding = {
                "finding_type": details["type"],
                "description": f"El método sobreescrito '{method_name}' tiene un cuerpo vacío o muy simple, posible técnica de evasión.",
                "line": ctx.start.line,
                "severity": details["severity"]
            }
            self.add_finding(finding)
            
        start_index = ctx.start.tokenIndex
        stop_index = ctx.stop.tokenIndex
        method_text = self.token_stream.getText(start_index, stop_index)
        
        self.method_entropies.append(calculate_entropy(method_text.encode('utf-8')))
        self.method_sizes.append(len(method_text))

    def enterLiteral(self, ctx: JavaParser.LiteralContext):
        if ctx.STRING_LITERAL():
            string_text = ctx.getText()
            string_content = string_text[1:-1]
            
            # --- NUEVA DETECCIÓN: Acceso a rutas de sistema sensibles ---
            if SENSITIVE_PATH_REGEX_GLOBAL.search(string_content):
                details = self.java_signatures.STRUCTURAL_PATTERNS["SENSITIVE_PATH_ACCESS"] # Obtén detalles si existe, sino None
                finding = {
                    "finding_type": details["type"],
                    "description": f"Acceso a ruta sensible detectado: '{string_content}'",
                    "line": ctx.start.line,
                    "severity": details["severity"]
                }
                self.add_finding(finding)
                

            # (La lógica para entropía de strings y secretos hardcodeados se mantiene)
            if string_content:
                self.string_entropies.append(calculate_entropy(string_content.encode('utf-8')))
            
            for keyword, details in self.java_signatures.STRING_KEYWORDS.items():
                if re.search(re.escape(keyword), string_content, re.IGNORECASE):
                    self.add_finding({
                        "finding_type": details["type"],
                        "description": f"Posible secreto/credencial encontrado en un string literal que contiene '{keyword}'",
                        "line": ctx.start.line, 
                        "severity": details["severity"]
                    })

    def enterMethodCall(self, ctx: JavaParser.MethodCallContext):
        call_text = ctx.getText()
        for pattern, details in self.java_signatures.METHOD_CALLS.items(): # Itera sobre METHOD_CALLS
            if call_text in pattern:
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Uso detectado de una llamada potencialmente peligrosa: '{pattern}'",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })
                break
    
    def enterCreator(self, ctx: JavaParser.CreatorContext):
        if ctx.createdName().getText() == 'File':
            if ctx.classCreatorRest() and ctx.classCreatorRest().arguments().getText() == '(".")':
                details = self.java_signatures.STRUCTURAL_PATTERNS["SELF_AWARE_CODE_FILE_DOT"]
                self.add_finding({
                    "finding_type": details["type"],
                    "description": "El código accede al directorio actual ('new File(\".\")'), posible preludio a auto-modificación.",
                    "line": ctx.start.line,
                    "severity": details["severity"]
                })

    def enterImportDeclaration(self, ctx: JavaParser.ImportDeclarationContext):
        self.import_count += 1
        import_text = ctx.qualifiedName().getText()
        for pattern, details in self.java_signatures.IMPORTS.items(): # Itera sobre IMPORTS
            if import_text.startswith(pattern):
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Import sospechoso detectado: '{import_text}'. Indica: {details['desc']}",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })

    def enterPackageDeclaration(self, ctx: JavaParser.PackageDeclarationContext):
        self.import_count += 1
    
    def enterCatchClause(self, ctx: JavaParser.CatchClauseContext):
        if ctx.block() and not ctx.block().blockStatement():
            details = self.java_signatures.STRUCTURAL_PATTERNS["EMPTY_CATCH_BLOCK"]
            self.add_finding({
                "finding_type": details["type"],
                "description": "Se ha detectado un bloque catch vacío. Ignorar excepciones puede ocultar errores críticos de seguridad.",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })


    def get_analysis_report(self) -> dict:
        sections_max_entropy = np.max(self.method_entropies) if self.method_entropies else 0.0
        sections_min_entropy = np.min(self.method_entropies) if self.method_entropies else 0.0
        sections_min_virtualsize = np.min(self.method_sizes) if self.method_sizes else 0.0
        resources_min_entropy = np.min(self.string_entropies) if self.string_entropies else 0.0
        feature_vector = {
            'SectionsMaxEntropy': sections_max_entropy,
            'SizeOfStackReserve': float(self.class_and_method_count),
            'SectionsMinVirtualsize': float(sections_min_virtualsize),
            'ResourcesMinEntropy': resources_min_entropy,
            'MajorLinkerVersion': 1.0,
            'SizeOfOptionalHeader': float(self.import_count),
            'AddressOfEntryPoint': float(self.has_main_method),
            'SectionsMinEntropy': sections_min_entropy,
            'MinorOperatingSystemVersion': 0.0,
            'SectionAlignment': 0.0,
            'SizeOfHeaders': float(self.import_count),
            'LoaderFlags': 0.0,
        }
        final_report = {
            "feature_vector": feature_vector,
            "static_findings": self.static_findings
        }
        return final_report