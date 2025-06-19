# Este código iría en un archivo como: api/code_analyzer/listeners/VestaCListener.py

import numpy as np
from antlr4 import CommonTokenStream
# Ajusta la ruta de importación según la ubicación de tus archivos generados por ANTLR
from grammars.CParser import CParser
from grammars.CListener import CListener

# Asumimos que la función de entropía está en un módulo de utilidades
# from ...services.feature_extractor import calculate_entropy
# Para este ejemplo, la definiremos aquí mismo por simplicidad:
def calculate_entropy(data: bytes) -> float:
    if not data: return 0.0
    occurences = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = occurences / len(data)
    entropy = -np.sum([p * np.log2(p) for p in probabilities if p > 0])
    return entropy

class VestaCListener(CListener):
    """
    Listener de ANTLR4 diseñado para extraer las 12 características proxy de VESTA
    a partir del código fuente de C.
    """
    def __init__(self, token_stream: CommonTokenStream):
        self.token_stream = token_stream

        # --- Listas para recolección de datos durante el recorrido ---
        self.function_entropies = []
        self.function_sizes = []
        self.string_entropies = []

        # --- Contadores ---
        self.include_count = 0
        self.function_count = 0
        self.has_main_function = 0

    # --- Métodos del Listener para Recolectar Datos ---

    # Se activa para cualquier declaración externa, buscamos los '#include'
    def enterExternalDeclaration(self, ctx:CParser.ExternalDeclarationContext):
        # El texto de un #include estará en un preprocessor directive
        # que no es un nodo estándar del parser, sino que se captura en el stream de tokens.
        # Por ahora, una aproximación simple es buscar en el texto.
        # Una solución más avanzada buscaría en los tokens ocultos del lexer.
        if ctx.getText().startswith('#include'):
            self.include_count += 1

    # Se activa al salir de una definición de función
    def exitFunctionDefinition(self, ctx:CParser.FunctionDefinitionContext):
        self.function_count += 1
        
        # Comprobar si es la función 'main' para AddressOfEntryPoint
        try:
            function_name = ctx.declarator().directDeclarator().directDeclarator().getText()
            if function_name == 'main':
                self.has_main_function = 1
        except AttributeError:
            # La estructura puede variar, pero intentamos encontrar 'main'
            if 'main' in ctx.declarator().getText():
                self.has_main_function = 1
        
        # Obtener el texto original de la función completa
        start_index = ctx.start.tokenIndex
        stop_index = ctx.stop.tokenIndex
        function_text = self.token_stream.getText(start_index, stop_index)
        
        # Calcular y guardar la entropía y el tamaño de esta función
        self.function_entropies.append(calculate_entropy(function_text.encode('utf-8')))
        self.function_sizes.append(len(function_text))

    # Se activa al entrar en una expresión primaria, donde pueden estar los strings
    def enterPrimaryExpression(self, ctx:CParser.PrimaryExpressionContext):
        if ctx.StringLiteral():
            full_string_content = ""
            for s in ctx.StringLiteral():
                str_text = s.getText()
                # Quitar las comillas para obtener el contenido
                content_part = str_text[1:-1]
                full_string_content += content_part
            
            if full_string_content:
                self.string_entropies.append(calculate_entropy(full_string_content.encode('utf-8')))

    # --- Método Final para Obtener las Características Calculadas ---

    def get_features(self) -> dict:
        """
        Calcula y ensambla el diccionario final de 12 características después
        de que el recorrido del árbol de sintaxis ha finalizado.
        """
        # Calcular agregados de las listas recolectadas
        sections_max_entropy = np.max(self.function_entropies) if self.function_entropies else 0.0
        sections_min_entropy = np.min(self.function_entropies) if self.function_entropies else 0.0
        sections_min_virtualsize = np.min(self.function_sizes) if self.function_sizes else 0.0
        resources_min_entropy = np.min(self.string_entropies) if self.string_entropies else 0.0

        # Ensamblar el diccionario final con los 12 proxies
        features = {
            'SectionsMaxEntropy': sections_max_entropy,
            'SizeOfStackReserve': float(self.function_count), # En C no hay clases, solo contamos funciones
            'SectionsMinVirtualsize': float(sections_min_virtualsize),
            'ResourcesMinEntropy': resources_min_entropy,
            'MajorLinkerVersion': 1.0,  # Placeholder
            'SizeOfOptionalHeader': float(self.include_count),
            'AddressOfEntryPoint': float(self.has_main_function),
            'SectionsMinEntropy': sections_min_entropy,
            'MinorOperatingSystemVersion': 0.0,  # Placeholder
            'SectionAlignment': 0.0,  # Placeholder
            'SizeOfHeaders': float(self.include_count),
            'LoaderFlags': 0.0,  # Placeholder
        }
        
        return features