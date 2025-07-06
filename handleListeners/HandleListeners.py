# api/code_analyzer/HandleListeners/HandleListeners.py

import os
from antlr4 import FileStream, CommonTokenStream, ParseTreeWalker, InputStream
from antlr4.error.ErrorListener import ErrorListener
import importlib.util # Para importar módulos dinámicamente

# --- Clase para manejar errores de ANTLR ---
class CustomErrorListener(ErrorListener):
    def __init__(self):
        super(CustomErrorListener, self).__init__()
        self.errors = []

    def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):
        self.errors.append({
            "line": line,
            "column": column,
            "message": msg,
            "offending_symbol": offendingSymbol.text if offendingSymbol else None
        })

    def reportAmbiguity(self, recognizer, dfa, startIndex, stopIndex, exact, ambigAlts, configs):
        pass
    def reportAttemptingFullContext(self, recognizer, dfa, startIndex, stopIndex, conflictingAlts, configs):
        pass
    def reportContextSensitivity(self, recognizer, dfa, startIndex, stopIndex, prediction, configs):
        pass

# --- Mapeo de configuraciones de lenguaje ---
# Las importaciones serán dinámicas para mayor robustez
# Los paths deben ser relativos desde la ubicación del archivo HandleListeners.py
# Requieren ubicar los módulos ANTLR y confiugurar las entradas de la librería acorde a la ubicación del Handler

# Mapeo de extensiones a rutas de módulos (ej. 'grammars.Java.JavaLexer')
# y el nombre de la regla de inicio
LANGUAGE_CONFIGS_MAP = {
    '.java': {
        'lexer_module': 'grammars.Java.JavaLexer',
        'parser_module': 'grammars.Java.JavaParser',
        'listener_module': 'listeners.VestaJavaListener',
        'start_rule': 'compilationUnit',
        'lexer_class_name': 'JavaLexer', # Nombre de la clase dentro del módulo .py
        'parser_class_name': 'JavaParser',
        'listener_class_name': 'VestaJavaListener'
    },
    '.py': {
        'lexer_module': 'grammars.Python.PythonLexer',
        'parser_module': 'grammars.Python.PythonParser',
        'listener_module': 'listeners.VestaPythonListener',
        'start_rule': 'file_input',
        'lexer_class_name': 'PythonLexer',
        'parser_class_name': 'PythonParser',
        'listener_class_name': 'VestaPythonListener'
    },
    '.c': {
        'lexer_module': 'grammars.C.CLexer',
        'parser_module': 'grammars.C.CParser',
        'listener_module': 'listeners.VestaCListener',
        'start_rule': 'compilationUnit',
        'lexer_class_name': 'CLexer',
        'parser_class_name': 'CParser',
        'listener_class_name': 'VestaCListener'
    },
    '.cpp': {
        'lexer_module': 'grammars.CPP.CPP14Lexer',
        'parser_module': 'grammars.CPP.CPP14Parser',
        'listener_module': 'listeners.VestaCppListener',
        'start_rule': 'translationUnit',
        'lexer_class_name': 'CPP14Lexer',
        'parser_class_name': 'CPP14Parser',
        'listener_class_name': 'VestaCppListener'
    },
    # '.cs': { ... },
    # '.sql': { ... },
    # '.json': { ... }
}


class AntlrListenerHandler:
    def __init__(self):
        # self.language_configs ya no es necesario aquí, usamos LANGUAGE_CONFIGS_MAP
        pass

    def _load_class_dynamically(self, module_name: str, class_name: str):
        """Carga una clase de un módulo dado su nombre completo."""
        try:
            # Importa el módulo completo
            spec = importlib.util.find_spec(module_name) # Se puede asumir que code_analyzer es el paquete base cuando se implemente en el backend Vesta
            if spec is None:
                raise ImportError(f"Módulo '{module_name}' no encontrado.")
            module = importlib.util.module_from_spec(spec)
            if spec.loader is None:
                raise ImportError(f"No se pudo cargar el loader para el módulo '{module_name}'.")
            spec.loader.exec_module(module)
            # Retorna la clase específica del módulo
            return getattr(module, class_name)
        except Exception as e:
            raise ImportError(f"No se pudo cargar la clase '{class_name}' del módulo '{module_name}': {e}")


    def analyze_file(self, file_path: str) -> dict:
        file_extension = os.path.splitext(file_path)[1].lower() # Trabajamos con extensiones para determinar el lenguaje
        # Determinar si el lenguaje está soportado
        if file_extension not in LANGUAGE_CONFIGS_MAP:
            return {
                "file_path": file_path,
                "status": "UNSUPPORTED_LANGUAGE",
                "message": f"Tipo de archivo no soportado para análisis ANTLR: {file_extension}",
                "amount_findings": 0,
                "feature_vector": {},
                "static_findings": []
            }

        config = LANGUAGE_CONFIGS_MAP[file_extension]
        error_listener = CustomErrorListener() # Reinicia el listener de errores para cada archivo

        try:
            # Carga dinámica de las clases Lexer, Parser y Listener
            LexerClass = self._load_class_dynamically(config['lexer_module'], config['lexer_class_name'])
            ParserClass = self._load_class_dynamically(config['parser_module'], config['parser_class_name'])
            ListenerClass = self._load_class_dynamically(config['listener_module'], config['listener_class_name'])
            start_rule_name = config['start_rule']


            input_stream = FileStream(file_path, encoding='utf-8', errors='ignore')
            
            lexer = LexerClass(input_stream)
            lexer.removeErrorListeners()  #Formatear los errores de sintaxis por defecto
            lexer.addErrorListener(error_listener) # Agregar nuestro manager de errores

            token_stream = CommonTokenStream(lexer)
            
            parser = ParserClass(token_stream)
            parser.removeErrorListeners()
            parser.addErrorListener(error_listener)
            
            # Evitar el error "del PythonParser" si ya se importó
            if hasattr(parser, 'del_'): # Si el parser tiene una regla llamada 'del'
                del_ = getattr(parser, 'del_') # Accede a ella
                # Esto es un workaround si hay un del PythonParser en la gramatica de Python
                # No es una solucion generica, se podria necesitar para la gramatica de Python
                # Si esto da error, es porque la gramatica no lo necesita.
            
            start_rule_method = getattr(parser, start_rule_name) # Administra la regla de inicio de forma dinámica
            tree = start_rule_method()  # Lo mismo que colcoar parser.compilationUnit() o parser.file_input() o la regla que amerite según el lenguaje
            
            listener_instance = ListenerClass(token_stream)
            walker = ParseTreeWalker()
            walker.walk(listener_instance, tree)
            
            report = listener_instance.get_analysis_report()
            report["amount_findings"] = len(report["static_findings"])
            report["file_path"] = file_path
            report["status"] = "SUCCESS"
            
            # Debido a que el parsing analiza toda la sintaxis, puede encontrar errores de sintaxis generando un aviso que podemos incluir en el reporte
            if error_listener.errors:
                report["status"] = "PARSING_ERRORS"
                report["parsing_errors"] = error_listener.errors
                report["static_findings"].insert(0, {
                    "finding_type": "PARSING_ISSUE",
                    "description": "Se encontraron errores de sintaxis al analizar el archivo. Esto podría indicar código malformado o ofuscado. Rrevisar parsing_errors para más detalle",
                    "line": 0, 
                    "severity": "HIGH"
                })
                report["amount_findings"] = len(report["static_findings"])
            return report

        except ImportError as e:
            return {
                "file_path": file_path,
                "status": "CONFIGURATION_ERROR",
                "message": f"Error de configuración (módulo/clase no encontrada): {str(e)}. Verifique las rutas en LANGUAGE_CONFIGS_MAP.",
                "feature_vector": {},
                "static_findings": []
            }
        except Exception as e:
            return {
                "file_path": file_path,
                "status": "ANALYSIS_FAILED",
                "message": f"Fallo inesperado durante el análisis: {str(e)}",
                "feature_vector": {},
                "static_findings": []
            }