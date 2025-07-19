import os
from antlr4 import FileStream, CommonTokenStream, ParseTreeWalker, InputStream, ParserRuleContext, Token
from antlr4.error.ErrorListener import ErrorListener
import importlib.util # To import modules dynamically
from typing import Dict, List, Any, Optional, Tuple, Type


# --- Class to handle ANTLR errors ---
class CustomErrorListener(ErrorListener):
    """
    Custom ANTLR4 ErrorListener to collect syntax errors during parsing.
    """
    def __init__(self) -> None:
        """
        Initializes the CustomErrorListener.
        """
        super(CustomErrorListener, self).__init__()
        self.errors: List[Dict[str, Any]] = []

    def syntaxError(self, recognizer: Any, offendingSymbol: Token, line: int, column: int, msg: str, e: Optional[Exception]) -> None:
        """
        Called when a syntax error is encountered.

        Args:
            recognizer (Any): The recognizer that detected the error.
            offendingSymbol (Token): The token that caused the error.
            line (int): The line number where the error occurred.
            column (int): The column number where the error occurred.
            msg (str): The error message.
            e (Optional[Exception]): The exception that caused the error.
        """
        self.errors.append({
            "line": line,
            "column": column,
            "message": msg,
            "offending_symbol": offendingSymbol.text if offendingSymbol else None
        })

    def reportAmbiguity(self, recognizer: Any, dfa: Any, startIndex: int, stopIndex: int, exact: bool, ambigAlts: Any, configs: Any) -> None:
        """
        Called when an ambiguity is detected. (Not collecting by design).
        """
        pass

    def reportAttemptingFullContext(self, recognizer: Any, dfa: Any, startIndex: int, stopIndex: int, conflictingAlts: Any, configs: Any) -> None:
        """
        Called when the parser attempts full context parsing. (Not collecting by design).
        """
        pass

    def reportContextSensitivity(self, recognizer: Any, dfa: Any, startIndex: int, stopIndex: int, prediction: int, configs: Any) -> None:
        """
        Called when context sensitivity is detected. (Not collecting by design).
        """
        pass

# --- Language configuration mapping ---
# Imports will be dynamic for greater robustness.
# Paths must be relative from the location of the HandleListeners.py file.
# They require locating the ANTLR modules and configuring the library entries according to the Handler's location.

# Mapping extensions to module paths (e.g., 'grammars.Java.JavaLexer')
# and the name of the start rule
LANGUAGE_CONFIGS_MAP: Dict[str, Dict[str, str]] = {
    '.java': {
        'lexer_module': 'grammars.Java.JavaLexer',
        'parser_module': 'grammars.Java.JavaParser',
        'listener_module': 'listeners.VestaJavaListener',
        'start_rule': 'compilationUnit',
        'lexer_class_name': 'JavaLexer', # Class name within the .py module
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
    '.js': {
        'lexer_module': 'grammars.JavaScript.JavaScriptLexer',
        'parser_module': 'grammars.JavaScript.JavaScriptParser',
        'listener_module': 'listeners.VestaJavaScriptListener',
        'start_rule': 'program',
        'lexer_class_name': 'JavaScriptLexer',
        'parser_class_name': 'JavaScriptParser',
        'listener_class_name': 'VestaJavaScriptListener'
    }
}


class AntlrListenerHandler:
    """
    Handles the dynamic loading and execution of ANTLR4 lexers, parsers, and listeners
    for different programming languages to perform static analysis.
    """
    def __init__(self) -> None:
        """
        Initializes the AntlrListenerHandler.
        The self.language_configs attribute is no longer needed here, using LANGUAGE_CONFIGS_MAP directly.
        """
        pass

    def _load_class_dynamically(self, module_name: str, class_name: str) -> Type[Any]:
        """
        Dynamically loads a class from a module given its full name.

        Args:
            module_name (str): The full module name (e.g., 'grammars.Java.JavaLexer').
            class_name (str): The name of the class within the module.

        Returns:
            Type[Any]: The loaded class object.

        Raises:
            ImportError: If the module or class cannot be loaded.
        """
        try:
            # Import the entire module
            spec = importlib.util.find_spec(module_name) # It can be assumed that code_analyzer is the base package when implemented in the Vesta backend
            if spec is None:
                raise ImportError(f"Module '{module_name}' not found.")
            module = importlib.util.module_from_spec(spec)
            if spec.loader is None:
                raise ImportError(f"Could not load the loader for module '{module_name}'.")
            spec.loader.exec_module(module)
            # Return the specific class from the module
            return getattr(module, class_name)
        except Exception as e:
            raise ImportError(f"Could not load class '{class_name}' from module '{module_name}': {e}")


    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyzes a source code file using the appropriate ANTLR4 lexer, parser, and listener
        based on the file extension.

        Args:
            file_path (str): The full path to the source code file.

        Returns:
            Dict[str, Any]: A dictionary containing the analysis report, including
                            feature vector, static findings, status, and any parsing errors.
        """
        file_extension: str = os.path.splitext(file_path)[1].lower() # Work with extensions to determine the language
        # Determine if the language is supported
        if file_extension not in LANGUAGE_CONFIGS_MAP:
            return {
                "file_path": file_path,
                "status": "UNSUPPORTED_LANGUAGE",
                "message": f"File type not supported for ANTLR analysis: {file_extension}",
                "amount_findings": 0,
                "feature_vector": {},
                "static_findings": []
            }

        config: Dict[str, str] = LANGUAGE_CONFIGS_MAP[file_extension]
        error_listener: CustomErrorListener = CustomErrorListener() # Reset the error listener for each file

        try:
            # Dynamic loading of Lexer, Parser, and Listener classes
            LexerClass: Type[Any] = self._load_class_dynamically(config['lexer_module'], config['lexer_class_name'])
            ParserClass: Type[Any] = self._load_class_dynamically(config['parser_module'], config['parser_class_name'])
            ListenerClass: Type[Any] = self._load_class_dynamically(config['listener_module'], config['listener_class_name'])
            start_rule_name: str = config['start_rule']


            input_stream: FileStream = FileStream(file_path, encoding='utf-8', errors='ignore')
            
            lexer: Any = LexerClass(input_stream)
            lexer.removeErrorListeners()  # Format default syntax errors
            lexer.addErrorListener(error_listener) # Add our error manager

            token_stream: CommonTokenStream = CommonTokenStream(lexer)
            
            parser: Any = ParserClass(token_stream)
            parser.removeErrorListeners()
            parser.addErrorListener(error_listener)
            
            # Avoid the "del PythonParser" error if already imported
            if hasattr(parser, 'del_'): # If the parser has a rule named 'del'
                del_ = getattr(parser, 'del_') # Access it
                # This is a workaround if there is a 'del' in the PythonParser grammar
                # It is not a generic solution, it might be needed for the Python grammar
                # If this causes an error, it means the grammar does not need it.
            
            start_rule_method: Any = getattr(parser, start_rule_name) # Manages the start rule dynamically
            tree: ParserRuleContext = start_rule_method()  # Same as calling parser.compilationUnit() or parser.file_input() or the appropriate rule depending on the language
            
            listener_instance: Any = ListenerClass(token_stream)
            walker: ParseTreeWalker = ParseTreeWalker()
            walker.walk(listener_instance, tree)
            
            report: Dict[str, Any] = listener_instance.get_analysis_report()
            report["amount_findings"] = len(report["static_findings"])
            report["file_path"] = file_path
            report["status"] = "SUCCESS"
            
            # Because parsing analyzes the entire syntax, it may find syntax errors generating a warning that we can include in the report.
            if error_listener.errors:
                report["status"] = "PARSING_ERRORS"
                report["parsing_errors"] = error_listener.errors
                report["static_findings"].insert(0, {
                    "finding_type": "PARSING_ISSUE",
                    "description": "Syntax errors found while analyzing the file. This might indicate malformed or obfuscated code. Check parsing_errors for more details.",
                    "line": 0, 
                    "severity": "HIGH"
                })
                report["amount_findings"] = len(report["static_findings"])
            return report

        except ImportError as e:
            return {
                "file_path": file_path,
                "status": "CONFIGURATION_ERROR",
                "message": f"Configuration error (module/class not found): {str(e)}. Check paths in LANGUAGE_CONFIGS_MAP.",
                "feature_vector": {},
                "static_findings": []
            }
        except Exception as e:
            return {
                "file_path": file_path,
                "status": "ANALYSIS_FAILED",
                "message": f"Unexpected failure during analysis: {str(e)}",
                "feature_vector": {},
                "static_findings": []
            }
    
    def analyze_directory(self, directory_path: str) -> List[Dict[str, Any]]:
        """
        Analyzes all files in a directory and returns a list of reports.

        Args:
            directory_path (str): The full path to the directory.

        Returns:
            List[Dict[str, Any]]: A list of analysis reports for each file in the directory.
        """
        reports: List[Dict[str, Any]] = []

        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                report = self.analyze_file(file_path)
                reports.append(report)

        return reports