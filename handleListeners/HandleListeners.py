from antlr4 import FileStream, CommonTokenStream, ParseTreeWalker
from grammars.Java.JavaLexer import JavaLexer
from grammars.Java.JavaParser import JavaParser
from grammars.Python.PythonLexer import PythonLexer
from grammars.Python.PythonParser import PythonParser
from listeners.VestaJavaListener import VestaJavaListener
from listeners.VestaPythonListener import VestaPythonListener




SUPPORTED_LANGUAGES = {'py': 'Python', 'java': 'Java', 'c': 'C', 'cpp': 'C++', 'js': 'JavaScript', 'json':'JSON'}

class HandleListeners:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self._language = self.detect_language()
        self._report = self.create_report()
        

    @property
    def language(self) -> str:
        return self._language
    
    @property
    def report(self) -> dict:
        return self._report
    
    def detect_language(self) -> str:
        end_path = self.file_path.split('.')[-1].lower()
        if end_path in SUPPORTED_LANGUAGES:
            return SUPPORTED_LANGUAGES[end_path]
        else:
            raise ValueError(f"Unsupported file type: {end_path}")
    
    def create_report(self) -> dict:
        if self.language == 'Python':
            return self.python_listener_report()
        elif self.language == 'Java':
            return self.java_listener_report()
        else:
            raise NotImplementedError(f"Analysis for {self.language} not implemented yet.")
    
    def java_listener_report(self) -> dict:
        self._input_stream = FileStream(self.file_path, encoding='utf-8')
        self._lexer = JavaLexer(self._input_stream)
        self._token_stream = CommonTokenStream(self._lexer)
        self._parser = JavaParser(self._token_stream)
        self._tree = self._parser.compilationUnit()
        self._listener = VestaJavaListener(self._token_stream)
        self._walker = ParseTreeWalker()
        self._walker.walk(self._listener, self._tree)
        
        return self._listener.get_analysis_report()
    
    def python_listener_report(self) -> dict:
        self._input_stream = FileStream(self.file_path, encoding='utf-8')
        self._lexer = PythonLexer(self._input_stream)
        self._token_stream = CommonTokenStream(self._lexer)
        self._parser = PythonParser(self._token_stream)
        self._tree = self._parser.file_input()
        self._listener = VestaPythonListener(self._token_stream)
        self._walker = ParseTreeWalker()
        self._walker.walk(self._listener, self._tree)

        return self._listener.get_analysis_report()
