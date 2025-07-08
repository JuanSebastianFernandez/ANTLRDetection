import re
import numpy as np
from antlr4 import CommonTokenStream, ParserRuleContext, Token
from antlr4.tree.Tree import TerminalNode 
from grammars.JavaScript.JavaScriptLexer import JavaScriptLexer 
from grammars.JavaScript.JavaScriptParser import JavaScriptParser 
from grammars.JavaScript.JavaScriptParserListener import JavaScriptParserListener 
from signatures.finding_types import JavaScriptSignatures, SENSITIVE_PATH_REGEX_GLOBAL
from typing import List, Dict, Set, Tuple


def calculate_entropy(data: bytes) -> float:
    """
    Calculate the Shannon entropy of a byte sequence.

    Args:
        data (bytes): Input byte sequence to analyze.

    Returns:
        float: Calculated entropy value. Returns 0.0 for empty input.
    """
    if not data: return 0.0
    occurences = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = occurences / len(data)
    entropy = -np.sum([p * np.log2(p) for p in probabilities if p > 0]) # type: ignore
    return entropy

class VestaJavaScriptListener(JavaScriptParserListener):
    """
    ANTLR4-based listener designed to extract an enriched report from JavaScript source code.

    Attributes:
        token_stream (CommonTokenStream): Token stream from the parser.
        static_findings (List[Dict]): Collected findings from the source code.
        function_entropies (List[float]): Entropy values for each method body.
        function_sizes (List[int]): Character length of each method.
        string_entropies (List[float]): Entropy values for each string literal.
        import_count (int): Number of import and requires declarations.
        class_and_function_count (int): Number of classes, methods and functions founded.
        has_main_function (int): 1 if a main function is founded, else 0.
        _finding_ids (Set[Tuple]): Internal set to avoid duplicate findings.
        js_signatures (JavaScriptSignatures): Reference to static rules and patterns.
    """

    def __init__(self, token_stream: CommonTokenStream) -> None:
        """
        Initializes the VestaJavaScriptListener with a token stream.

        Args:
            token_stream (CommonTokenStream): The token stream from the parser.
        """
        self.token_stream: CommonTokenStream = token_stream
        self.static_findings: List[Dict] = []
        self.js_signatures: JavaScriptSignatures = JavaScriptSignatures() # Instance of JS-specific signatures
        self.function_entropies: List[float] = []
        self.function_sizes: List[int] = []
        self.string_entropies: List[float] = []
        self.import_count: int = 0 # Count of imports/requires
        self.class_and_function_count: int = 0
        self.has_main_function: int = 0 # For AddressOfEntryPoint (proxy)
        self._finding_ids: Set[Tuple] = set()

    def add_finding(self, finding: Dict) -> None:
        """
        Adds a new finding to the result list, avoiding duplicates.

        Args:
            finding (Dict): Finding dictionary with keys 'finding_type', 'line', etc.
        """
        finding_id: Tuple = (finding['finding_type'], finding['line'], finding['description'])
        if finding_id not in self._finding_ids:
            self.static_findings.append(finding)
            self._finding_ids.add(finding_id)

    def enterImportStatement(self, ctx: JavaScriptParser.ImportStatementContext) -> None:
        """
        Triggered upon entering an import statement (for 'import ...').
        Detects suspicious module imports.

        Args:
            ctx (JavaScriptParser.ImportStatementContext): Parsing context.
        """
        self.import_count += 1
        # The string literal from 'from' contains the module path
        if ctx.importFromBlock():
            import_path: str = ctx.importFromBlock().getText().strip("'\"")
            for pattern, details in self.js_signatures.IMPORTS.items():
                if pattern in import_path: # Search for the module pattern
                    self.add_finding({
                        "finding_type": details["type"],
                        "description": f"Suspicious module import: {import_path}. Indicates: {details['desc']}",
                        "line": ctx.start.line, 
                        "severity": details["severity"]
                    })

    def enterClassDeclaration(self, ctx: JavaScriptParser.ClassDeclarationContext) -> None:
        """
        Triggered upon entering a class declaration.
        Detects short or obfuscated class names.

        Args:
            ctx (JavaScriptParser.ClassDeclarationContext): Parsing context.
        """
        self.class_and_function_count += 1 # Count classes
        class_name: str = ctx.identifier().getText()
        details: Dict = self.js_signatures.NAMING_CONVENTIONS["OBFUSCATED_CLASS_SHORT_NAME"]
        # print(f"Class detected: {class_name}") # debugging

        if class_name and len(class_name) <= 2:
            self.add_finding({
                "finding_type": details["type"],
                "description": f"Suspiciously short class name: '{class_name}', possible evasion technique.",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })
        elif not class_name:
            self.add_finding({
                "finding_type": details["type"],
                "description": "Class with unidentifiable name or unexpected structure (possible obfuscation).",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })

    def exitFunctionDeclaration(self, ctx: JavaScriptParser.FunctionDeclarationContext) -> None:
        """
        Triggered after a function declaration has been fully parsed.
        Detects suspicious naming and calculates entropy and size of the function body.

        Args:
            ctx (JavaScriptParser.FunctionDeclarationContext): Parsing context.
        """
        self.class_and_function_count += 1 # Count functions
        function_name: str = ctx.identifier().getText()
        # print(f"Function detected: {function_name}") # debugging
        
        details: Dict = self.js_signatures.NAMING_CONVENTIONS["OBFUSCATED_METHOD_SHORT_NAME"]
        if function_name and len(function_name) <= 2:
            self.add_finding({
                "finding_type": details["type"],
                "description": f"Suspiciously short function name: '{function_name}()'",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })
        elif not function_name:
            self.add_finding({
                "finding_type": details["type"],
                "description": "Function with unidentifiable name or unexpected structure (possible obfuscation).",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })

        # Detection: Main entry point 'main' (proxy)
        if function_name == 'main':
            self.has_main_function = 1
        
        # Entropy and size of the function body
        if ctx.functionBody():
            start_index: int = ctx.functionBody().start.tokenIndex
            stop_index: int = ctx.functionBody().stop.tokenIndex
            function_body_text: str = self.token_stream.getText(start_index, stop_index)
            self.function_entropies.append(calculate_entropy(function_body_text.encode('utf-8')))
            self.function_sizes.append(len(function_body_text))

    def exitMethodDefinition(self, ctx: JavaScriptParser.MethodDefinitionContext) -> None:
        """
        Triggered after a method definition (within classes in ES6+) has been fully parsed.
        Detects suspicious naming, minimal method bodies, and calculates entropy and size.

        Args:
            ctx (JavaScriptParser.MethodDefinitionContext): Parsing context.
        """
        self.class_and_function_count += 1 # Count methods as functions
        method_name: str = ctx.classElementName().getText()
        # print(f"Method detected: {method_name}") # debugging
        
        details: Dict = self.js_signatures.NAMING_CONVENTIONS["OBFUSCATED_METHOD_SHORT_NAME"]
        if method_name and len(method_name) <= 2:
            self.add_finding({
                "finding_type": details["type"],
                "description": f"Suspiciously short method name: '{method_name}()'",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })
        elif not method_name:
            self.add_finding({
                "finding_type": details["type"],
                "description": "Method with unidentifiable name or unexpected structure (possible obfuscation).",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })

        # Detection: Suspicious polymorphism and override (for JS)
        # In JS, there is no direct '@override'. We look for an empty or very simple method body.
        if ctx.functionBody() and ctx.functionBody().sourceElements() is None: # Empty body
            details = self.js_signatures.STRUCTURAL_PATTERNS["SUSPICIOUS_OVERRIDE"]
            self.add_finding({
                "finding_type": details["type"],
                "description": f"Method '{method_name}' has an empty body, possible evasion technique or placeholder.",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })
        
        # Entropy and size of the method body
        if ctx.functionBody():
            start_index: int = ctx.functionBody().start.tokenIndex
            stop_index: int = ctx.functionBody().stop.tokenIndex
            method_body_text: str = self.token_stream.getText(start_index, stop_index)
            self.function_entropies.append(calculate_entropy(method_body_text.encode('utf-8')))
            self.function_sizes.append(len(method_body_text))

    def enterLiteral(self, ctx: JavaScriptParser.LiteralContext) -> None:
        """
        Triggered when a literal (including StringLiteral and TemplateStringLiteral) is encountered.
        Detects secrets, entropy in strings, and sensitive path access.

        Args:
            ctx (JavaScriptParser.LiteralContext): Parsing context.
        """
        string_content: str | None = None
        if ctx.StringLiteral():
            string_content = ctx.StringLiteral().getText().strip("'\"")  # Removes double and single quotes
        elif ctx.templateStringLiteral():
            # For template literals (backticks ` `), get the full text
            string_content = ctx.templateStringLiteral().getText().strip("`")
        if string_content:
            self.string_entropies.append(calculate_entropy(string_content.encode('utf-8')))
            
            # Search for secrets and sensitive paths (uses GLOBAL regex)
            if SENSITIVE_PATH_REGEX_GLOBAL.search(string_content):
                details: Dict = self.js_signatures.STRUCTURAL_PATTERNS["SENSITIVE_PATH_ACCESS"]
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Sensitive path access detected: {string_content}",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })
            
            for keyword, details in self.js_signatures.STRING_KEYWORDS.items():
                if re.search(re.escape(keyword), string_content, re.IGNORECASE):
                    self.add_finding({
                        "finding_type": details["type"],
                        "description": f"Possible secret/credential found in a string literal containing '{keyword}'",
                        "line": ctx.start.line, 
                        "severity": details["severity"]
                    })
                    
    def enterExpressionStatement(self, ctx: JavaScriptParser.ExpressionStatementContext) -> None:
        """
        Triggered upon entering an expression statement (for function calls like eval(), etc.).
        Detects potentially dangerous method calls and self-aware code patterns.

        Args:
            ctx (JavaScriptParser.ExpressionStatementContext): Parsing context.
        """
        # Search for dangerous call patterns in the expression text
        expression_text: str = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)
        # print(expression_text) # debugging
        for pattern, details in self.js_signatures.METHOD_CALLS.items():
            if pattern in expression_text:
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Use of a potentially dangerous call/pattern detected: '{pattern}'",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })
                # No 'break' here, as an expression can contain multiple dangerous calls

        # Detection: Self-aware code (SELF_AWARE_BEHAVIOR)
        # Common patterns in JS for self-aware code (Node.js)
        patterns_self_modification: List[str] = ["__dirname", "process.argv[0]", "module.filename"]
        for pattern in patterns_self_modification:
            if pattern in expression_text:
                details: Dict = self.js_signatures.STRUCTURAL_PATTERNS["SELF_AWARE_CODE_PATH"]
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Code attempts to access its own execution path via: '{expression_text}' (possible prelude to self-modification/encryption).",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })

    def enterCatchProduction(self, ctx: JavaScriptParser.CatchProductionContext) -> None:
        """
        Triggered upon entering a catch production (catch blocks).
        Detects empty catch blocks, which may hide critical security issues.

        Args:
            ctx (JavaScriptParser.CatchProductionContext): Parsing context.
        """
        # print(ctx.block().statementList()) # debugging
        
        if ctx.block() and ctx.block().statementList() is None: # If the block is empty
            details: Dict = self.js_signatures.STRUCTURAL_PATTERNS["EMPTY_CATCH_BLOCK"]
            self.add_finding({
                "finding_type": details["type"],
                "description": "An empty catch block has been detected. Ignoring exceptions can hide critical security errors.",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })

    def get_analysis_report(self) -> Dict:
        """
        Calculates and assembles the final report, which includes both the 12
        feature vector and the list of static security findings.

        Returns:
            Dict: A dictionary containing:
                - 'feature_vector': Feature values useful for ML models or heuristics.
                - 'static_findings': List of detected static issues in the code.
        """
        # Calculate aggregates from collected lists
        sections_max_entropy: float = np.max(self.function_entropies) if self.function_entropies else 0.0
        sections_min_entropy: float = np.min(self.function_entropies) if self.function_entropies else 0.0
        sections_min_virtualsize: float = np.min(self.function_sizes) if self.function_sizes else 0.0
        resources_min_entropy: float = np.min(self.string_entropies) if self.string_entropies else 0.0

        feature_vector: Dict[str, float] = {
            'SectionsMaxEntropy': sections_max_entropy,
            'SizeOfStackReserve': float(self.class_and_function_count), # JS has classes and functions
            'SectionsMinVirtualsize': float(sections_min_virtualsize),
            'ResourcesMinEntropy': resources_min_entropy,
            'MajorLinkerVersion': 1.0,  # Placeholder
            'SizeOfOptionalHeader': float(self.import_count), # Count of imports
            'AddressOfEntryPoint': float(self.has_main_function),
            'SectionsMinEntropy': sections_min_entropy,
            'MinorOperatingSystemVersion': 0.0,  # Placeholder
            'SectionAlignment': 0.0,  # Placeholder
            'SizeOfHeaders': float(self.import_count), # Count of imports
            'LoaderFlags': 0.0,  # Placeholder
        }
        
        final_report: Dict = {
            "feature_vector": feature_vector,
            "static_findings": self.static_findings
        }
        
        return final_report