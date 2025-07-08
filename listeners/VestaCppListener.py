import re
import numpy as np
from antlr4 import CommonTokenStream, ParserRuleContext, Token
from antlr4.tree.Tree import TerminalNode 
from grammars.CPP.CPP14Lexer import CPP14Lexer 
from grammars.CPP.CPP14Parser import CPP14Parser 
from grammars.CPP.CPP14ParserListener import CPP14ParserListener 
from signatures.finding_types import CppSignatures, SENSITIVE_PATH_REGEX_GLOBAL 
from typing import List, Dict, Set, Tuple


def calculate_entropy(data: bytes) -> float:
    """
    Calculate the Shannon entropy of a byte sequence.

    Args:
        data (bytes): Input byte sequence to analyze.

    Returns:
        float: Calculated entropy value. Returns 0.0 for empty input.
    """
    if not data: 
        return 0.0
    occurences = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = occurences / len(data)
    entropy = -np.sum([p * np.log2(p) for p in probabilities if p > 0])
    return entropy

class VestaCppListener(CPP14ParserListener):
    """
    ANTLR4-based listener designed to extract an enriched report from C++ source code.

    Attributes:
        token_stream (CommonTokenStream): Token stream from the parser.
        static_findings (List[Dict]): Collected findings from the source code.
        function_entropies (List[float]): Entropy values for each method body.
        function_sizes (List[int]): Character length of each method.
        string_entropies (List[float]): Entropy values for each string literal.
        include_count (int): Number of # include declarations.
        class_and_function_count (int): Number of classes, methods and functions founded.
        has_main_function (int): 1 if a main function is founded, else 0.
        _finding_ids (Set[Tuple]): Internal set to avoid duplicate findings.
        cpp_signatures (CppSignatures): Reference to static rules and patterns.
    """
    
    def __init__(self, token_stream: CommonTokenStream) -> None:
        """
        Initializes the VestaCppListener with a token stream.

        Args:
            token_stream (CommonTokenStream): The token stream from the parser.
        """
        self.token_stream: CommonTokenStream = token_stream
        self.static_findings: List[Dict] = []
        self.cpp_signatures: CppSignatures = CppSignatures() # Instance of C++ specific signatures

        # Data collection for the 12 features
        self.function_entropies: List[float] = []
        self.function_sizes: List[int] = []
        self.string_entropies: List[float] = []
        self.include_count: int = 0 # Count of #include directives
        self.class_and_function_count: int = 0
        self.has_main_function: int = 0 # For AddressOfEntryPoint
        self._finding_ids: Set[Tuple] = set()
        self._pre_analyze_includes()

    def _pre_analyze_includes(self) -> None:
        """
        Performs a pre-analysis of the token_stream to detect #include directives.
        """
        self.token_stream.seek(0)
        for token in self.token_stream.tokens:
            if token.channel == Token.HIDDEN_CHANNEL and token.text.strip().startswith('#include'):
                self.include_count += 1
                include_text: str = token.text.strip()

                for pattern, details in self.cpp_signatures.IMPORTS.items():
                    # Search for the header pattern (e.g., "iostream", "windows.h")
                    if pattern in include_text: 
                        self.add_finding({
                            "finding_type": details["type"],
                            "description": f"Suspicious header inclusion detected: '{include_text}'. Indicates: {details['desc']}",
                            "line": token.line, 
                            "severity": details["severity"]
                        })
        self.token_stream.seek(0)

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


    # --- Listener Methods Adapted for C++ ---

    def enterClassSpecifier(self, ctx: CPP14Parser.ClassSpecifierContext) -> None:
        """
        Triggered upon entering a class specifier.
        Detects short or obfuscated class names.

        Args:
            ctx (CPP14Parser.ClassSpecifierContext): Parsing context.
        """
        self.class_and_function_count += 1
        class_name: str = "UNKNOWN_CLASS"
        if ctx.classHead().classHeadName():
            class_name = ctx.classHead().classHeadName().getText()
    
        details: Dict = self.cpp_signatures.NAMING_CONVENTIONS["OBFUSCATED_CLASS_SHORT_NAME"]
        if class_name != "UNKNOWN_CLASS" and len(class_name) <= 2:
            self.add_finding({
                "finding_type": details["type"],
                "description": f"Suspiciously short class name: '{class_name}', possible evasion technique.",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })
        elif class_name == "UNKNOWN_CLASS":
            self.add_finding({
                "finding_type": details["type"],
                "description": "Class with unidentifiable name or unexpected structure (possible obfuscation).",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })

    def exitFunctionDefinition(self, ctx: CPP14Parser.FunctionDefinitionContext) -> None:
        """
        Triggered after a function definition has been fully parsed.
        Detects suspicious naming, minimal function bodies, and calculates entropy.

        Args:
            ctx (CPP14Parser.FunctionDefinitionContext): Parsing context.
        """
        self.class_and_function_count += 1
        function_name: str = "UNKNOWN_FUNCTION"
        try:
            for child in ctx.declarator().pointerDeclarator().noPointerDeclarator().children:
                if type(child).__name__ == "NoPointerDeclaratorContext":
                    function_name = child.getText()
                    break
        except AttributeError:
            pass
        #print(function_name) #debugging

        details: Dict = self.cpp_signatures.NAMING_CONVENTIONS["OBFUSCATED_METHOD_SHORT_NAME"]
        if function_name != "UNKNOWN_FUNCTION" and len(function_name) <= 2:
            self.add_finding({
                "finding_type": details["type"],
                "description": f"Suspiciously short function name: '{function_name}()', possible evasion technique.",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })
        elif function_name == "UNKNOWN_FUNCTION":
            self.add_finding({
                "finding_type": details["type"],
                "description": "Function with unidentifiable name or unexpected structure (possible obfuscation).",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })

        # Detection: Main entry point 'main'
        if function_name == 'main':
            self.has_main_function = 1

        # Detection: Very simple function bodies (proxy for suspicious "override"/evasion)
        # A function body can be a compoundStatement (a {...} block)

        # Empty function: this is a special case since, according to tests in C++, no compilation
        # error is generated for empty functions without a body or return.
        if ctx.functionBody().getText() == "{}":  
            details = self.cpp_signatures.STRUCTURAL_PATTERNS["EMPTY_FUNCTION_BODY"]
            self.add_finding({
                "finding_type": details["type"],
                "description": f"Function '{function_name}()' has an empty body, possible evasion technique or placeholder.",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })
        
        for child in ctx.functionBody().compoundStatement().children:
            if type(child).__name__ == "StatementSeqContext":
                body: str = child.getText()
                body_list: List[str] = body.split(";")
                body_list = [item.strip() for item in body_list if item.strip()]  # Clean up spaces
                # print(body_list) # debugging
                if len(body_list) <= 1:
                    if body_list and body_list[0] == "return":
                        # If the body is just a 'return;' or similarly simple
                        # Detection: Suspicious polymorphism and override (for C++)
                        if ')override{' in ctx.getText():  # Look if it has override as plain text in the declaration
                            # print(f"Override found in declaration: {ctx.start.line}") # debugging
                            # If it is override and the body is very simple (empty or a single simple statement)
                            details = self.cpp_signatures.STRUCTURAL_PATTERNS["SUSPICIOUS_OVERRIDE"]
                            self.add_finding({
                                "finding_type": details["type"],
                                "description": f"Overridden method '{function_name}' has an empty or very simple body, possible evasion technique.",
                                "line": ctx.start.line, 
                                "severity": details["severity"]
                            })
                        else:
                            # If it's not override, but the body is very simple
                            details = self.cpp_signatures.STRUCTURAL_PATTERNS["SIMPLE_FUNCTION_BODY"]

                            self.add_finding({
                                "finding_type": details["type"],
                                "description": f"Function '{function_name}()' with empty or very simple body, possible evasion technique or placeholder.",
                                "line": ctx.start.line, 
                                "severity": details["severity"]
                            })

        start_index: int = ctx.start.tokenIndex
        stop_index: int = ctx.stop.tokenIndex
        function_text: str = self.token_stream.getText(start_index, stop_index)
        self.function_entropies.append(calculate_entropy(function_text.encode('utf-8')))
        self.function_sizes.append(len(function_text))

    def enterLiteral(self, ctx: CPP14Parser.LiteralContext) -> None:
        """
        Triggered when a literal (including string literals) is encountered.
        Detects secrets, entropy in strings, and sensitive path access.

        Args:
            ctx (CPP14Parser.LiteralContext): Parsing context.
        """
        string_text: str = ctx.getText()
        # Strings in C++ can have prefixes L"", u"", U"", R"", u8""
        # and can be concatenated. getText() should provide the full literal.
        # Remove quotes and prefixes for content
        string_content: str = re.sub(r'^[LuU]?R?"', '', string_text) # Remove prefixes and initial quote
        string_content = re.sub(r'"$', '', string_content) # Remove final quote
        string_content = string_content.replace("'", "")

        # For raw strings R"delimiter(...)delimiter", remove the delimiter
        if string_text.startswith('R"'):
            match = re.match(r'R"(.*?)\((.*)\)\1"', string_text, re.DOTALL)
            if match:
                string_content = match.group(2)
            else:
                string_content = string_text # Fallback if it doesn't match a raw string

        if string_content and not string_content.isdigit():
            # print(string_content) # debugging
            self.string_entropies.append(calculate_entropy(string_content.encode('utf-8')))
            
            # Search for secrets and sensitive paths (uses GLOBAL regex)
            if SENSITIVE_PATH_REGEX_GLOBAL.search(string_content):
                details: Dict = self.cpp_signatures.STRUCTURAL_PATTERNS["SENSITIVE_PATH_ACCESS"]
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Sensitive path access detected: '{string_content}'",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })
            
            for keyword, details in self.cpp_signatures.STRING_KEYWORDS.items():
                if re.search(re.escape(keyword), string_content, re.IGNORECASE):
                    self.add_finding({
                        "finding_type": details["type"],
                        "description": f"Possible secret/credential found in a string literal containing '{keyword}'",
                        "line": ctx.start.line, 
                        "severity": details["severity"]
                    })
    # Use this function only to detect classes that serve for specific calls we don't know.
    # The example contains the search for classes that find 'system'.

    # def enterEveryRule(self, ctx):
    #     founded_methods = []
    #     text = ctx.getText()
    #     if 'system(' in text and ctx.start.line == 37:
    #         founded_methods.append(type(ctx).__name__)
    #     for method in founded_methods:
    #         print(f"Found class: {method}")


    def enterStatement(self, ctx: CPP14Parser.StatementContext) -> None:
        """
        Triggered upon entering a statement.
        Detects dangerous method calls and self-aware code patterns.

        Args:
            ctx (CPP14Parser.StatementContext): Parsing context.
        """
        # A postfixExpression is a function call if it has an 'expressionList' in parentheses.
        # Or if it's a 'primaryExpression' followed by 'LPAR' and 'RPAR'.
        if ctx.declarationStatement():
            call_text: str = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)

            for pattern, details in self.cpp_signatures.METHOD_CALLS.items():
                if pattern in call_text:
                    self.add_finding({
                        "finding_type": details["type"],
                        "description": f"Use of a potentially dangerous call detected: '{pattern}'",
                        "line": ctx.start.line, 
                        "severity": details["severity"]
                    })
                    break

        # Detection: Self-aware code (SELF_AWARE_BEHAVIOR) - argv[0], __FILE__, etc.
        statement_text: str = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)
        patterns_self_modification: List[str] = ['argv[0]', '__FILE__', 'GetModuleFileName'] # Windows API
        # Common patterns in C/C++ for self-aware code
        for pattern in patterns_self_modification:
            if pattern in statement_text:
                # print(statement_text) # debugging
                details: Dict = self.cpp_signatures.STRUCTURAL_PATTERNS["SELF_AWARE_CODE_ARGV0"]
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Code attempts to access its own execution path (possible prelude to self-modification/encryption) via {pattern}.",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })

    def enterHandler(self, ctx: CPP14Parser.HandlerContext) -> None:
        """
        Triggered upon entering a handler (catch block in C++).
        Detects empty catch blocks, which may hide critical security issues.

        Args:
            ctx (CPP14Parser.HandlerContext): Parsing context.
        """
        # A handler has a 'compoundStatement' as its body
        if ctx.compoundStatement() and not ctx.compoundStatement().statementSeq():  # statementSeq is None if the block is empty
            # print(ctx.compoundStatement().getText()) # debugging
            details: Dict = self.cpp_signatures.STRUCTURAL_PATTERNS["EMPTY_CATCH_BLOCK"]
            self.add_finding({
                "finding_type": details["type"],
                "description": "An empty catch block has been detected in C++. Ignoring exceptions can hide critical security errors.",
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
        sections_max_entropy: float = np.max(self.function_entropies) if self.function_entropies else 0.0
        sections_min_entropy: float = np.min(self.function_entropies) if self.function_entropies else 0.0
        sections_min_virtualsize: float = np.min(self.function_sizes) if self.function_sizes else 0.0
        resources_min_entropy: float = np.min(self.string_entropies) if self.string_entropies else 0.0

        feature_vector: Dict[str, float] = {
            'SectionsMaxEntropy': sections_max_entropy,
            'SizeOfStackReserve': float(self.class_and_function_count), # C++ has classes and functions
            'SectionsMinVirtualsize': float(sections_min_virtualsize),
            'ResourcesMinEntropy': resources_min_entropy,
            'MajorLinkerVersion': 1.0,  # Placeholder
            'SizeOfOptionalHeader': float(self.include_count), # Count of #include
            'AddressOfEntryPoint': float(self.has_main_function),
            'SectionsMinEntropy': sections_min_entropy,
            'MinorOperatingSystemVersion': 0.0,  # Placeholder
            'SectionAlignment': 0.0,  # Placeholder
            'SizeOfHeaders': float(self.include_count), # Count of #include
            'LoaderFlags': 0.0,  # Placeholder
        }
        
        final_report: Dict = {
            "feature_vector": feature_vector,
            "static_findings": self.static_findings
        }
        
        return final_report