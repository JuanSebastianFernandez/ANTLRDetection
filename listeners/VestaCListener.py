import re
import numpy as np
from antlr4 import CommonTokenStream, ParserRuleContext, Token
from antlr4.tree.Tree import TerminalNode 
from grammars.C.CLexer import CLexer 
from grammars.C.CParser import CParser 
from grammars.C.CListener import CListener 
from signatures.finding_types import CSignatures, SENSITIVE_PATH_REGEX_GLOBAL
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

class VestaCListener(CListener):
    """
    ANTLR4-based listener designed to extract an enriched report from C source code,
    adapted to the structure of the provided parsers and lexers.
    """
    def __init__(self, token_stream: CommonTokenStream) -> None:
        """
        Initializes the VestaCListener with a token stream.

        Args:
            token_stream (CommonTokenStream): The token stream from the parser.
        """
        self.token_stream: CommonTokenStream = token_stream
        self.static_findings: List[Dict] = []
        self.c_signatures: CSignatures = CSignatures() # Instance of C-specific signatures

        # Data collection for the 12 features
        self.function_entropies: List[float] = []
        self.function_sizes: List[int] = []
        self.string_entropies: List[float] = []
        self.include_count: int = 0 # Count of #include directives to resemble imports
        self.function_count: int = 0
        self.has_main_function: int = 0 # For AddressOfEntryPoint
        self._finding_ids: Set[Tuple] = set()
        self._pre_analyze_includes()  # Pre-analysis to detect #include directives
    
    def _pre_analyze_includes(self) -> None:
        """
        Performs a pre-analysis of the token_stream to detect #include directives.
        """
        # print("Entering _pre_analyze_includes")  # Debugging
        # Reset the token_stream to iterate from the beginning
        self.token_stream.seek(0)
        
        # Iterate through all tokens, including those on the hidden channel
        for token in self.token_stream.tokens:
            if token.channel == Token.HIDDEN_CHANNEL and token.text.strip().startswith('#include'):
                self.include_count += 1
                import_text: str = token.text.strip() # The full text of the directive
                
                for pattern, details in self.c_signatures.IMPORTS.items():
                    # Search for the header pattern (e.g., "stdio.h")
                    if pattern in import_text: 
                        self.add_finding({
                            "finding_type": details["type"],
                            "description": f"Suspicious header inclusion detected: '{import_text}'. Indicates: {details['desc']}",
                            "line": token.line, 
                            "severity": details["severity"]
                        })
        # Return to the beginning for the ParserTreeWalker
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

    def exitFunctionDefinition(self, ctx: CParser.FunctionDefinitionContext) -> None:
        """
        Triggered after a function definition has been fully parsed.
        Detects suspicious naming, minimal function bodies, and calculates entropy.

        Args:
            ctx (CParser.FunctionDefinitionContext): Parsing context.
        """
        # print("Entering exitFunctionDefinition")
        # print(ctx.getText())  # Debugging: Print the function text
        self.function_count += 1
        function_name: str = "UNKNOWN_FUNCTION"
        try:
            for child in ctx.declarator().directDeclarator().children:
                if type(child).__name__ == "DirectDeclaratorContext":
                    function_name = child.getText()
                    break
        except AttributeError:
            pass # Could not extract the name, use UNKNOWN_FUNCTION        
        
        # print(f"Function name detected: {function_name}")  # Debugging

        # Detection: Suspiciously short function names (obfuscation)
        details: Dict = self.c_signatures.NAMING_CONVENTIONS["OBFUSCATED_METHOD_SHORT_NAME"]
        
        if function_name != "UNKNOWN_FUNCTION" and len(function_name) <= 2:
            self.add_finding({
                "finding_type": details["type"],
                "description": f"Suspiciously short function name: '{function_name}()'",
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
            # print("Detected main function")  # Debugging
            self.has_main_function = 1
        
        # Detection: Simple or empty function body
        for child in ctx.compoundStatement().children:
            if type(child).__name__ == "BlockItemListContext":
                body: str = child.getText()
                # print(f"Function body: {body}")  # Debugging 
                body_list: List[str] = body.split(";")
                body_list = [item.strip() for item in body_list if item.strip()]  # Clean up spaces
                if len(body_list) <= 1:
                    if body_list and body_list[0] == "return":
                        # If the body is just a 'return;' or similarly simple
                        details = self.c_signatures.STRUCTURAL_PATTERNS["SIMPLE_FUNCTION_BODY"]
                        self.add_finding({
                            "finding_type": details["type"],
                            "description": f"Function '{function_name}' with empty or very simple body, possible evasion technique or placeholder.",
                            "line": ctx.start.line, 
                            "severity": details["severity"]
                        })


        # Get the full function text for entropy and size
        start_index: int = ctx.start.tokenIndex
        stop_index: int = ctx.stop.tokenIndex
        function_text: str = self.token_stream.getText(start_index, stop_index)
        self.function_entropies.append(calculate_entropy(function_text.encode('utf-8')))
        self.function_sizes.append(len(function_text))

    def enterPrimaryExpression(self, ctx: CParser.PrimaryExpressionContext) -> None:
        """
        Triggered when a primary expression is encountered (where StringLiteral can appear).
        Detects secrets, entropy in strings, and sensitive path access.

        Args:
            ctx (CParser.PrimaryExpressionContext): Parsing context.
        """
        if ctx.StringLiteral():
            string_content: str = ctx.getText()[1:-1] # Remove quotes
            # print("Detected StringLiteral:", string_content)  # Debugging
            if string_content:
                self.string_entropies.append(calculate_entropy(string_content.encode('utf-8')))
                if SENSITIVE_PATH_REGEX_GLOBAL.search(string_content):
                    details: Dict = self.c_signatures.STRUCTURAL_PATTERNS["SENSITIVE_PATH_ACCESS"]
                    self.add_finding({
                        "finding_type": details["type"],
                        "description": f"Sensitive path access detected: '{string_content}'",
                        "line": ctx.start.line, 
                        "severity": details["severity"]
                    })       
                for keyword, details in self.c_signatures.STRING_KEYWORDS.items():
                    if re.search(re.escape(keyword), string_content, re.IGNORECASE):
                        self.add_finding({
                            "finding_type": details["type"],
                            "description": f"Possible secret/credential found in a string literal containing '{keyword}'",
                            "line": ctx.start.line, 
                            "severity": details["severity"]
                        })

    def enterPostfixExpression(self, ctx: CParser.PostfixExpressionContext) -> None:
        """
        Triggered upon entering a postfix expression (for function calls, e.g., myFunction()).
        Detects use of potentially dangerous method calls and self-aware code patterns (e.g., argv[0]).

        Args:
            ctx (CParser.PostfixExpressionContext): Parsing context.
        """
        # Search for function calls. A postfixExpression can be an ID(...), obj.method(...), etc.
        # If it has a LeftParen and RightParen, it is a function call.
        # print(ctx.getText()) # Debugging
        if ctx.LeftParen() and ctx.RightParen():
            call_text: str = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)
            for pattern, details in self.c_signatures.METHOD_CALLS.items():
                if pattern in call_text:
                    self.add_finding({
                        "finding_type": details["type"],
                        "description": f"Use of a potentially dangerous call detected: '{pattern}'",
                        "line": ctx.start.line, 
                        "severity": details["severity"]
                    })
        # Detection: Self-aware code (SELF_AWARE_BEHAVIOR) - argv[0]
        # This can be found in expressions or calls.
        call_text: str = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)
        # Search for patterns like argv[0] 
        if "argv[0]" in call_text or "self" in call_text: # Note: 'self' is not idiomatic for C in this context.
            details: Dict = self.c_signatures.STRUCTURAL_PATTERNS["SELF_AWARE_CODE_ARGV0"]
            self.add_finding({
                "finding_type": details["type"],
                "description": "Code attempts to access its own execution name (argv[0])/self.",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })

    # C does not have try-catch/except like Java/Python.
    # So enterCatchClause, enterExcept_block, enterIf_stmt (for main) do not apply.
    # These methods from Java/Python listeners that do not have a direct analogue are omitted.

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
            'SizeOfStackReserve': float(self.function_count), # Only functions for C
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