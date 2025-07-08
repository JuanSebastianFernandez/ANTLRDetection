import re
import numpy as np
from antlr4 import CommonTokenStream, ParserRuleContext
from antlr4.tree.Tree import TerminalNode 
from grammars.Python.PythonLexer import PythonLexer 
from grammars.Python.PythonParser import PythonParser 
from grammars.Python.PythonParserListener import PythonParserListener 
from signatures.finding_types import PythonSignatures, SENSITIVE_PATH_REGEX_GLOBAL


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
    occurrences = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = occurrences / len(data)
    entropy = -np.sum([p * np.log2(p) for p in probabilities if p > 0])
    return entropy


class VestaPythonListener(PythonParserListener):
    """
    ANTLR4-based listener designed to extract an enriched report from Python source code,
    adapted to the structure of the provided parsers and lexers.

    Attributes:
        token_stream (CommonTokenStream): Token stream from the parser.
        static_findings (List[Dict]): Collected findings from the source code.
        function_entropies (List[float]): Entropy values for each method body.
        function_sizes (List[int]): Character length of each method.
        string_entropies (List[float]): Entropy values for each string literal.
        import_count (int): Number of import declarations.
        class_and_function_count (int): Number of classes, methods and functions founded.
        has_main_entry_point (int): 1 if a main entry is founded, else 0.
        _finding_ids (Set[Tuple]): Internal set to avoid duplicate findings.
        python_signatures (PythonSignatures): Reference to static rules and patterns.
    """

    def __init__(self, token_stream: CommonTokenStream):
        """
        Initializes the VestaPythonListener with a token stream.

        Args:
            token_stream (CommonTokenStream): The token stream from the parser.
        """
        self.token_stream: CommonTokenStream = token_stream
        self.static_findings: list[dict] = []
        self.python_signatures: PythonSignatures = PythonSignatures()
        self.function_entropies: list[float] = []
        self.function_sizes: list[int] = []
        self.string_entropies: list[float] = []
        self.import_count: int = 0
        self.class_and_function_count: int = 0
        self.has_main_entry_point: int = 0
        self._finding_ids: set[tuple] = set()

    def add_finding(self, finding: dict) -> None:
        """
        Adds a new finding to the result list, avoiding duplicates.

        Args:
            finding (dict): Finding dictionary with keys 'finding_type', 'line', etc.
        """
        # Using a tuple to check for finding uniqueness
        finding_id = (finding['finding_type'], finding['line'], finding['description'])
        if finding_id not in self._finding_ids:
            self.static_findings.append(finding)
            self._finding_ids.add(finding_id)

    def enterImport_stmt(self, ctx: PythonParser.Import_stmtContext) -> None:
        """
        Triggered upon entering an import statement.
        Detects suspicious imports based on predefined patterns.

        Args:
            ctx (PythonParser.Import_stmtContext): Parsing context.
        """
        self.import_count += 1
        import_text = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)
        for pattern, details in self.python_signatures.IMPORTS.items():
            # Use re.escape for patterns with dots (e.g., os.path)
            if re.search(r'\b' + re.escape(pattern) + r'\b', import_text): 
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Suspicious import detected: '{pattern}'. Indicates: {details['desc']}",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })

    def enterClass_def_raw(self, ctx: PythonParser.Class_def_rawContext) -> None:
        """
        Triggered upon entering a class definition.
        Detects suspicious or obfuscated class names.

        Args:
            ctx (PythonParser.Class_def_rawContext): Parsing context.
        """
        self.class_and_function_count += 1
        class_name = None
        name_ctx = ctx.name()

        if name_ctx:
            class_name = name_ctx.getText()

        details = self.python_signatures.NAMING_CONVENTIONS["OBFUSCATED_CLASS_SHORT_NAME"]
        if class_name:
            if len(class_name) <= 2:
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Suspiciously short class name: '{class_name}'",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })
        else:
            self.add_finding({
                "finding_type": details["type"], 
                "description": "Class with an unidentifiable name, no name, or unexpected structure (possible obfuscation).",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })

    def exitFunction_def_raw(self, ctx: PythonParser.Function_def_rawContext) -> None:
        """
        Triggered after a function definition has been fully parsed.
        Detects suspicious naming, minimal function bodies, and calculates entropy.

        Args:
            ctx (PythonParser.Function_def_rawContext): Parsing context.
        """
        self.class_and_function_count += 1
        function_name = None
        name_ctx = ctx.name()
        if name_ctx:
            function_name = name_ctx.getText()

        details = self.python_signatures.NAMING_CONVENTIONS["OBFUSCATED_METHOD_SHORT_NAME"]
        if function_name:
            if len(function_name) <= 2:
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Suspiciously short function name: '{function_name}()'",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })
            # --- Detection: Suspicious polymorphism and override (adapted for Python) ---
            # A function body that only contains 'pass' or is very simple
            # The 'block' rule contains a list of 'statement'
            if ctx.block() and ctx.block().statements(): # Check that the block and statements exist
                statements = ctx.block().statements().statement()
                if self._detected_pass_in_statements(statements):
                    # If there's a single 'pass' statement, it's considered suspicious
                    details = self.python_signatures.STRUCTURAL_PATTERNS["SUSPICIOUS_PASS_BODY"]
                    self.add_finding({
                        "finding_type": details["type"], 
                        "description": f"Function '{function_name}' has a single 'pass' body, possibly an evasion or obfuscation technique.",
                        "line": ctx.start.line, 
                        "severity": details["severity"]
                        })
        else:
            self.add_finding({
                "finding_type": details["type"], 
                "description": "Function with an unidentifiable name or unexpected structure (possible obfuscation).",
                "line": ctx.start.line, 
                "severity": details["severity"]
            })

        # Get the full function text for entropy and size calculation
        start_index = ctx.start.tokenIndex
        stop_index = ctx.stop.tokenIndex
        function_text = self.token_stream.getText(start_index, stop_index)
        self.function_entropies.append(calculate_entropy(function_text.encode('utf-8')))
        self.function_sizes.append(len(function_text))

    def enterStrings(self, ctx: PythonParser.StringsContext) -> None:
        """
        Triggered when a string literal (including f-strings) is encountered.
        Detects secrets, entropy in strings, and sensitive path access.

        Args:
            ctx (PythonParser.StringsContext): Parsing context.
        """
        full_string_content = ""
        for child in ctx.children:
            if type(child).__name__ == "FstringContext":
                # For f-strings, get the full text of the f-string.
                full_string_content += self.token_stream.getText(child.start.tokenIndex, child.stop.tokenIndex)
            elif type(child).__name__ == "StringContext":
                # For normal strings, use getText() and then eval to unquote.
                # This handles different string types like '...', "...", '''...''', """..."""
                # and also escapes within the string.
                try:
                    full_string_content += eval(child.getText())
                except (SyntaxError, ValueError) as e:
                    # Handle cases where eval might fail (e.g., malformed strings)
                    # For now, just append raw text if eval fails.
                    full_string_content += child.getText().strip("'\"")

        if full_string_content:
            self.string_entropies.append(calculate_entropy(full_string_content.encode('utf-8')))
            # Search for secrets and sensitive paths
            if SENSITIVE_PATH_REGEX_GLOBAL.search(full_string_content):
                details = self.python_signatures.STRUCTURAL_PATTERNS["SENSITIVE_PATH_ACCESS"]
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Code contains a string that appears to be a sensitive system file/directory path: '{full_string_content}'.",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })
            
            for keyword, details in self.python_signatures.STRING_KEYWORDS.items(): 
                if re.search(keyword, full_string_content, re.IGNORECASE):
                    self.add_finding({
                        "finding_type": details["type"],
                        "description": f"Possible secret/credential found in a string literal containing '{keyword}'",
                        "line": ctx.start.line, 
                        "severity": details["severity"]
                    })
    
    def enterSimple_stmt(self, ctx: PythonParser.Simple_stmtContext) -> None:
        """
        Triggered upon entering a simple statement.
        Detects use of potentially dangerous method calls and self-modification patterns.

        Args:
            ctx (PythonParser.Simple_stmtContext): Parsing context.
        """
        statement_text = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)
        for pattern, details in self.python_signatures.METHOD_CALLS.items():
            if pattern in statement_text:
                # Avoid false positives for subprocess.run if shell=True is not used
                if pattern == "subprocess.run" and "shell=True" not in statement_text: 
                    continue 
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Use of a potentially dangerous call/pattern detected: '{pattern}'",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })
        
        patterns_self_modification = ["Path(__file__)", "os.path.abspath(__file__)", "sys.argv[0]", "open(__file__)"]
            
        for pattern in patterns_self_modification:
            if pattern in statement_text:
                # If a self-modification pattern is found, add a finding
                details = self.python_signatures.STRUCTURAL_PATTERNS["SELF_AWARE_CODE_PATH"]
                self.add_finding({
                    "finding_type": details["type"],
                    "description": f"Code attempts to access its own execution path using: {pattern} (possible prelude to self-modification/encryption).",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })
            
    def enterIf_stmt(self, ctx: PythonParser.If_stmtContext) -> None:
        """
        Triggered upon entering an if statement.
        Detects the presence of a main entry point ('if __name__ == "__main__"').

        Args:
            ctx (PythonParser.If_stmtContext): Parsing context.
        """
        # The 'if' condition is in ctx.named_expression() which in turn contains the 'expression'
        condition_text = self.token_stream.getText(ctx.named_expression().start.tokenIndex, ctx.named_expression().stop.tokenIndex)
        if "__name__" in condition_text and ("'__main__'" in condition_text or '"__main__"' in condition_text):
            self.has_main_entry_point = 1

    def enterExcept_block(self, ctx: PythonParser.Except_blockContext) -> None:
        """
        Triggered upon entering an except block.
        Detects empty except blocks, which may hide critical security issues.

        Args:
            ctx (PythonParser.Except_blockContext): Parsing context.
        """
        if ctx.block() and ctx.block().statements():
            statements = ctx.block().statements().statement()
            # Check if there is a single 'pass' statement in the except block
            if self._detected_pass_in_statements(statements):
                details = self.python_signatures.STRUCTURAL_PATTERNS["EMPTY_EXCEPT_BLOCK"]
                self.add_finding({
                    "finding_type": details["type"],
                    "description": "Empty 'except' block or with a 'pass' body, which can hide critical errors.",
                    "line": ctx.start.line, 
                    "severity": details["severity"]
                })

    def _detected_pass_in_statements(self, statements: list[ParserRuleContext]) -> bool:
        """
        Checks if there is a single 'pass' statement in a list of statements.

        Args:
            statements (list[ParserRuleContext]): A list of statement contexts.

        Returns:
            bool: True if a single 'pass' statement is found, False otherwise.
        """
        if len(statements) == 1:
            stmt_text = self.token_stream.getText(statements[0].start.tokenIndex, statements[0].stop.tokenIndex)
            stmt_text_lines = stmt_text.splitlines() # Ensure text is handled correctly
            # Clean up empty lines and comment lines
            cleaned_stmt_text = [line.strip() for line in stmt_text_lines if line.strip() and not line.strip().startswith("#")]
            
            if len(cleaned_stmt_text) == 1 and cleaned_stmt_text[0].startswith('pass'):
                return True
        return False

    def get_analysis_report(self) -> dict:
        """
        Generates a final analysis report including statistical features and detected findings.

        Returns:
            dict: A dictionary containing:
                - 'feature_vector': Feature values useful for ML models or heuristics.
                - 'static_findings': List of detected static issues in the code.
        """
        sections_max_entropy = np.max(self.function_entropies) if self.function_entropies else 0.0
        sections_min_entropy = np.min(self.function_entropies) if self.function_entropies else 0.0
        sections_min_virtualsize = np.min(self.function_sizes) if self.function_sizes else 0.0
        resources_min_entropy = np.min(self.string_entropies) if self.string_entropies else 0.0

        feature_vector = {
            'SectionsMaxEntropy': sections_max_entropy,
            'SizeOfStackReserve': float(self.class_and_function_count),
            'SectionsMinVirtualsize': float(sections_min_virtualsize),
            'ResourcesMinEntropy': resources_min_entropy,
            'MajorLinkerVersion': 1.0,  # Placeholder
            'SizeOfOptionalHeader': float(self.import_count),
            'AddressOfEntryPoint': float(self.has_main_entry_point),
            'SectionsMinEntropy': sections_min_entropy,
            'MinorOperatingSystemVersion': 0.0,  # Placeholder
            'SectionAlignment': 0.0,  # Placeholder
            'SizeOfHeaders': float(self.import_count),
            'LoaderFlags': 0.0,  # Placeholder
        }
        
        final_report = {
            "feature_vector": feature_vector,
            "static_findings": self.static_findings
        }
        
        return final_report