import re
import numpy as np
from antlr4 import CommonTokenStream, ParserRuleContext
from antlr4.tree.Tree import TerminalNode 
from grammars.Python.PythonLexer import PythonLexer 
from grammars.Python.PythonParser import PythonParser 
from grammars.Python.PythonParserListener import PythonParserListener 
from signatures.finding_types import PythonSignatures, SENSITIVE_PATH_REGEX_GLOBAL

class VestaPythonListener(PythonParserListener):
    """
    ANTLR4-based listener designed to extract an enriched report from Python source code,
    adapted to the structure of the provided parsers and lexers.

    Attributes:
        token_stream (CommonTokenStream): Token stream from the parser.
        static_findings (List[Dict]): Collected findings from the source code.
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
        self._finding_ids: set[tuple] = set()

    def add_finding(self, finding: dict) -> None:
        """
        Adds a new finding to the result list, avoiding duplicates.

        Args:
            finding (dict): Finding dictionary with keys 'finding_type', 'line', etc.
        """
        # Using a tuple to check for finding uniqueness
        finding_id = (finding['finding_type'], finding['line'])
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
        import_text = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)
        for pattern, details in self.python_signatures.IMPORTS.items():
            # Use re.escape for patterns with dots (e.g., os.path)
            if re.search(r'\b' + re.escape(pattern) + r'\b', import_text): 
                self.add_finding({
                        "finding_type": details.get("type", "No type provided"),
                        "description": f"{details.get('desc', '')} In import path: '{pattern}'",
                        "line": ctx.start.line, 
                        "severity": details.get("severity", "No severity provided"),
                        "weight": details.get("weight", 1.0),
                        "behavioral_trigger": details.get("behavioral_trigger", None)
                    })

    def enterClass_def_raw(self, ctx: PythonParser.Class_def_rawContext) -> None:
        """
        Triggered upon entering a class definition.
        Detects suspicious or obfuscated class names.

        Args:
            ctx (PythonParser.Class_def_rawContext): Parsing context.
        """
        class_name = None
        name_ctx = ctx.name()

        if name_ctx:
            class_name = name_ctx.getText()

        details = self.python_signatures.NAMING_CONVENTIONS["OBFUSCATED_CLASS_SHORT_NAME"]
        if class_name:
            if len(class_name) <= 2:
                self.add_finding({
                    "finding_type": details.get("type", "No type provided"),
                    "description": f"{details.get('desc', '')} '{class_name}', possible obfuscation",
                    "line": ctx.start.line, 
                    "severity": details.get("severity", "No severity provided"),
                    "weight": details.get("weight", 1.0),
                    "behavioral_trigger": details.get("behavioral_trigger", None)
                })
        else:
            self.add_finding({
                "finding_type": details.get("type", "No type provided"),
                "description": "Class with unidentifiable name or unexpected structure (possible obfuscation).",
                "line": ctx.start.line, 
                "severity": details.get("severity", "No severity provided"),
                "weight": details.get("weight", 1.0),
                "behavioral_trigger": details.get("behavioral_trigger", None)
            })

    def exitFunction_def_raw(self, ctx: PythonParser.Function_def_rawContext) -> None:
        """
        Triggered after a function definition has been fully parsed.
        Detects suspicious naming, minimal function bodies, and calculates entropy.

        Args:
            ctx (PythonParser.Function_def_rawContext): Parsing context.
        """
        function_name = None
        name_ctx = ctx.name()
        if name_ctx:
            function_name = name_ctx.getText()

        details = self.python_signatures.NAMING_CONVENTIONS["OBFUSCATED_FUNCTION_SHORT_NAME"]
        if function_name:
            if len(function_name) <= 2:
                self.add_finding({
                    "finding_type": details.get("type", "No type provided"),
                    "description": f"{details.get('desc', '')} '{function_name}()', possible obfuscation",
                    "line": ctx.start.line, 
                    "severity": details.get("severity", "No severity provided"),
                    "weight": details.get("weight", 1.0),
                    "behavioral_trigger": details.get("behavioral_trigger", None)
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
                        "finding_type": details.get("type", "No type provided"), 
                        "description": f"{details.get('desc', '')} Function '{function_name}'.",
                        "line": ctx.start.line, 
                        "severity": details.get("severity", "No severity provided"),
                        "weight": details.get("weight", 1.0),
                        "behavioral_trigger": details.get("behavioral_trigger", None)
                        })
        else:
            self.add_finding({
                "finding_type": details.get("type", "No type provided"),
                "description": "Function with unidentifiable name or unexpected structure (possible obfuscation).",
                "line": ctx.start.line, 
                "severity": details.get("severity", "No severity provided"),
                "weight": details.get("weight", 1.0),
                "behavioral_trigger": details.get("behavioral_trigger", None)
            })

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
            # Search for secrets and sensitive paths
            if SENSITIVE_PATH_REGEX_GLOBAL.search(full_string_content):
                details = self.python_signatures.STRUCTURAL_PATTERNS["SENSITIVE_PATH_ACCESS"]
                self.add_finding({
                    "finding_type": details.get("type", "No type provided"),
                    "description": f"{details.get('desc', '')} Detected in: {full_string_content}",
                    "line": ctx.start.line, 
                    "severity": details.get("severity", "No severity provided"),
                    "weight": details.get("weight", 1.0),
                    "behavioral_trigger": details.get("behavioral_trigger", None)
                })
            
            for keyword, details in self.python_signatures.STRING_KEYWORDS.items(): 
                if re.search(keyword, full_string_content, re.IGNORECASE):
                    self.add_finding({
                        "finding_type": details.get("type", "No type provided"),
                        "description": f"{details.get('desc', '')} Found in a string literal containing '{keyword}'",
                        "line": ctx.start.line, 
                        "severity": details.get("severity", "No severity provided"),
                        "weight": details.get("weight", 1.0),
                        "behavioral_trigger": details.get("behavioral_trigger", None)
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
                    "finding_type": details.get("type", "No type provided"),
                    "description": f"{details.get('desc', '')} Detected in: '{pattern}'",
                    "line": ctx.start.line, 
                    "severity": details.get("severity", "No severity provided"),
                    "weight": details.get("weight", 1.0),
                    "behavioral_trigger": details.get("behavioral_trigger", None)
                })

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
                    "finding_type": details.get("type", "No type provided"),
                    "description": details.get('desc', ''),
                    "line": ctx.start.line, 
                    "severity": details.get("severity", "No severity provided"),
                    "weight": details.get("weight", 1.0),
                    "behavioral_trigger": details.get("behavioral_trigger", None)
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
        self.static_findings = sorted(self.static_findings, key=lambda x: (x['line'], x['finding_type']))
        self.static_findings = [self.static_findings[i] for i in range(len(self.static_findings)) 
                                if i == 0 or (self.static_findings[i]['finding_type'], self.static_findings[i]['description']) !=
                                (self.static_findings[i-1]['finding_type'], self.static_findings[i-1]['description'])]

        behavioral_trigger_counts: dict[str, int] = {}
        for finding in self.static_findings:
            trigger = finding.get("behavioral_trigger")
            if trigger:
                behavioral_trigger_counts[trigger] = behavioral_trigger_counts.get(trigger, 0) + 1
        
        # 2. Generamos hallazgos de comportamiento consolidados para el reporte si se cumple el umbral.
        #    Esta lógica es para la detección en vivo.
        if behavioral_trigger_counts:
            all_triggers_found = set(behavioral_trigger_counts.keys())
            for pattern_name, details in self.python_signatures.BEHAVIORAL_PATTERNS.items():
                required_triggers = set(details["triggers"])
                if required_triggers:
                    intersection = required_triggers.intersection(all_triggers_found)
                    intersection_percentage = len(intersection) / len(required_triggers)

                    if intersection_percentage >= 0.6:  # Umbral de coincidencia del 60%
                        self.add_finding({
                            "finding_type": pattern_name,
                            "description": (
                                f"BEHAVIORAL PATTERN FOUND: '{pattern_name}' (coincidence of the {intersection_percentage:.2%}). "
                                f"Triggers founded: {list(intersection)} - {details.get('desc', '')}"
                            ),
                            "line": 0,  # Línea 0 indica un hallazgo de archivo completo
                            "severity": details.get("severity", "No severity provided"),
                            "weight": details.get("weight", 1.0),
                            "percentage_of_pattern": f"{intersection_percentage:.2%}"
                        })

        # 3. Retornamos el informe final
        original_code_text: str = self.token_stream.getText(0)
        
        final_report: dict = {
            "original_code": original_code_text,
            "static_findings": self.static_findings,
            "behavioral_trigger_counts": behavioral_trigger_counts
        }
        
        return final_report