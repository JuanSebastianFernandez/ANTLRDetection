import re
import numpy as np
from antlr4 import CommonTokenStream, ParserRuleContext, Token
from antlr4.tree.Tree import TerminalNode 
from grammars.C.CLexer import CLexer 
from grammars.C.CParser import CParser 
from grammars.C.CListener import CListener 
from signatures.finding_types import CSignatures, SENSITIVE_PATH_REGEX_GLOBAL
from typing import List, Dict, Set, Tuple

class VestaCListener(CListener):
    """
    ANTLR4-based listener designed to extract an enriched report from C source code,
    adapted to the structure of the provided parsers and lexers.

    Attributes:
        token_stream (CommonTokenStream): Token stream from the parser.
        static_findings (List[Dict]): Collected findings from the source code.
        _finding_ids (Set[Tuple]): Internal set to avoid duplicate findings.
        c_signatures (CSignatures): Reference to static rules and patterns.
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
                import_text: str = token.text.strip() # The full text of the directive
                for pattern, details in self.c_signatures.IMPORTS.items():
                    # Search for the header pattern (e.g., "stdio.h")
                    if pattern in import_text: 
                        self.add_finding({
                            "finding_type": details.get("type", "No type provided"),
                            "description": f"{details.get('desc', '')} In import path: '{pattern}'",
                            "line": token.line, 
                            "severity": details.get("severity", "No severity provided"),
                            "weight": details.get("weight", 1.0),
                            "behavioral_trigger": details.get("behavioral_trigger", None)
                        })
        # Return to the beginning for the ParserTreeWalker
        self.token_stream.seek(0)

    def add_finding(self, finding: Dict) -> None:
        """
        Adds a new finding to the result list, avoiding duplicates.

        Args:
            finding (Dict): Finding dictionary with keys 'finding_type', 'line', etc.
        """
        finding_id: Tuple = (finding['finding_type'], finding['line'])
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
        details: Dict = self.c_signatures.NAMING_CONVENTIONS["OBFUSCATED_FUNCTION_SHORT_NAME"]
        
        if function_name != "UNKNOWN_FUNCTION" and len(function_name) <= 2:
            self.add_finding({
                "finding_type": details.get("type", "No type provided"),
                "description": f"{details.get('desc', '')} '{function_name}()', possible obfuscation",
                "line": ctx.start.line, 
                "severity": details.get("severity", "No severity provided"),
                "weight": details.get("weight", 1.0),
                "behavioral_trigger": details.get("behavioral_trigger", None)
            })
        elif function_name == "UNKNOWN_FUNCTION":
            self.add_finding({
                "finding_type": details.get("type", "No type provided"),
                "description": "Function with unidentifiable name or unexpected structure (possible obfuscation).",
                "line": ctx.start.line, 
                "severity": details.get("severity", "No severity provided"),
                "weight": details.get("weight", 1.0),
                "behavioral_trigger": details.get("behavioral_trigger", None)
            })
        
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
                            "finding_type": details.get("type", "No type provided"),
                            "description": f"{details.get('desc', '')} In function '{function_name}'.",
                            "line": ctx.start.line, 
                            "severity": details.get("severity", "No severity provided"),
                            "weight": details.get("weight", 1.0),
                            "behavioral_trigger": details.get("behavioral_trigger", None)
                        })

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
                if SENSITIVE_PATH_REGEX_GLOBAL.search(string_content):
                    details: Dict = self.c_signatures.STRUCTURAL_PATTERNS["SENSITIVE_PATH_ACCESS"]
                    self.add_finding({
                        "finding_type": details.get("type", "No type provided"),
                        "description": f"{details.get('desc', '')} Detected in: '{string_content}'",
                        "line": ctx.start.line, 
                        "severity": details.get("severity", "No severity provided"),
                        "weight": details.get("weight", 1.0),
                        "behavioral_trigger": details.get("behavioral_trigger", None)
                    })       
                for keyword, details in self.c_signatures.STRING_KEYWORDS.items():
                    if re.search(re.escape(keyword), string_content, re.IGNORECASE):
                        self.add_finding({
                            "finding_type": details.get("type", "No type provided"),
                            "description": f"{details.get('desc', '')} Found in '{keyword}'",
                            "line": ctx.start.line, 
                            "severity": details.get("severity", "No severity provided"),
                            "weight": details.get("weight", 1.0),
                            "behavioral_trigger": details.get("behavioral_trigger", None)
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
                        "finding_type": details.get("type", "No type provided"),
                        "description": f"{details.get('desc', '')} Detected in: '{pattern}'",
                        "line": ctx.start.line, 
                        "severity": details.get("severity", "No severity provided"),
                        "weight": details.get("weight", 1.0),
                        "behavioral_trigger": details.get("behavioral_trigger", None)
                    })
        # Detection: Self-aware code (SELF_AWARE_BEHAVIOR) - argv[0]
        # This can be found in expressions or calls.
        call_text: str = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)
        # Search for patterns like argv[0] 
        if "argv[0]" in call_text or "self" in call_text: # Note: 'self' is not idiomatic for C in this context.
            details: Dict = self.c_signatures.STRUCTURAL_PATTERNS["SELF_AWARE_CODE_ARGV0"]
            self.add_finding({
                "finding_type": details.get("type", "No type provided"),
                "description": details.get('desc', ''),
                "line": ctx.start.line, 
                "severity": details.get("severity", "No severity provided"),
                "weight": details.get("weight", 1.0),
                "behavioral_trigger": details.get("behavioral_trigger", None)
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
        self.static_findings = sorted(self.static_findings, key=lambda x: (x['line'], x['finding_type']))
        self.static_findings = [self.static_findings[i] for i in range(len(self.static_findings)) 
                                if i == 0 or (self.static_findings[i]['finding_type'], self.static_findings[i]['description']) !=
                                (self.static_findings[i-1]['finding_type'], self.static_findings[i-1]['description'])]

        behavioral_trigger_counts: Dict[str, int] = {}
        for finding in self.static_findings:
            trigger = finding.get("behavioral_trigger")
            if trigger:
                behavioral_trigger_counts[trigger] = behavioral_trigger_counts.get(trigger, 0) + 1
        
        # 2. Generamos hallazgos de comportamiento consolidados para el reporte si se cumple el umbral.
        #    Esta lógica es para la detección en vivo.
        if behavioral_trigger_counts:
            all_triggers_found = set(behavioral_trigger_counts.keys())
            for pattern_name, details in self.c_signatures.BEHAVIORAL_PATTERNS.items():
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