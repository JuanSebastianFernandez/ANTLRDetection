import re
import numpy as np
from antlr4 import CommonTokenStream, ParserRuleContext, Token
from antlr4.tree.Tree import TerminalNode 
from grammars.CPP.CPP14Lexer import CPP14Lexer 
from grammars.CPP.CPP14Parser import CPP14Parser 
from grammars.CPP.CPP14ParserListener import CPP14ParserListener 
from signatures.finding_types import CppSignatures, SENSITIVE_PATH_REGEX_GLOBAL 
from typing import List, Dict, Set, Tuple

class VestaCppListener(CPP14ParserListener):
    """
    ANTLR4-based listener designed to extract an enriched report from C++ source code.

    Attributes:
        token_stream (CommonTokenStream): Token stream from the parser.
        static_findings (List[Dict]): Collected findings from the source code.
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
        self._finding_ids: Set[Tuple] = set()
        self._pre_analyze_includes()

    def _pre_analyze_includes(self) -> None:
        """
        Performs a pre-analysis of the token_stream to detect #include directives.
        """
        self.token_stream.seek(0)
        for token in self.token_stream.tokens:
            if token.channel == Token.HIDDEN_CHANNEL and token.text.strip().startswith('#include'):
                include_text: str = token.text.strip()
                for pattern, details in self.cpp_signatures.IMPORTS.items():
                    # Search for the header pattern (e.g., "iostream", "windows.h")
                    if pattern in include_text: 
                        self.add_finding({
                            "finding_type": details.get("type", "No type provided"),
                            "description": f"{details.get('desc', '')} In import path: '{pattern}'",
                            "line": token.line, 
                            "severity": details.get("severity", "No severity provided"),
                            "weight": details.get("weight", 1.0),
                            "behavioral_trigger": details.get("behavioral_trigger", None)
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
        class_name: str = "UNKNOWN_CLASS"
        if ctx.classHead().classHeadName():
            class_name = ctx.classHead().classHeadName().getText()
    
        details: Dict = self.cpp_signatures.NAMING_CONVENTIONS["OBFUSCATED_CLASS_SHORT_NAME"]
        if class_name != "UNKNOWN_CLASS" and len(class_name) <= 2:
            self.add_finding({
                "finding_type": details.get("type", "No type provided"),
                "description": f"{details.get('desc', '')} '{class_name}', possible obfuscation",
                "line": ctx.start.line, 
                "severity": details.get("severity", "No severity provided"),
                "weight": details.get("weight", 1.0),
                "behavioral_trigger": details.get("behavioral_trigger", None)
            })
        elif class_name == "UNKNOWN_CLASS":
            self.add_finding({
                "finding_type": details.get("type", "No type provided"),
                "description": "Class with unidentifiable name or unexpected structure (possible obfuscation).",
                "line": ctx.start.line, 
                "severity": details.get("severity", "No severity provided"),
                "weight": details.get("weight", 1.0),
                "behavioral_trigger": details.get("behavioral_trigger", None)
            })

    def exitFunctionDefinition(self, ctx: CPP14Parser.FunctionDefinitionContext) -> None:
        """
        Triggered after a function definition has been fully parsed.
        Detects suspicious naming, minimal function bodies, and calculates entropy.

        Args:
            ctx (CPP14Parser.FunctionDefinitionContext): Parsing context.
        """
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
        # Detection: Very simple function bodies (proxy for suspicious "override"/evasion)
        # A function body can be a compoundStatement (a {...} block)

        # Empty function: this is a special case since, according to tests in C++, no compilation
        # error is generated for empty functions without a body or return.
        if ctx.functionBody().getText() == "{}":  
            details = self.cpp_signatures.STRUCTURAL_PATTERNS["EMPTY_FUNCTION_BODY"]
            self.add_finding({
                "finding_type": details.get("type", "No type provided"),
                "description": f"{details.get('desc', '')} In the function '{function_name}()'.",
                "line": ctx.start.line, 
                "severity": details.get("severity", "No severity provided"),
                "weight": details.get("weight", 1.0),
                "behavioral_trigger": details.get("behavioral_trigger", None)
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
                                "finding_type": details.get("type", "No type provided"),
                                "description": f"{details.get('desc', '')} Function '{function_name}()'.",
                                "line": ctx.start.line, 
                                "severity": details.get("severity", "No severity provided"),
                                "weight": details.get("weight", 1.0),
                                "behavioral_trigger": details.get("behavioral_trigger", None)
                            })
                        else:
                            # If it's not override, but the body is very simple
                            details = self.cpp_signatures.STRUCTURAL_PATTERNS["SIMPLE_FUNCTION_BODY"]

                            self.add_finding({
                                "finding_type": details.get("type", "No type provided"),
                                "description": f"{details.get('desc', '')} In function '{function_name}'.",
                                "line": ctx.start.line, 
                                "severity": details.get("severity", "No severity provided"),
                                "weight": details.get("weight", 1.0),
                                "behavioral_trigger": details.get("behavioral_trigger", None)
                            })

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
            # Search for secrets and sensitive paths (uses GLOBAL regex)
            if SENSITIVE_PATH_REGEX_GLOBAL.search(string_content):
                details: Dict = self.cpp_signatures.STRUCTURAL_PATTERNS["SENSITIVE_PATH_ACCESS"]
                self.add_finding({
                    "finding_type": details.get("type", "No type provided"),
                    "description": f"{details.get('desc', '')} Detected in: '{string_content}'",
                    "line": ctx.start.line, 
                    "severity": details.get("severity", "No severity provided"),
                    "weight": details.get("weight", 1.0),
                    "behavioral_trigger": details.get("behavioral_trigger", None)
                }) 
            
            for keyword, details in self.cpp_signatures.STRING_KEYWORDS.items():
                if re.search(re.escape(keyword), string_content, re.IGNORECASE):
                    self.add_finding({
                        "finding_type": details.get("type", "No type provided"),
                        "description": f"{details.get('desc', '')} Found in '{keyword}'",
                        "line": ctx.start.line, 
                        "severity": details.get("severity", "No severity provided"),
                        "weight": details.get("weight", 1.0),
                        "behavioral_trigger": details.get("behavioral_trigger", None)
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
                        "finding_type": details.get("type", "No type provided"),
                        "description": f"{details.get('desc', '')} Detected in: '{pattern}'",
                        "line": ctx.start.line, 
                        "severity": details.get("severity", "No severity provided"),
                        "weight": details.get("weight", 1.0),
                        "behavioral_trigger": details.get("behavioral_trigger", None)
                    })

        # Detection: Self-aware code (SELF_AWARE_BEHAVIOR) - argv[0], __FILE__, etc.
        statement_text: str = self.token_stream.getText(ctx.start.tokenIndex, ctx.stop.tokenIndex)
        patterns_self_modification: List[str] = ['argv[0]', '__FILE__', 'GetModuleFileName'] # Windows API
        # Common patterns in C/C++ for self-aware code
        for pattern in patterns_self_modification:
            if pattern in statement_text:
                # print(statement_text) # debugging
                details: Dict = self.cpp_signatures.STRUCTURAL_PATTERNS["SELF_AWARE_CODE"]
                self.add_finding({
                    "finding_type": details.get("type", "No type provided"),
                    "description": f"{details.get('desc', '')} In '{pattern}'",
                    "line": ctx.start.line, 
                    "severity": details.get("severity", "No severity provided"),
                    "weight": details.get("weight", 1.0),
                    "behavioral_trigger": details.get("behavioral_trigger", None)
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
                "finding_type": details.get("type", "No type provided"),
                "description": details.get('desc', ''),
                "line": ctx.start.line, 
                "severity": details.get("severity", "No severity provided"),
                "weight": details.get("weight", 1.0),
                "behavioral_trigger": details.get("behavioral_trigger", None)
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
            for pattern_name, details in self.cpp_signatures.BEHAVIORAL_PATTERNS.items():
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