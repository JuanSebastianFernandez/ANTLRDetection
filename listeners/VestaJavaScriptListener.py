import re
import numpy as np
from antlr4 import CommonTokenStream, ParserRuleContext, Token
from antlr4.tree.Tree import TerminalNode 
from grammars.JavaScript.JavaScriptLexer import JavaScriptLexer 
from grammars.JavaScript.JavaScriptParser import JavaScriptParser 
from grammars.JavaScript.JavaScriptParserListener import JavaScriptParserListener 
from signatures.finding_types import JavaScriptSignatures, SENSITIVE_PATH_REGEX_GLOBAL
from typing import List, Dict, Set, Tuple

class VestaJavaScriptListener(JavaScriptParserListener):
    """
    ANTLR4-based listener designed to extract an enriched report from JavaScript source code.

    Attributes:
        token_stream (CommonTokenStream): Token stream from the parser.
        static_findings (List[Dict]): Collected findings from the source code.
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
        self._finding_ids: Set[Tuple] = set()

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

    def enterImportStatement(self, ctx: JavaScriptParser.ImportStatementContext) -> None:
        """
        Triggered upon entering an import statement (for 'import ...').
        Detects suspicious module imports.

        Args:
            ctx (JavaScriptParser.ImportStatementContext): Parsing context.
        """
        # The string literal from 'from' contains the module path
        if ctx.importFromBlock():
            import_path: str = ctx.importFromBlock().getText().strip("'\"")
            for pattern, details in self.js_signatures.IMPORTS.items():
                if pattern in import_path: # Search for the module pattern
                    self.add_finding({
                        "finding_type": details.get("type", "No type provided"),
                        "description": f"{details.get('desc', '')} In import path: '{pattern}'",
                        "line": ctx.start.line, 
                        "severity": details.get("severity", "No severity provided"),
                        "weight": details.get("weight", 1.0),
                        "behavioral_trigger": details.get("behavioral_trigger", None)
                    })

        
    def enterClassDeclaration(self, ctx: JavaScriptParser.ClassDeclarationContext) -> None:
        """
        Triggered upon entering a class declaration.
        Detects short or obfuscated class names.

        Args:
            ctx (JavaScriptParser.ClassDeclarationContext): Parsing context.
        """
        class_name: str = ctx.identifier().getText()
        details: Dict = self.js_signatures.NAMING_CONVENTIONS["OBFUSCATED_CLASS_SHORT_NAME"]
        # print(f"Class detected: {class_name}") # debugging
        if class_name and len(class_name) <= 2:
            self.add_finding({
                "finding_type": details.get("type", "No type provided"),
                "description": f"{details.get('desc', '')} '{class_name}', possible obfuscation",
                "line": ctx.start.line, 
                "severity": details.get("severity", "No severity provided"),
                "weight": details.get("weight", 1.0),
                "behavioral_trigger": details.get("behavioral_trigger", None)
            })

        elif not class_name:
            self.add_finding({
                "finding_type": details.get("type", "No type provided"),
                "description": "Class with unidentifiable name or unexpected structure (possible obfuscation).",
                "line": ctx.start.line, 
                "severity": details.get("severity", "No severity provided"),
                "weight": details.get("weight", 1.0),
                "behavioral_trigger": details.get("behavioral_trigger", None)
            })


    def exitFunctionDeclaration(self, ctx: JavaScriptParser.FunctionDeclarationContext) -> None:
        """
        Triggered after a function declaration has been fully parsed.
        Detects suspicious naming and calculates entropy and size of the function body.

        Args:
            ctx (JavaScriptParser.FunctionDeclarationContext): Parsing context.
        """
        function_name: str = ctx.identifier().getText()
        # print(f"Function detected: {function_name}") # debugging
        
        details: Dict = self.js_signatures.NAMING_CONVENTIONS["OBFUSCATED_FUNCTION_SHORT_NAME"]
        if function_name and len(function_name) <= 2:
            self.add_finding({
                "finding_type": details.get("type", "No type provided"),
                "description": f"{details.get('desc', '')} '{function_name}()', possible obfuscation",
                "line": ctx.start.line, 
                "severity": details.get("severity", "No severity provided"),
                "weight": details.get("weight", 1.0),
                "behavioral_trigger": details.get("behavioral_trigger", None)
            })

        elif not function_name:
            self.add_finding({
                "finding_type": details.get("type", "No type provided"),
                "description": "Function with unidentifiable name or unexpected structure (possible obfuscation).",
                "line": ctx.start.line, 
                "severity": details.get("severity", "No severity provided"),
                "weight": details.get("weight", 1.0),
                "behavioral_trigger": details.get("behavioral_trigger", None)
            })
        
    def exitMethodDefinition(self, ctx: JavaScriptParser.MethodDefinitionContext) -> None:
        """
        Triggered after a method definition (within classes in ES6+) has been fully parsed.
        Detects suspicious naming, minimal method bodies, and calculates entropy and size.

        Args:
            ctx (JavaScriptParser.MethodDefinitionContext): Parsing context.
        """
        method_name = "UNKNOWN_METHOD"

        if ctx.classElementName():
            # print(ctx.classElementName().getText()) # debugging
            method_name: str = ctx.classElementName().getText()
        elif ctx.getter():
            # print(ctx.getter().classElementName().getText())  # debugging
            method_name: str = ctx.getter().getText()           # Selected all get because the name may be short, but 'get' and 'set' are methods to acces the attributes
        elif ctx.setter():
            # print(ctx.setter().classElementName().getText())    # debugging
            method_name: str = ctx.setter().getText()           # Selected all set because the name may be short, but 'get' and 'set' are methods to acces the attributes

        # print(f"Method detected: {method_name}") # debugging

        details: Dict = self.js_signatures.NAMING_CONVENTIONS["OBFUSCATED_METHOD_SHORT_NAME"]
        if method_name and len(method_name) <= 2:
            self.add_finding({
                "finding_type": details.get("type", "No type provided"),
                "description": f"{details.get('desc', '')} '{method_name}()', possible obfuscation",
                "line": ctx.start.line, 
                "severity": details.get("severity", "No severity provided"),
                "weight": details.get("weight", 1.0),
                "behavioral_trigger": details.get("behavioral_trigger", None)
            })

        elif method_name == "UNKNOWN_METHOD":
            self.add_finding({
                "finding_type": details.get("type", "No type provided"),
                "description": "Method with unidentifiable name or unexpected structure (possible obfuscation).",
                "line": ctx.start.line, 
                "severity": details.get("severity", "No severity provided"),
                "weight": details.get("weight", 1.0),
                "behavioral_trigger": details.get("behavioral_trigger", None)
            })

        # Detection: Suspicious polymorphism and override (for JS)
        # In JS, there is no direct '@override'. We look for an empty or very simple method body.
        if ctx.functionBody() and ctx.functionBody().sourceElements() is None: # Empty body
            details = self.js_signatures.STRUCTURAL_PATTERNS["SUSPICIOUS_OVERRIDE"]
            self.add_finding({
                "finding_type": details.get("type", "No type provided"),
                "description": f"{details.get('desc', '')} '{method_name}'.",
                "line": ctx.start.line, 
                "severity": details.get("severity", "No severity provided"),
                "weight": details.get("weight", 1.0),
                "behavioral_trigger": details.get("behavioral_trigger", None)
            })
        

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
            # Search for secrets and sensitive paths (uses GLOBAL regex)
            if SENSITIVE_PATH_REGEX_GLOBAL.search(string_content):
                details: Dict = self.js_signatures.STRUCTURAL_PATTERNS["SENSITIVE_PATH_ACCESS"]
                self.add_finding({
                    "finding_type": details.get("type", "No type provided"),
                    "description": f"{details.get('desc', '')} Detected in: {string_content}",
                    "line": ctx.start.line, 
                    "severity": details.get("severity", "No severity provided"),
                    "weight": details.get("weight", 1.0),
                    "behavioral_trigger": details.get("behavioral_trigger", None)
                })
            
            for keyword, details in self.js_signatures.STRING_KEYWORDS.items():
                if re.search(re.escape(keyword), string_content, re.IGNORECASE):
                    self.add_finding({
                        "finding_type": details.get("type", "No type provided"),
                        "description": f"{details.get('desc', '')} Found in a string literal containing '{keyword}'",
                        "line": ctx.start.line, 
                        "severity": details.get("severity", "No severity provided"),
                        "weight": details.get("weight", 1.0),
                        "behavioral_trigger": details.get("behavioral_trigger", None)
                    })
                    
    def enterExpressionStatement(self, ctx: JavaScriptParser.ExpressionStatementContext) -> None:
        """
        Triggered upon entering an expression statement (for function calls like eval(), etc.).
        Detects potentially dangerous method calls and self-aware code patterns.

        Args:
            ctx (JavaScriptParser.ExpressionStatementContext): Parsing context.
        """
        # Search for dangerous call patterns in the expression text
        expression_text: str = ctx.expressionSequence().getText()
        # print(expression_text) # debugging
        for pattern, details in self.js_signatures.METHOD_CALLS.items():
            if pattern in expression_text:
                self.add_finding({
                    "finding_type": details.get("type", "No type provided"),
                    "description": f"{details.get('desc', '')} Detected in: '{pattern}'",
                    "line": ctx.start.line, 
                    "severity": details.get("severity", "No severity provided"),
                    "weight": details.get("weight", 1.0),
                    "behavioral_trigger": details.get("behavioral_trigger", None)
                })
                # No 'break' here, as an expression can contain multiple dangerous calls

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
        # Clean report: Remove duplicate findings based on (finding_type, description)
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
            for pattern_name, details in self.js_signatures.BEHAVIORAL_PATTERNS.items():
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