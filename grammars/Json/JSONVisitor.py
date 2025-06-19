# Generated from JSON.g4 by ANTLR 4.13.2
from antlr4 import *
if "." in __name__:
    from .JSONParser import JSONParser
else:
    from JSONParser import JSONParser

# This class defines a complete generic visitor for a parse tree produced by JSONParser.

class JSONVisitor(ParseTreeVisitor):

    # Visit a parse tree produced by JSONParser#json.
    def visitJson(self, ctx:JSONParser.JsonContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JSONParser#obj.
    def visitObj(self, ctx:JSONParser.ObjContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JSONParser#pair.
    def visitPair(self, ctx:JSONParser.PairContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JSONParser#arr.
    def visitArr(self, ctx:JSONParser.ArrContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JSONParser#value.
    def visitValue(self, ctx:JSONParser.ValueContext):
        return self.visitChildren(ctx)



del JSONParser