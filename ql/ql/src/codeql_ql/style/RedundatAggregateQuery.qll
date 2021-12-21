import ql

/**
 * Holds if `aggr` is of one of the following forms:
 * `exists(var | range | formula)` or `any(var | range | formula)`
 */
private predicate aggregate(AstNode aggr, Formula range, AstNode formula, VarDecl var) {
  exists(Exists ex | aggr = ex |
    ex.getRange() = range and
    ex.getFormula() = formula and
    count(ex.getArgument(_)) = 1 and
    ex.getArgument(0) = var
  )
  or
  exists(Any anyy | aggr = anyy |
    anyy.getRange() = range and
    anyy.getExpr(0) = formula and
    count(anyy.getExpr(_)) = 1 and
    count(anyy.getArgument(_)) = 1 and
    anyy.getArgument(0) = var
  )
}

/**
 * Holds if `aggr` is a redundant aggregate.
 */
predicate redundatAggregate(AstNode aggr, AstNode formula, VarDecl var) {
  exists(AstNode operand, ComparisonFormula comp |
    aggregate(aggr, comp, formula, var) and
    comp.getOperator() = "=" and
    comp.getAnOperand().(VarAccess).getDeclaration() = var and
    not operand.(VarAccess).getDeclaration() = var and
    operand = comp.getAnOperand() and
    count(VarAccess access | access.getDeclaration() = var) = 2 and
    any(VarAccess access | access.getDeclaration() = var).getParent+() = formula
  )
}
