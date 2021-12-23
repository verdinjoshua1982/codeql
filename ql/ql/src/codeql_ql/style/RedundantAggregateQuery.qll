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
 * The aggregate declares a single variable `var`, the value of which is `operand`, and it is only used in `formula`.
 */
predicate redundatAggregate(AstNode aggr, AstNode formula, VarDecl var, AstNode operand) {
  exists(ComparisonFormula comp |
    aggregate(aggr, comp, formula, var) and
    comp.getOperator() = "=" and
    comp.getAnOperand().(VarAccess).getDeclaration() = var and
    not operand.(VarAccess).getDeclaration() = var and
    operand = comp.getAnOperand() and
    count(VarAccess access | access.getDeclaration() = var) = 2 and
    any(VarAccess access | access.getDeclaration() = var) = getAChildOfAggregateFormula(formula)
  ) and
  // negative edges are not neccessarily semantics preserving - we are conservative here and just check for the existance of `not` or any aggregate inside the formula
  not getAChildOfAggregateFormula(formula) instanceof Negation and
  not getAChildOfAggregateFormula(formula) instanceof Aggregate and
  not getAChildOfAggregateFormula(formula) instanceof IfFormula and
  not getAChildOfAggregateFormula(formula) instanceof Forall and
  not getAChildOfAggregateFormula(formula) instanceof Forex and
  // it's not neccessarily redundant inside noopt.
  not aggr.getEnclosingPredicate().getAnAnnotation() instanceof NoOpt
}

/** Gets a (transitive) child of the formula from a `exists(..)` or `any(..)`. */
AstNode getAChildOfAggregateFormula(AstNode formula) {
  aggregate(_, _, formula, _) and result = formula
  or
  result = getAChildOfAggregateFormula(formula).getAChild()
}

/**
 * Holds if `aggr` is of one of the following forms:
 * `exists(var | range)` or `any(var | range)`
 */
private predicate castAggregate(AstNode aggr, Formula range, VarDecl var, string kind) {
  kind = "exists" and
  exists(Exists ex | aggr = ex |
    ex.getRange() = range and
    not exists(ex.getFormula()) and
    count(ex.getArgument(_)) = 1 and
    ex.getArgument(0) = var
  )
  or
  kind = "any" and
  exists(Any anyy | aggr = anyy |
    not exists(anyy.getRange()) and
    anyy.getExpr(0) = range and
    count(anyy.getExpr(_)) = 1 and
    count(anyy.getArgument(_)) = 1 and
    anyy.getArgument(0) = var
  )
  or
  kind = "any" and
  exists(Any anyy | aggr = anyy |
    range = anyy.getRange() and
    count(anyy.getArgument(_)) = 1 and
    anyy.getArgument(0) = var and
    not exists(anyy.getExpr(0))
  )
}

/** Holds if `aggr` is an aggregate that could be replaced with an instanceof or inline cast. */
predicate aggregateCouldBeCast(
  AstNode aggr, ComparisonFormula comp, string kind, VarDecl var, AstNode operand
) {
  castAggregate(aggr, comp, var, kind) and
  comp.getOperator() = "=" and
  count(VarAccess access | access.getDeclaration() = var) = 1 and
  comp.getAnOperand().(VarAccess).getDeclaration() = var and
  operand = comp.getAnOperand() and
  not operand.(VarAccess).getDeclaration() = var
}
