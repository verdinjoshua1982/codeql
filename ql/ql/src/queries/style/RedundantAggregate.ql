/**
 * @name Redundant aggregate
 * @description An exists/any aggregate where a single variable is assigned in the range,
 *              and used once in the formula, can be replaced with something simpler.
 * @kind problem
 * @problem.severity warning
 * @id ql/redundant-aggregate
 * @precision high
 */

import ql
import codeql_ql.style.RedundantAggregateQuery

from AstNode aggr, AstNode formula, VarDecl var
where redundantAggregate(aggr, formula, var, _)
select aggr,
  "The $@ in this aggregate is assigned and used exactly once, and the aggregate can therefore be simplified away.",
  var, "variable " + var.getName()
