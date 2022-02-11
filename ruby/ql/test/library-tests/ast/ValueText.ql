import ruby

from Expr e, ConstantValue value
where value = e.getConstantValue()
select e, value, value.getValueType()
