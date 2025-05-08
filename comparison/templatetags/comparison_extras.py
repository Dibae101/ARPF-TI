from django import template

register = template.Library()

@register.filter
def filter_by_rule_type(queryset, rule_type):
    """Get the count of rules for a specific rule type from a queryset"""
    for item in queryset:
        if item['rule_type'] == rule_type:
            return item['count']
    return 0

@register.filter
def subtract(value, arg):
    """Subtract the arg from the value"""
    return value - arg

@register.filter
def multiply(value, arg):
    """Multiply the value by the arg"""
    if value is None:
        return 0
    return value * arg

@register.filter
def divide(value, arg):
    """Divide the value by the arg"""
    if arg is None or arg == 0:
        return 0
    return value / arg

@register.filter
def percentage(value, total):
    """Calculate percentage with fallback to 0"""
    if total is None or total == 0:
        return 0
    return (value / total) * 100