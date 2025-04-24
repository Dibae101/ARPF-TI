from django import template

register = template.Library()

@register.filter
def subtract(value, arg):
    """
    Subtract the arg from the value.
    Usage: {{ value|subtract:arg }}
    """
    try:
        return int(value) - int(arg)
    except (ValueError, TypeError):
        try:
            return float(value) - float(arg)
        except (ValueError, TypeError):
            return value

@register.filter
def percentage(value, total):
    """
    Calculate percentage of value against total.
    Usage: {{ value|percentage:total }}
    """
    try:
        if int(total) == 0:
            return 0
        return round((int(value) / int(total)) * 100, 1)
    except (ValueError, TypeError, ZeroDivisionError):
        return 0

@register.filter
def threat_severity_color(severity):
    """Return a color class based on threat severity."""
    severity = severity.lower() if severity else ''
    if severity == 'critical':
        return 'bg-red-100 text-red-800'
    elif severity == 'high':
        return 'bg-orange-100 text-orange-800'
    elif severity == 'medium':
        return 'bg-yellow-100 text-yellow-800'
    elif severity == 'low':
        return 'bg-blue-100 text-blue-800'
    else:
        return 'bg-gray-100 text-gray-800'