"""Whole-prompt estimates and conservative parsing of provider quota headers."""
import math
import re


def estimate_tokens(messages):
    # Approximation, not the model tokenizer. Count schema/instructions as well
    # as context; UTF-8 byte length avoids undercounting non-ASCII code as chars.
    return math.ceil(sum(len(m['content'].encode('utf-8')) for m in messages) / 3) + 16 * len(messages)


def compact_schema(value, root=True):
    if isinstance(value, list): return [compact_schema(v, False) for v in value]
    if not isinstance(value, dict): return value
    result = {}
    for key, item in value.items():
        if key in {'title', 'default', 'description'} and not (root and key == 'title'): continue
        if key in {'properties', '$defs'}:
            # These keys name fields/models, so a field named "title" survives.
            result[key] = {name: compact_schema(schema, False) for name, schema in item.items()}
        else: result[key] = compact_schema(item, False)
    return result


def seconds(value):
    """Provider durations such as 7.5s or 1m2s; reject arbitrary header text."""
    if not isinstance(value, str) or len(value) > 80: return None
    if re.fullmatch(r'\d+(?:\.\d+)?', value): result = float(value)
    elif re.fullmatch(r'(?:\d+(?:\.\d+)?(?:ms|s|m|h))+', value):
        result = sum(float(n) * {'ms': .001, 's': 1, 'm': 60, 'h': 3600}[unit]
                     for n, unit in re.findall(r'(\d+(?:\.\d+)?)(ms|s|m|h)', value))
    else: return None
    return result if math.isfinite(result) and 0 <= result <= 86400 else None


def integer(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{1,10}', value): return None
    result = int(value)
    return result if result <= 1_000_000_000 else None
