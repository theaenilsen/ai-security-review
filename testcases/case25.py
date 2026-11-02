import ast


def parse_settings(text):
    value = ast.literal_eval(text)
    if not isinstance(value, dict):
        raise ValueError("forventet en dict")
    return value
