def obfuscate_password(attributes: dict) -> dict:
    attributes["password"] = "****" if attributes["password"] else None
    return attributes


def nonify_empty_iterable(obj):
    if obj is None:
        return obj
    if len(obj) == 0:
        return None
    return obj
