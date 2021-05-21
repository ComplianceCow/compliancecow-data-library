import re

UUID_PATTERN = re.compile(
    r'^[\da-f]{8}-([\da-f]{4}-){3}[\da-f]{12}$', re.IGNORECASE)


def is_valid_user(client):
    if client:
        return True
    raise Exception({"error": "Not a valid client..!"})


def is_valid_uuid(uuidstr):
    return UUID_PATTERN.match(uuidstr)


def is_valid_uuids(uuidstrs):
    return all(UUID_PATTERN.match(uuidstr) for uuidstr in uuidstrs)


def get_valid_uuids(uuidstrs):
    uuids = []
    for uuidstr in uuidstrs:
        if is_valid_uuid(uuidstr):
            uuids.append(uuidstr)
    return uuids
