def is_valid_key(ele, key):
    return ele and key and key in ele and ((type(ele[key]) == int and ele[key] > -1) or ele[key])


def is_valid_array(ele, key):
    return is_valid_key(ele, key) and len(ele[key]) > 0
