import json
# def get_header(client):
# token = None
# if (client and client.credentials and client.credentials.token):
#     token = client.credentials.token
# if token is None and client.auth_token:
#     token = client.auth_token
# if token:
#     return {"Authorization": token}
# return None


def get_header(token, security_ctx=None):
    header = None
    if token:
        header = {"Authorization": token}
    if security_ctx and isinstance(security_ctx, dict) and bool(security_ctx):
        header = {"X-Cow-Security-Context": json.dumps(security_ctx)}
    return header
