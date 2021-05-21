# def get_header(client):
# token = None
# if (client and client.credentials and client.credentials.token):
#     token = client.credentials.token
# if token is None and client.auth_token:
#     token = client.auth_token
# if token:
#     return {"Authorization": token}
# return None


def get_header(token):
    if token:
        return {"Authorization": token}
    return None
