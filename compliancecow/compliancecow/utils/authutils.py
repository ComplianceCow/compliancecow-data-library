import requests

from compliancecow.utils import dictutils, wsutils


def authorize_client(client):
    client.auth_token = ""
    req_data = {
        "grant_type": "client_credentials"
    }
    if client.client_id and client.client_secret:
     
        req_data['client_id'] = client.client_id
        req_data['client_secret'] = client.client_secret
    elif client.credentials.client_id and client.credentials.client_secret:
        req_data['client_id'] = client.credentials.client_id
        req_data['client_secret'] = client.credentials.client_secret

    url_path = wsutils.get_api_url(
        client.credentials.protocol, client.credentials.domain)
    if url_path:
        
        url_path += "v1/oauth2/token"
        response = requests.post(url_path, data=req_data)
        
        response_json = response.json()
        if dictutils.is_valid_key(response_json, "tokenType") and dictutils.is_valid_key(response_json, "authToken"):
            client.auth_token = response_json["tokenType"] + \
                " "+response_json["authToken"]
            return

    raise Exception("Not a valid credential")


def with_retry_for_auth_failure(fn):
    def retry(*kwargs):
        client = kwargs[0]
        newkwargs = kwargs[1:]
        response = fn(*newkwargs)
        if dictutils.is_valid_key(response, "Message") and response['Message'] == 'UNAUTHORIZED':
            if (client.client_id and client.client_secret) or (client.credentials.client_id and client.credentials.client_secret):
                if len(newkwargs) >= 2 and isinstance(newkwargs[2], str):
                    newkwargslist = list(newkwargs)
                    newkwargslist[2] = client.auth_token
                    newkwargs = tuple(newkwargslist)
                authorize_client(client)
                response = fn(*newkwargs)
            else:
                return {'error': 'Token expired'}
        return response
    return retry
