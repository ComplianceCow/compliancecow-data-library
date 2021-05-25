import math

from compliancecow.utils import dictutils


def authorize_client(client):
    # authorisation logic should be implemented
    return client


def with_retry_for_auth_failure(fn):
    def retry(*kwargs):
        # print('inside utils')
        client = kwargs[0]
        newkwargs = kwargs[1:]
        response = fn(*newkwargs)
        if dictutils.is_valid_key(response, "Message") and response['Message'] == 'UNAUTHORIZED':
            return {'error': 'Token expired'}
        # if dictutils.is_valid_key(response, "Message") or response.status_code:
        #     authorize_client(client)
        #     response = fn(*newkwargs)
        return response
    return retry
