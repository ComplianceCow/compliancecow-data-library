import requests
import logging
import json
from compliancecow.utils import constants, dictutils, headerutils


def post(urlPath, reqData, token, security_ctx=None):
    header = headerutils.get_header(token, security_ctx)
    logging.info("POST_REQUEST", url=urlPath, reqData=reqData, header=header)
    response = requests.post(
        urlPath, json=reqData, headers=header)
    # print('raw :', response.raw)
    responseJSON = response.json()
    return responseJSON


def put(urlPath, reqData, token, security_ctx=None):
    header = headerutils.get_header(token, security_ctx)
    logging.info("PUT_REQUEST", url=urlPath, reqData=reqData, header=header)
    response = requests.put(urlPath, json=reqData, headers=header)

    responseJSON = response.json()
    return responseJSON


def patch(urlPath, reqData, token, security_ctx=None):
    header = headerutils.get_header(token, security_ctx)
    logging.info("PATCH_REQUEST", url=urlPath, reqData=reqData, header=header)
    response = requests.patch(urlPath, json=reqData, headers=header)
    responseJSON = response.json()
    return responseJSON


def delete(urlPath, reqData, token, security_ctx=None):
    header = headerutils.get_header(token, security_ctx)
    logging.info("DELETE_REQUEST", url=urlPath, reqData=reqData, header=header)
    response = requests.delete(
        urlPath, json=reqData, headers=header)
    if response.status_code == 204:
        responseJSON = {"msg": "Successfully Deleted"}
    else:
        responseJSON = response.json()
    return responseJSON


def get(urlPath, params, token, security_ctx=None):
    header = headerutils.get_header(token, security_ctx)
    logging.info("GET_REQUEST", url=urlPath, header=header)
    response = requests.get(urlPath, params=params, headers=header)
    # print('raw :', response.raw)
    responseJSON = response.json()
    return responseJSON


def headerbuilder(client):
    header = headerutils.get_header(client)
    # if header:
    #     modifiedheader=dict()
    #     if dictutils.is_valid_key(header, constants.SecurityContext):
    #         securityCtx=header[constants.SecurityContext]
    #         if not isinstance(securityCtx, str):
    #             securityCtx = json.dumps(securityCtx)

    #         # if not isinstance(header, str):
    #         #     if isinstance(header, dict):
    #         #         header = json.dumps(header)
    #         modifiedheader[constants.SecurityContext] = securityCtx
    #         return modifiedheader
    return header


def get_url(protocol, host):
    url = "{protocol}://{host}/".format(protocol=protocol, host=host)
    return url


def get_api_url(protocol, host):
    url = get_url(protocol, host)+"api/"
    return url


def get_rule_engine_url(protocol, host):
    url = "{protocol}://{host}/".format(protocol=protocol, host=host)
    return url


def get_rule_engine_api_url(protocol, host):
    url = get_url(protocol, host)+"api/"
    return url
