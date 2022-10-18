import pandas as pd
from compliancecow.utils import wsutils, constants, dictutils, utils
import json
import io
import base64
import re


def fetch_report(plan_exec_id=None, params=None, auth_token=None, headers=None):
    url = constants.RuleEngineURL+"/api/v1/account/plan-executions/"+plan_exec_id
    headers = header_builder(headers, auth_token)
    return wsutils.get(url, params, headers)


def execute_plan(plan_id=None, controlinputs=None, auth_token=None, header=None):
    url = constants.RuleEngineURL+"/api/v1/account/plan-executions"
    reqObj = {
        "PlanID": plan_id,
        "ControlInputs": controlinputs
    }
    header = header_builder(header, auth_token)
    return wsutils.post(url, reqObj, header)


def get_file(hashed_filename=None, auth_token=None, header=None):
    header = header_builder(header, auth_token)
    urlPath = constants.RuleEngineURL+"/api/url-hash/download/"+hashed_filename
    return wsutils.get(urlPath, None, header)


def header_builder(headers=None, auth_token=None):
    if not headers:
        headers = {}

    if auth_token:
        headers['Authorization'] = auth_token

    if not bool(headers) and not auth_token:
        headers['X-Cow-Security-Context'] = "{}"

    return headers


def get_report_data_from_rule_engine_as_dict(plan_exec_id=None, files_to_be_fetched=None, return_format=utils.ReportDataType.DATAFRAME, header=None):
    """
        Just for developers to consume the data from rule engine in a single method.
        Don't use this method if the data is heavy. Use func:`~get_file_data()` for single file download
    """
    report_data_dict = None
    report_data = fetch_report(
        plan_exec_id, headers=header)
    controls = None
    if dictutils.is_valid_key(report_data, 'items'):
        plan_exec_resp = report_data["items"][0]

        if (dictutils.is_valid_key(plan_exec_resp, 'ID') and dictutils.is_valid_array(plan_exec_resp, 'Controls')):

            controls = [{"Controls": plan_exec_resp['Controls']}]
        control_meta, instances, files_to_fetch_datas = get_meta_data_from_report(
            controls, files_to_be_fetched,  return_format)
        if files_to_fetch_datas and bool(files_to_fetch_datas):
            report_data_dict = {}
            for fileitem in files_to_fetch_datas:
                previous_data = []
                if return_format == utils.ReportDataType.DATAFRAME and fileitem['fileName'] in report_data_dict:
                    previous_data = report_data_dict[fileitem['fileName']]
                current_data = get_data_from_rule_engine(
                    fileHash=fileitem["fileHash"], return_format=return_format, header=header)
                if len(previous_data) > 0:
                    current_data.extend(previous_data)
                report_data_dict[fileitem['fileName']] = current_data
    return report_data_dict


def get_report_data_as_dict_array(plan_exec_id=None, files_to_be_fetched=None, return_format=utils.ReportDataType.DATAFRAME, control_id=None, headers=None, header=None):
    """
        Just for developers to consume the data from rule engine in a single method. 
        Don't use this method if the data is heavy. Use func:`~get_file_data()` for single file download
    """

    report_data_dict = None
    output_data_dict = pd.DataFrame()

    if headers is None:
        headers = dict()
    if header and bool(header):
        headers.update(header)

    report_data = fetch_report(plan_exec_id, headers=headers)
    if dictutils.is_valid_array(report_data, 'items'):
        plan_exec_resp = report_data["items"][0]
        if (dictutils.is_valid_key(plan_exec_resp, 'ID') and dictutils.is_valid_array(plan_exec_resp, 'Controls')):
            controls = [{"Controls": plan_exec_resp['Controls']}]
        _, _, files_to_fetch_datas = get_meta_data_from_report(
            controls, files_to_be_fetched,  return_format)
        if files_to_fetch_datas and bool(files_to_fetch_datas):
            report_data_dict = {}
            for fileitem in files_to_fetch_datas:
                report_data_dict["instance"] = fileitem['instanceName']
                report_data_dict["fileName"] = fileitem['fileName']
                report_data_dict['fileData'] = get_data_from_rule_engine(
                    fileHash=fileitem["fileHash"], return_format=return_format, header=headers)
                output_data_dict = output_data_dict.append(
                    report_data_dict, ignore_index=True)
    return output_data_dict


def get_meta_data_from_report(controls, files_to_be_fetched=None, control_meta=None, instances=None, file_datas=None, return_format=utils.ReportDataType.DATAFRAME):

    if files_to_be_fetched is None:
        files_to_be_fetched = []
    if control_meta is None:
        control_meta = []
    if instances is None:
        instances = []
    if file_datas is None:
        file_datas = []

    for control in controls:
        if dictutils.is_valid_array(control, 'Controls'):
            get_meta_data_from_report(control['Controls'],
                                      files_to_be_fetched, control_meta, instances, file_datas, return_format)
        else:
            if (dictutils.is_valid_key(control, 'RuleSetOutput')
                    and dictutils.is_valid_array(control['RuleSetOutput'], 'ruleOutputs')):
                control_data = {
                    'controlId': control['ControlID'],
                    'tag': control['Tag'],
                    'validationStatus': control['Tag']
                }

                if dictutils.is_valid_key(control, 'RuleSetOutput') and dictutils.is_valid_key(control['RuleSetOutput'], 'ValidationStatus'):
                    control_data['validationStatus'] = control['RuleSetOutput']['ValidationStatus']

                if dictutils.is_valid_key(control, 'RuleSetOutput') and dictutils.is_valid_key(control['RuleSetOutput'], 'ValidationProgress'):
                    control_data['validationProgress'] = control['RuleSetOutput']['ValidationProgress']

                if dictutils.is_valid_key(control, 'RuleSetOutput') and dictutils.is_valid_key(control['RuleSetOutput'], 'ExecutionProgress'):
                    control_data['executionProgress'] = control['RuleSetOutput']['ExecutionProgress']

                control_meta.append(control_data)

                for ruleoutput in control['RuleSetOutput']['ruleOutputs']:
                    instance,file_data=get_filedata_and_instancedata(ruleoutput,files_to_be_fetched,instances,file_datas)
                    instances.append(instance)
                    file_datas.append(file_data)
        return control_meta, instances, file_datas

def get_filedata_and_instancedata(ruleoutput,files_to_be_fetched=None):
    if (dictutils.is_valid_key(ruleoutput, 'ruleiovalues') and dictutils.is_valid_key(ruleoutput['ruleiovalues'], 'outputFiles')):
        instance_data = {}
        
        if dictutils.is_valid_key(ruleoutput, 'ControlID'):
            instance_data['ControlID'] = ruleoutput["ControlID"]
        if dictutils.is_valid_key(ruleoutput, 'instanceName'):
            instance_data['instanceName'] = ruleoutput["instanceName"]

        if dictutils.is_valid_key(ruleoutput, 'state'):
            instance_data['state'] = ruleoutput["state"]

        if dictutils.is_valid_key(ruleoutput, 'complianceStatus'):
            instance_data['complianceStatus'] = ruleoutput["complianceStatus"]

        if dictutils.is_valid_key(ruleoutput, 'compliancePCT'):
            instance_data['compliancePCT'] = ruleoutput["compliancePCT"]

        
        for key, value in ruleoutput['ruleiovalues']['outputFiles'].items():
            filename = ""
            if value:
                filename = get_file_name_from_report_data(
                    value)
            if filename and not ("OtherOutputs.json" in value or "RuleIOSummary.json" in value or (len(files_to_be_fetched) > 0 and filename not in files_to_be_fetched)):
                file_data = {
                    'instanceName': ruleoutput["instanceName"],
                    "fileName": filename,
                    "fileHash": key
                }
                if dictutils.is_valid_key(ruleoutput, 'ControlID'):
                    file_data['ControlID'] = ruleoutput["ControlID"]
                return  instance_data,file_data        
    return None, None
def get_meta_data_from_ruleset_report(controls, files_to_be_fetched=None,  instances=None, file_datas=None, return_format=utils.ReportDataType.DATAFRAME):
    if files_to_be_fetched is None:
        files_to_be_fetched = []
    if instances is None:
        instances = []
    if file_datas is None:
        file_datas = []
    
    for ruleoutput in controls["Controls"]:
        instance,file_data=get_filedata_and_instancedata(ruleoutput,files_to_be_fetched=files_to_be_fetched)
        instances.append(instance)
        file_datas.append(file_data)
    return instances,file_datas

def get_file_data(plan_exec_id, file_name, header, available_file_infos: list = None, return_format=utils.ReportDataType.DATAFRAME):
    report_data = fetch_report(plan_exec_id, headers=header)
    report_data_dict = dict()
    if dictutils.is_valid_array(report_data, 'items'):
        plan_exec_resp = report_data["items"][0]
        if available_file_infos is None and (dictutils.is_valid_key(plan_exec_resp, 'ID') and dictutils.is_valid_array(plan_exec_resp, 'Controls')):
            controls = [{"Controls": plan_exec_resp['Controls']}]
            control_meta, instances, available_file_infos = get_meta_data_from_report(
                controls, [file_name],  return_format)

            if available_file_infos:
                for fileitem in available_file_infos:
                    if file_name == fileitem['fileName']:
                        report_data_dict["instance"] = fileitem['instanceName']
                        report_data_dict["fileName"] = fileitem['fileName']
                        report_data_dict['fileData'] = get_data_from_rule_engine(
                            fileHash=fileitem["fileHash"], return_format=return_format, header=header)
                        break
    return report_data_dict

def get_file_name_from_report_data(rule_op_file_name):
    if rule_op_file_name.find('-')!= -1:
        val = rule_op_file_name.split('-')# Need to be change to regex
    else:
        val = re.split(r'[-.]',rule_op_file_name )  # Need to be change to regex
    val = val[0]
    return val

def get_data_from_rule_engine(fileHash=None, control_id=None, instance_name=None, return_format=None, header=None):
    data = {}
    final_data = {}
    resp = get_file(fileHash, header=header)
    if dictutils.is_valid_key(resp, 'FileName') and 'FileContent' in resp:
        file_byts = resp['FileContent']
        data = base64.b64decode(file_byts)

        if return_format == utils.ReportDataType.JSON:
            final_data = {
                'controlId': control_id,
                'instanceName': instance_name,
                'fileHash': fileHash,
                'fileContent': data
            }
            data = json.loads(data.decode('utf-8'))
            final_data['fileContent'] = data

        if return_format == utils.ReportDataType.DATAFRAME:
            if '.csv' in resp['FileName']:
                s = str(data, 'utf-8')
                dataset = io.StringIO(s)
                df = pd.read_csv(dataset)
                final_data = df.to_dict()
            elif '.parquet' in resp['FileName']:
                dataset = io.BytesIO(data)
                final_data = pd.read_parquet(dataset)
            else:
                final_data = json.loads(data.decode('utf-8'))

    return final_data
