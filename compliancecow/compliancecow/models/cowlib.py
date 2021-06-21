import json
from logging import error
import os
from uuid import UUID
from typing import Any, TypeVar, Type, cast, List, Union
from datetime import datetime
import dateutil.parser
import pandas as pd
import pyarrow.parquet as pq
import base64
import pyarrow as pa

from compliancecow.utils import constants, dictutils, authutils, utils, wsutils, validateutils
from compliancecow.models import configuration, cowreport
# from compliancecow.data import metadata


T = TypeVar("T")


class Credential:
    auth_token: str
    client_id: str
    client_secret: str
    refresh_token: str
    domain: str
    protocol: str

    def __init__(self, auth_token: str = None, client_id: str = None, client_secret: str = None, refresh_token: str = None, domain: str = None, protocol: str = None) -> None:
        self.auth_token = auth_token
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        self.domain = domain
        self.protocol = protocol

    @staticmethod
    def from_dict(obj: Any) -> 'Credential':
        credential = None
        if isinstance(obj, dict):
            auth_token = client_id = client_secret = refresh_token = domain = protocol = None
            if dictutils.is_valid_key(obj, "auth_token"):
                auth_token = utils.from_str(obj.get("auth_token"))
            if dictutils.is_valid_key(obj, "client_id"):
                client_id = utils.from_str(obj.get("client_id"))
            if dictutils.is_valid_key(obj, "client_secret"):
                client_secret = utils.from_str(obj.get("client_secret"))
            if dictutils.is_valid_key(obj, "refresh_token"):
                refresh_token = utils.from_str(obj.get("refresh_token"))
            if dictutils.is_valid_key(obj, "domain"):
                domain = utils.from_str(obj.get("domain"))
            if dictutils.is_valid_key(obj, "protocol"):
                protocol = utils.from_str(obj.get("protocol"))
            credential = Credential(
                auth_token, client_id, client_secret, refresh_token, domain, protocol)
        return credential

    def to_dict(self) -> dict:
        result: dict = {}
        if self.auth_token:
            result["auth_token"] = utils.from_str(self.auth_token)
        if self.client_id:
            result["client_id"] = utils.from_str(self.client_id)
        if self.client_secret:
            result["client_secret"] = utils.from_str(self.client_secret)
        if self.refresh_token:
            result["refresh_token"] = utils.from_str(self.refresh_token)
        if self.domain:
            result["domain"] = utils.from_str(self.domain)
        if self.protocol:
            result["protocol"] = utils.from_str(self.protocol)
        return result


class Client:
    auth_token: str
    credential_dict: dict
    file_path: str
    client_id: str
    client_secret: str
    credentials: Credential

    def __init__(self, auth_token: str = None, credential_dict: dict = None, file_path: str = None, client_id: str = None, client_secret: str = None, credentials: Credential = None) -> None:
        self.auth_token = auth_token
        self.credential_dict = credential_dict
        self.file_path = file_path
        self.client_id = client_id
        self.client_secret = client_secret
        self.credentials = credentials
        if file_path and not bool(credential_dict):
            with open(file_path) as jsonfile:
                self.credential_dict = json.load(jsonfile)
        if bool(self.credential_dict):
            self.credentials = Credential.from_dict(self.credential_dict)

        if self.credentials is None:
            self.credentials = Credential()

        if not self.auth_token and self.credentials.auth_token:
            self.auth_token = self.credentials.auth_token

        if not self.credentials.protocol:
            self.credentials.protocol = constants.ComplinaceCowProtocol

        if not self.credentials.domain:
            self.credentials.domain = constants.ComplinaceCowHostName

        if not self.auth_token and not self.credentials.auth_token:
            raise Exception("Not a valid credential")

    @staticmethod
    def from_dict(obj: Any) -> 'Client':
        client = None
        if isinstance(obj, dict):
            auth_token = credential_dict = file_path = client_id = client_secret = credentials = None
            if dictutils.is_valid_key(obj, "auth_token"):
                auth_token = utils.from_str(obj.get("auth_token"))
            if dictutils.is_valid_key(obj, "credential_dict"):
                credential_dict = utils.from_str(obj.get("credential_dict"))
            if dictutils.is_valid_key(obj, "file_path"):
                file_path = utils.from_str(obj.get("file_path"))
            if dictutils.is_valid_key(obj, "client_id"):
                client_id = utils.from_str(obj.get("client_id"))
            if dictutils.is_valid_key(obj, "client_secret"):
                client_secret = utils.from_str(obj.get("client_secret"))
            if dictutils.is_valid_key(obj, "credentials"):
                credentials = Credential.from_dict(obj.get("credentials"))
            client = Client(auth_token, credential_dict, file_path,
                            client_id, client_secret, credentials)
        return client

    def to_dict(self) -> dict:
        result: dict = {}
        if self.auth_token:
            result["auth_token"] = str(self.auth_token)
        if self.credential_dict:
            result["credential_dict"] = str(self.credential_dict)
        if self.file_path:
            result["file_path"] = utils.from_str(self.file_path)
        if self.client_id:
            result["client_id"] = utils.from_str(self.client_id)
        if self.client_secret:
            result["client_secret"] = utils.from_str(self.client_secret)
        if self.credentials and bool(self.credentials):
            result["credentials"] = utils.to_class(
                Credential, self.credentials)
        return result

    def get_plans(self, ids=None, is_base_fields_only=True) -> List['Plan'] and dict:
        plans = errors = None
        if self.auth_token:
            url = wsutils.get_api_url(
                self.credentials.protocol, self.credentials.domain)
            if url:
                url += "v1/plans"
                querydict = dict()
                if ids:
                    ids = list(set(validateutils.get_valid_uuids(ids)))
                    querydict['ids'] = ids
                respJson = authutils.with_retry_for_auth_failure(
                    wsutils.get)(self, url, querydict, self.auth_token)
                if dictutils.is_valid_key(respJson, 'error') or not dictutils.is_valid_array(respJson, constants.Items):
                    errors = respJson
                if dictutils.is_valid_array(respJson, constants.Items):
                    plans = utils.from_list(
                        Plan.from_dict, respJson.get(constants.Items))
        return plans, errors

    def get_plan_instances(self, plan=None, plan_id=None, ids=None, from_date=None, to_date=None, is_base_fields_only=True) -> List['PlanInstance'] and dict:
        # error handle for token expiry with try catch or with exec.

        if plan is None and plan_id is None:
            return None, {'error': 'Plan and PlanID both cannot be empty'}

        if plan_id is None:
            plan_id = plan.id

        plan_instances = errors = None
        if self.auth_token:
            url = wsutils.get_api_url(
                self.credentials.protocol, self.credentials.domain)
            if url:
                url += "v1/plan-instances"
                plan_ids = [str(plan_id)]
                querydict = dict()
                if ids:
                    ids = list(set(validateutils.get_valid_uuids(ids)))
                    querydict['ids'] = ids
                if plan_ids:
                    plan_ids = list(
                        set(validateutils.get_valid_uuids(plan_ids)))
                    querydict['plan_ids'] = plan_ids
                if from_date:
                    querydict['created_at_start_time'] = from_date
                if to_date:
                    querydict['created_at_end_time'] = to_date

                respJson = authutils.with_retry_for_auth_failure(wsutils.get)(
                    self, url, querydict, self.auth_token)
                if dictutils.is_valid_key(respJson, 'error') or not dictutils.is_valid_array(respJson, constants.Items):
                    errors = respJson
                if dictutils.is_valid_array(respJson, constants.Items):
                    plan_instances = utils.from_list(
                        PlanInstance.from_dict, respJson.get(constants.Items))

                    utils.modify_plan_instances(plan_instances)

        return plan_instances, errors

    def get_evidence_data(self, evidence=None, record_ids=None, owner_type="user", is_user_priority=True, is_src_fetch_call=True) -> pd.DataFrame and dict:
        data = pd.DataFrame
        errors = None
        if evidence is None:
            errors = {'error': 'evidence object cannot be empty'}

        if self.auth_token:
            url = wsutils.get_api_url(
                self.credentials.protocol, self.credentials.domain)
            if url:
                url += "v1/datahandler/fetch-data"
                reqDict = {
                    "fileName": evidence.file_name,
                    "planGUID": str(evidence.plan_id),
                    "planExecGUID": str(evidence.plan_instance_id),
                    "controlGUID": str(evidence.plan_control_id),
                    "templateType": "evidence",
                    "ownerType": owner_type,
                    "evidenceID": str(evidence.id),
                    "isUserPriority": is_user_priority,
                    "isSrcFetchCall": is_src_fetch_call,
                    "recordIds": record_ids
                }

                responseJson = authutils.with_retry_for_auth_failure(wsutils.post)(
                    self, url, reqDict, self.auth_token)
                if dictutils.is_valid_key(responseJson, "error"):
                    errors = responseJson
                if dictutils.is_valid_key(responseJson, "fileBytes"):
                    message_bytes = base64.b64decode(responseJson['fileBytes'])
                    reader = pa.BufferReader(message_bytes)
                    data = pq.read_table(reader).to_pandas()
        return data, errors

    def get_configurations(self, id=None, is_meta_data_to_be_return=False) -> List[Any] and dict:
        configurations = errors = None
        if self.auth_token:
            url = wsutils.get_api_url(
                self.credentials.protocol, self.credentials.domain)
            if url:
                url += "v1/configuration"
                querydict = {}
                if id:
                    querydict['id'] = id
                if is_meta_data_to_be_return:
                    querydict['isMetaDataToBeReturn'] = is_meta_data_to_be_return

                responseJson = authutils.with_retry_for_auth_failure(wsutils.get)(
                    self, url, querydict, self.auth_token)

                if dictutils.is_valid_key(responseJson, "error"):
                    errors = responseJson

                if dictutils.is_valid_array(responseJson, constants.Items):
                    configurations = utils.from_list(
                        configuration.Configuration.from_dict, responseJson.get(constants.Items))

        return configurations, errors

    def get_dashboard_categories(self, plan_id, plan_name=None) -> List[Any] and dict:
        dashboard_categories = errors = None
        if self.auth_token:
            url = wsutils.get_api_url(
                self.credentials.protocol, self.credentials.domain)
            if url:
                url += "v1/plans/"+plan_id+"/categories/"
                responseJson = authutils.with_retry_for_auth_failure(wsutils.get)(
                    self, url, None, self.auth_token)

                if dictutils.is_valid_key(responseJson, "error"):
                    errors = responseJson

                if dictutils.is_valid_array(responseJson, constants.Items):
                    dashboard_categories = utils.from_list(
                        cowreport.ReportCategories.from_dict, responseJson.get(constants.Items))

        return dashboard_categories, errors

    def get_dashboards(self, plan_id, category_id) -> List[Any] and dict:
        dashboards = errors = None
        if self.auth_token:
            url = wsutils.get_api_url(
                self.credentials.protocol, self.credentials.domain)
            if url:
                url += "v1/plans/"+plan_id+"/categories/"+category_id+"/dashboards/"
                responseJson = authutils.with_retry_for_auth_failure(wsutils.get)(
                    self, url, None, self.auth_token)

                if dictutils.is_valid_key(responseJson, "error"):
                    errors = responseJson

                if dictutils.is_valid_array(responseJson, constants.Items):
                    dashboards = utils.from_list(
                        cowreport.Dashboard.from_dict, responseJson.get(constants.Items))

        return dashboards, errors

    def get_reports(self, plan_id=None, report_id=None, report_name=None, dashboard_id=None, category_id=None, tags='report'):
        reports = errors = None

        if self.auth_token:
            url = wsutils.get_api_url(
                self.credentials.protocol, self.credentials.domain)
            if url:
                url += "v1/report-cards"
                query_dict = {'reportId': report_id, 'reportName': report_name,
                              'dashboardId': dashboard_id, 'categoryId': category_id, 'tags': tags,
                              "planId": plan_id}

                responseJson = authutils.with_retry_for_auth_failure(wsutils.get)(
                    self, url, query_dict, self.auth_token)

                if dictutils.is_valid_key(responseJson, "error"):
                    errors = responseJson

                if dictutils.is_valid_array(responseJson, constants.Items):
                    reports = utils.from_list(
                        cowreport.Report.from_dict, responseJson.get(constants.Items))

        return reports, errors

    def __get_report_details(self, report_id: str = None, report_name: str = None, type: cowreport.Type = cowreport.Type.DATA, format_type: cowreport.DataType = cowreport.DataType.JSON) -> List[Any] and dict:
        report_data = errors = None

        if report_id is None and report_name is None:
            return None, {'error': 'report_id/report_name both cannot be empty'}

        if self.auth_token:
            url = wsutils.get_api_url(
                self.credentials.protocol, self.credentials.domain)

            if report_id is None:
                reports, error = self.get_reports(
                    report_name=report_name)
                if reports is None or not reports or error or bool(error):
                    return None, {'error': 'report not available'}
                else:
                    report_id = str(reports[0].id)
            if url:
                url += "v1/report-cards/"+report_id
                query_dict = {"type": format_type.value,
                              "format_type": format_type.value}
                responseJson = authutils.with_retry_for_auth_failure(wsutils.get)(
                    self, url, query_dict, self.auth_token)

                if dictutils.is_valid_key(responseJson, "error"):
                    errors = responseJson

                report_data = responseJson

        return report_data, errors

    def get_report_schema(self, report_id: str = None, report_name: str = None) -> cowreport.ReportSchema and dict:
        response, errors = self.__get_report_details(
            report_id=report_id, report_name=report_name, type=cowreport.Type.SCHEMA)
        if errors is None and not bool(errors):
            return cowreport.report_schema_from_dict(response), errors
        return None, errors

    def get_report_data(self, report_id: str = None, report_name: str = None, format_type: cowreport.DataType = cowreport.DataType.JSON) -> cowreport.ReportData and dict:
        response, errors = self.__get_report_details(
            report_id=report_id, report_name=report_name, type=cowreport.Type.DATA, format_type=format_type)
        if errors is None and not bool(errors):
            return cowreport.report_data_from_dict(response), errors
        return None, errors


def client_from_dict(s: Any) -> Client:
    return Client.from_dict(s)


def client_to_dict(x: Client) -> Any:
    return utils.to_class(Client, x)


class Evidence:
    id: UUID
    name: str
    description: str
    file_name: str
    type: str
    plan_instance_control_id: UUID
    plan_id: UUID
    plan_instance_id: UUID
    plan_control_id: UUID

    def __init__(self, id: UUID, name: str, description: str, file_name: str, type: str, plan_instance_control_id: UUID, plan_id: UUID, plan_instance_id: UUID, plan_control_id: UUID) -> None:
        self.id = id
        self.name = name
        self.description = description
        self.file_name = file_name
        self.type = type
        self.plan_instance_control_id = plan_instance_control_id
        self.plan_id = plan_id
        self.plan_instance_id = plan_instance_id
        self.plan_control_id = plan_control_id

    def get_data(self, auth_token=None, record_ids=None, owner_type="user", is_user_priority=True, is_src_fetch_call=True) -> pd.DataFrame and dict:
        data = pd.DataFrame
        errors = None
        if auth_token:
            url = wsutils.get_api_url(
                constants.ComplinaceCowProtocol, constants.ComplinaceCowHostName)
            if url:
                url += "v1/datahandler/fetch-data"
                reqDict = {
                    "fileName": self.file_name,
                    "planGUID": str(self.plan_id),
                    "planExecGUID": str(self.plan_instance_id),
                    "controlGUID": str(self.plan_control_id),
                    "templateType": "evidence",
                    "ownerType": owner_type,
                    "evidenceID": str(self.id),
                    "isUserPriority": is_user_priority,
                    "isSrcFetchCall": is_src_fetch_call,
                    "recordIds": record_ids
                }

                responseJson = wsutils.post(url, reqDict, auth_token)

                if dictutils.is_valid_key(responseJson, "error"):
                    errors = responseJson
                if dictutils.is_valid_key(responseJson, "data"):
                    message_bytes = base64.b64decode(responseJson['data'])
                    reader = pa.BufferReader(message_bytes)
                    data = pq.read_table(reader).to_pandas()
        return data, errors

    @staticmethod
    def from_dict(obj: Any) -> 'Evidence' or None:
        evidence = None
        if isinstance(obj, dict):
            id = name = description = file_name = type = plan_instance_control_id = plan_id = plan_instance_id = plan_control_id = None
            if dictutils.is_valid_key(obj, "id"):
                id = UUID(obj.get("id"))
            if dictutils.is_valid_key(obj, "name"):
                name = utils.from_str(obj.get("name"))
            if dictutils.is_valid_key(obj, "description"):
                description = utils.from_str(obj.get("description"))
            if dictutils.is_valid_key(obj, "fileName"):
                file_name = utils.from_str(obj.get("fileName"))
            if dictutils.is_valid_key(obj, "type"):
                type = utils.from_str(obj.get("type"))
            if dictutils.is_valid_key(obj, "planInstanceControlId"):
                plan_instance_control_id = UUID(
                    obj.get("planInstanceControlId"))
            if dictutils.is_valid_key(obj, "planId"):
                plan_id = UUID(obj.get("planId"))
            if dictutils.is_valid_key(obj, "planInstanceId"):
                plan_instance_id = UUID(obj.get("planInstanceId"))
            if dictutils.is_valid_key(obj, "planControlId"):
                plan_control_id = UUID(obj.get("planInstanceId"))
            evidence = Evidence(id, name, description,
                                file_name, type, plan_instance_control_id, plan_id, plan_instance_id, plan_control_id)
        return evidence

    def to_dict(self) -> dict:
        result: dict = {}
        if self.id:
            result["id"] = str(self.id)
        if self.name:
            result["name"] = utils.from_str(self.name)
        if self.description:
            result["description"] = utils.from_str(self.description)
        if self.file_name:
            result["fileName"] = utils.from_str(self.file_name)
        if self.type:
            result["type"] = utils.from_str(self.type)
        if self.plan_instance_control_id:
            result["planInstanceControlId"] = str(
                self.plan_instance_control_id)
        if self.plan_instance_id:
            result["planInstanceId"] = str(
                self.plan_instance_id)
        if self.plan_id:
            result["planId"] = str(
                self.plan_id)
        if self.plan_control_id:
            result["planControlId"] = str(
                self.plan_control_id)
        return result


class CheckList:
    id: UUID
    plan_instance_id: UUID
    plan_instance_control_id: UUID
    topic: str
    description: str
    creator: UUID
    priority: str
    tags: List[str]
    assignedto: List[UUID]
    duedate: str
    last_updated: datetime
    created_on: datetime
    deleted_at: None

    def __init__(self, id: UUID, plan_instance_id: UUID, plan_instance_control_id: UUID, topic: str, description: str, creator: UUID, priority: str, tags: List[str], assignedto: List[UUID], duedate: str, last_updated: datetime, created_on: datetime, deleted_at: None) -> None:
        self.id = id
        self.plan_instance_id = plan_instance_id
        self.plan_instance_control_id = plan_instance_control_id
        self.topic = topic
        self.description = description
        self.creator = creator
        self.priority = priority
        self.tags = tags
        self.assignedto = assignedto
        self.duedate = duedate
        self.last_updated = last_updated
        self.created_on = created_on
        self.deleted_at = deleted_at

    @staticmethod
    def from_dict(obj: Any) -> 'CheckList' or None:
        check_list = None
        if isinstance(obj, dict):
            id = plan_instance_id = plan_instance_control_id = topic = description = creator = priority = tags = assignedto = duedate = last_updated = created_on = deleted_at = None
            if dictutils.is_valid_key(obj, "ID"):
                id = UUID(obj.get("ID"))
            if dictutils.is_valid_key(obj, "planInstanceId"):
                plan_instance_id = UUID(obj.get("planInstanceId"))
            if dictutils.is_valid_key(obj, "planInstanceControlId"):
                plan_instance_control_id = UUID(
                    obj.get("planInstanceControlId"))
            if dictutils.is_valid_key(obj, "topic"):
                topic = utils.from_str(obj.get("topic"))
            if dictutils.is_valid_key(obj, "description"):
                description = utils.from_str(obj.get("description"))
            if dictutils.is_valid_key(obj, "creator"):
                creator = UUID(obj.get("creator"))
            if dictutils.is_valid_key(obj, "priority"):
                priority = utils.from_str(obj.get("priority"))
            if dictutils.is_valid_key(obj, "tags"):
                tags = utils.from_list(utils.from_str, obj.get("tags"))
            if dictutils.is_valid_key(obj, "assignedto"):
                assignedto = utils.from_list(
                    lambda x: UUID(x), obj.get("assignedto"))
            if dictutils.is_valid_key(obj, "duedate"):
                duedate = utils.from_str(obj.get("duedate"))
            if dictutils.is_valid_key(obj, "LastUpdated"):
                last_updated = utils.from_datetime(obj.get("LastUpdated"))
            if dictutils.is_valid_key(obj, "CreatedOn"):
                created_on = utils.from_datetime(obj.get("CreatedOn"))
            if dictutils.is_valid_key(obj, "DeletedAt"):
                deleted_at = utils.from_none(obj.get("DeletedAt"))
            check_list = CheckList(id, plan_instance_id, plan_instance_control_id, topic, description,
                                   creator, priority, tags, assignedto, duedate, last_updated, created_on, deleted_at)
        return check_list

    def to_dict(self) -> dict:
        result: dict = {}
        if self.id:
            result["ID"] = str(self.id)
        if self.plan_instance_id:
            result["planInstanceId"] = str(self.plan_instance_id)
        if self.plan_instance_control_id:
            result["planInstanceControlId"] = str(
                self.plan_instance_control_id)
        if self.topic:
            result["topic"] = utils.from_str(self.topic)
        if self.description:
            result["description"] = utils.from_str(self.description)
        if self.creator:
            result["creator"] = str(self.creator)
        if self.priority:
            result["priority"] = utils.from_str(self.priority)
        if self.tags:
            result["tags"] = utils.from_list(utils.from_str, self.tags)
        if self.assignedto:
            result["assignedto"] = utils.from_list(
                lambda x: str(x), self.assignedto)
        if self.duedate:
            result["duedate"] = utils.from_str(self.duedate)
        if self.last_updated:
            result["LastUpdated"] = self.last_updated.isoformat()
        if self.created_on:
            result["CreatedOn"] = self.created_on.isoformat()
        if self.deleted_at:
            result["DeletedAt"] = utils.from_none(self.deleted_at)

        return result


def check_list_from_dict(s: Any) -> CheckList:
    return CheckList.from_dict(s)


def check_list_to_dict(x: CheckList) -> Any:
    return utils.to_class(CheckList, x)


class Tags:
    default: dict()

    def __init__(self, tags: dict) -> None:
        self.tags = tags


class NoteTags(Tags):
    def __init__(self, default: dict) -> None:
        Tags.__init__(
            self, default)


class Note:
    id: UUID
    topic: str
    notes: str
    note_type: str
    note_src_type: str
    creator: UUID
    priority: str
    sequence: int
    note_tags: dict
    plan_instance_id: str
    plan_instance_control_id: UUID
    created_on: datetime
    due_date: datetime
    last_updated: datetime

    def __init__(self, id: UUID, topic: str, notes: str, note_type: str, note_src_type: str, creator: UUID, priority: str, sequence: int, note_tags: dict, plan_instance_id: str, plan_instance_control_id: UUID, created_on: datetime, due_date: datetime, last_updated: datetime) -> None:
        self.id = id
        self.topic = topic
        self.notes = notes
        self.note_type = note_type
        self.note_src_type = note_src_type
        self.creator = creator
        self.priority = priority
        self.sequence = sequence
        self.note_tags = note_tags
        self.plan_instance_id = plan_instance_id
        self.plan_instance_control_id = plan_instance_control_id
        self.created_on = created_on
        self.due_date = due_date
        self.last_updated = last_updated

    @staticmethod
    def from_dict(obj: Any) -> 'Note' or None:
        note = None
        if isinstance(obj, dict):
            id = topic = notes = note_type = note_src_type = creator = priority = sequence = note_tags = plan_instance_id = plan_instance_control_id = created_on = due_date = last_updated = None
            if dictutils.is_valid_key(obj, "id"):
                id = UUID(obj.get("id"))
            if dictutils.is_valid_key(obj, "Topic"):
                topic = utils.from_str(obj.get("Topic"))
            if dictutils.is_valid_key(obj, "Notes"):
                notes = utils.from_str(obj.get("Notes"))
            if dictutils.is_valid_key(obj, "NoteType"):
                note_type = utils.from_str(obj.get("NoteType"))
            if dictutils.is_valid_key(obj, "NoteSrcType"):
                note_src_type = utils.from_str(obj.get("NoteSrcType"))
            if dictutils.is_valid_key(obj, "Creator"):
                creator = UUID(obj.get("Creator"))
            if dictutils.is_valid_key(obj, "Priority"):
                priority = utils.from_str(obj.get("Priority"))
            if dictutils.is_valid_key(obj, "Sequence"):
                sequence = utils.from_int(obj.get("Sequence"))
            if dictutils.is_valid_key(obj, "NoteTags"):
                note_tags = obj.get("NoteTags")
            if dictutils.is_valid_key(obj, "PlanInstanceID"):
                plan_instance_id = utils.from_str(obj.get("PlanInstanceID"))
            if dictutils.is_valid_key(obj, "PlanInstanceControlID"):
                plan_instance_control_id = UUID(
                    obj.get("PlanInstanceControlID"))
            if dictutils.is_valid_key(obj, "CreatedOn"):
                created_on = utils.from_datetime(obj.get("CreatedOn"))
            if dictutils.is_valid_key(obj, "DueDate"):
                due_date = utils.from_datetime(obj.get("DueDate"))
            if dictutils.is_valid_key(obj, "LastUpdated"):
                last_updated = utils.from_datetime(obj.get("LastUpdated"))
            note = Note(id, topic, notes, note_type, note_src_type, creator, priority, sequence,
                        note_tags, plan_instance_id, plan_instance_control_id, created_on, due_date, last_updated)
        return note

    def to_dict(self) -> dict:
        result: dict = {}
        if self.id:
            result["id"] = str(self.id)
        if self.topic:
            result["Topic"] = utils.from_str(self.topic)
        if self.notes:
            result["Notes"] = utils.from_str(self.notes)
        if self.note_type:
            result["NoteType"] = utils.from_str(self.note_type)
        if self.note_src_type:
            result["NoteSrcType"] = utils.from_str(self.note_src_type)
        if self.creator:
            result["Creator"] = str(self.creator)
        if self.priority:
            result["Priority"] = utils.from_str(self.priority)
        if self.sequence:
            result["Sequence"] = utils.from_int(self.sequence)
        if self.note_tags:
            result["NoteTags"] = self.note_tags
        if self.plan_instance_id:
            result["PlanInstanceID"] = utils.from_str(self.plan_instance_id)
        if self.plan_instance_control_id:
            result["PlanInstanceControlID"] = str(
                self.plan_instance_control_id)
        if self.created_on:
            result["CreatedOn"] = self.created_on.isoformat()
        if self.due_date:
            result["DueDate"] = self.due_date.isoformat()
        if self.last_updated:
            result["LastUpdated"] = self.last_updated.isoformat()
        return result


class PlanInstanceControl:
    id: UUID
    parent_control_id: UUID
    name: str
    displayable: str
    alias: str
    priority: str
    stage: str
    status: str
    type: str
    reporting_level_control: bool
    evidences: List[Evidence]
    controls: List['PlanInstanceControl']
    notes: List[Note]
    control_id: UUID
    plan_instance_id: UUID
    initiated_by: UUID
    started: datetime
    ended: datetime
    cn_control_execution_start_time: datetime
    cn_control_execution_end_time: datetime
    cn_synthesizer_start_time: datetime
    cn_synthesizer_end_time: datetime
    execution_status: str
    leaf_control: bool
    tags: dict
    check_lists: List[CheckList]

    def __init__(self, id: UUID, parent_control_id: UUID, name: str, displayable: str, alias: str, priority: str, stage: str, status: str, type: str, reporting_level_control: bool, evidences: List[Evidence], notes: List[Note], control_id: UUID, plan_instance_id: UUID, initiated_by: UUID, started: datetime, ended: datetime, cn_control_execution_start_time: datetime, cn_control_execution_end_time: datetime, cn_synthesizer_start_time: datetime, cn_synthesizer_end_time: datetime, execution_status: str, leaf_control: bool, tags: dict, controls: List['PlanInstanceControl'], check_lists: List[CheckList]) -> None:
        self.id = id
        self.parent_control_id = parent_control_id
        self.name = name
        self.displayable = displayable
        self.alias = alias
        self.priority = priority
        self.stage = stage
        self.status = status
        self.type = type
        self.reporting_level_control = reporting_level_control
        self.evidences = evidences
        self.notes = notes
        self.control_id = control_id
        self.plan_instance_id = plan_instance_id
        self.initiated_by = initiated_by
        self.started = started
        self.ended = ended
        self.cn_control_execution_start_time = cn_control_execution_start_time
        self.cn_control_execution_end_time = cn_control_execution_end_time
        self.cn_synthesizer_start_time = cn_synthesizer_start_time
        self.cn_synthesizer_end_time = cn_synthesizer_end_time
        self.execution_status = execution_status
        self.leaf_control = leaf_control
        self.controls = controls
        self.tags = tags
        self.check_lists = check_lists

    @staticmethod
    def from_dict(obj: Any) -> 'PlanInstanceControl' or None:
        plan_instance_control = None
        if isinstance(obj, dict):
            id = parent_control_id = name = displayable = alias = priority = stage = status = type = reporting_level_control = evidences = notes = control_id = plan_instance_id = initiated_by = started = ended = cn_control_execution_start_time = cn_control_execution_end_time = cn_synthesizer_start_time = cn_synthesizer_end_time = execution_status = leaf_control = tags = controls = check_lists = None
            if dictutils.is_valid_key(obj, "id"):
                id = UUID(obj.get("id"))
            if dictutils.is_valid_key(obj, "parentControlId"):
                parent_control_id = UUID(obj.get("parentControlId"))
            if dictutils.is_valid_key(obj, "name"):
                name = utils.from_str(obj.get("name"))
            if dictutils.is_valid_key(obj, "displayable"):
                displayable = utils.from_str(obj.get("displayable"))
            if dictutils.is_valid_key(obj, "alias"):
                alias = utils.from_str(obj.get("alias"))
            if dictutils.is_valid_key(obj, "priority"):
                priority = utils.from_str(obj.get("priority"))
            if dictutils.is_valid_key(obj, "stage"):
                stage = utils.from_str(obj.get("stage"))
            if dictutils.is_valid_key(obj, "status"):
                status = utils.from_str(obj.get("status"))
            if dictutils.is_valid_key(obj, "type"):
                type = utils.from_str(obj.get("type"))
            if dictutils.is_valid_key(obj, "reportingLevelControl"):
                reporting_level_control = utils.from_bool(
                    obj.get("reportingLevelControl"))
            if dictutils.is_valid_array(obj, "evidences"):
                evidences = utils.from_list(
                    Evidence.from_dict, obj.get("evidences"))
            if dictutils.is_valid_array(obj, "notes"):
                notes = utils.from_list(Note.from_dict, obj.get("notes"))
            if dictutils.is_valid_key(obj, "controlId"):
                control_id = UUID(obj.get("controlId"))
            if dictutils.is_valid_key(obj, "planInstanceId"):
                plan_instance_id = UUID(obj.get("planInstanceId"))
            if dictutils.is_valid_key(obj, "initiatedBy"):
                initiated_by = UUID(obj.get("initiatedBy"))
            if dictutils.is_valid_key(obj, "started"):
                started = utils.from_datetime(obj.get("started"))
            if dictutils.is_valid_key(obj, "ended"):
                ended = utils.from_datetime(obj.get("ended"))
            if dictutils.is_valid_key(obj, "cnControlExecutionStartTime"):
                cn_control_execution_start_time = utils.from_datetime(
                    obj.get("cnControlExecutionStartTime"))
            if dictutils.is_valid_key(obj, "cnControlExecutionEndTime"):
                cn_control_execution_end_time = utils.from_datetime(
                    obj.get("cnControlExecutionEndTime"))
            if dictutils.is_valid_key(obj, "cnSynthesizerStartTime"):
                cn_synthesizer_start_time = utils.from_datetime(
                    obj.get("cnSynthesizerStartTime"))
            if dictutils.is_valid_key(obj, "cnSynthesizerEndTime"):
                cn_synthesizer_end_time = utils.from_datetime(
                    obj.get("cnSynthesizerEndTime"))
            if dictutils.is_valid_key(obj, "executionStatus"):
                execution_status = utils.from_str(obj.get("executionStatus"))
            if dictutils.is_valid_key(obj, "leafControl"):
                leaf_control = utils.from_bool(obj.get("leafControl"))
            if dictutils.is_valid_key(obj, "tags"):
                tags = obj.get("tags")
            if dictutils.is_valid_array(obj, "controls"):
                controls = utils.from_list(
                    PlanInstanceControl.from_dict, obj.get("controls"))
            if dictutils.is_valid_array(obj, "checklists"):
                check_lists = utils.from_list(
                    CheckList.from_dict, obj.get("checklists"))
            plan_instance_control = PlanInstanceControl(id, parent_control_id, name, displayable, alias, priority, stage, status, type, reporting_level_control, evidences, notes, control_id, plan_instance_id,
                                                        initiated_by, started, ended, cn_control_execution_start_time, cn_control_execution_end_time, cn_synthesizer_start_time, cn_synthesizer_end_time, execution_status, leaf_control, tags, controls, check_lists)
        return plan_instance_control

    def to_dict(self) -> dict:
        result: dict = {}
        if self.id:
            result["id"] = str(self.id)
        if self.parent_control_id:
            result["parentControlId"] = str(self.parent_control_id)
        if self.name:
            result["name"] = utils.from_str(self.name)
        if self.displayable:
            result["displayable"] = utils.from_str(self.displayable)
        if self.alias:
            result["alias"] = utils.from_str(self.alias)
        if self.priority:
            result["priority"] = utils.from_str(self.priority)
        if self.stage:
            result["stage"] = utils.from_str(self.stage)
        if self.status:
            result["status"] = utils.from_str(self.status)
        if self.type:
            result["type"] = utils.from_str(self.type)
        if self.reporting_level_control:
            result["reportingLevelControl"] = utils.from_bool(
                self.reporting_level_control)
        if self.evidences:
            result["evidences"] = utils.from_list(
                lambda x: utils.to_class(Evidence, x), self.evidences)
        if self.notes:
            result["notes"] = utils.from_list(
                lambda x: utils.to_class(Note, x), self.notes)
        if self.control_id:
            result["controlId"] = str(self.control_id)
        if self.plan_instance_id:
            result["planInstanceId"] = str(self.plan_instance_id)
        if self.initiated_by:
            result["initiatedBy"] = str(self.initiated_by)
        if self.started:
            result["started"] = self.started.isoformat()
        if self.ended:
            result["ended"] = self.ended.isoformat()
        if self.cn_control_execution_start_time:
            result["cnControlExecutionStartTime"] = self.cn_control_execution_start_time.isoformat()
        if self.cn_control_execution_end_time:
            result["cnControlExecutionEndTime"] = self.cn_control_execution_end_time.isoformat()
        if self.cn_synthesizer_start_time:
            result["cnSynthesizerStartTime"] = self.cn_synthesizer_start_time.isoformat()
        if self.cn_synthesizer_end_time:
            result["cnSynthesizerEndTime"] = self.cn_synthesizer_end_time.isoformat()
        if self.execution_status:
            result["executionStatus"] = utils.from_str(self.execution_status)
        if self.leaf_control:
            result["leafControl"] = utils.from_bool(self.leaf_control)
        if self.tags:
            result['tags'] = self.tags
        if self.controls:
            result["controls"] = utils.from_list(lambda x: utils.to_class(
                PlanInstanceControl, x), self.controls)
        if self.check_lists:
            result["checklists"] = utils.from_list(lambda x: utils.to_class(
                CheckList, x), self.check_lists)
        return result


def planinstancecontrol_from_dict(s: Any) -> PlanInstanceControl:
    return PlanInstanceControl.from_dict(s)


def planinstancecontrol_to_dict(x: PlanInstanceControl) -> Any:
    return utils.to_class(PlanInstanceControl, x)


class PlanInstance:
    id: UUID
    name: str
    domain_id: UUID
    org_id: UUID
    group_id: UUID
    description: str
    plan_id: UUID
    type: str
    config_id: UUID
    from_date: str
    to_date: str
    started: str
    ended: datetime
    cn_plan_execution_start_time: datetime
    cn_plan_execution_end_time: datetime
    status: str
    initiated_by: UUID
    controls: List[PlanInstanceControl]

    def __init__(self, id: UUID, name: str, domain_id: UUID, org_id: UUID, group_id: UUID, description: str, plan_id: UUID, type: str, config_id: UUID, from_date: str, to_date: str, started: str, ended: datetime, cn_plan_execution_start_time: datetime, cn_plan_execution_end_time: datetime, status: str, initiated_by: UUID, controls: List[PlanInstanceControl]) -> None:
        self.id = id
        self.name = name
        self.domain_id = domain_id
        self.org_id = org_id
        self.group_id = group_id
        self.description = description
        self.plan_id = plan_id
        self.type = type
        self.config_id = config_id
        self.from_date = from_date
        self.to_date = to_date
        self.started = started
        self.ended = ended
        self.cn_plan_execution_start_time = cn_plan_execution_start_time
        self.cn_plan_execution_end_time = cn_plan_execution_end_time
        self.status = status
        self.initiated_by = initiated_by
        self.controls = controls

    def get_plan_instance_controls(self, along_with_heirarchy=False, having_evidences=False, having_notes=False, having_attachments=False, having_checklists=False, automated=True) -> List[PlanInstanceControl] or None:
        controls = None
        if along_with_heirarchy:
            controls = utils.fetch_controls(self, having_evidences=having_evidences,
                                            having_notes=having_notes, having_attachments=having_attachments, having_checklists=having_checklists, automated=automated)
        else:
            controls = utils.fetch_controls_without_hierarchy(self, having_evidences=having_evidences, having_notes=having_notes,
                                                              having_attachments=having_attachments, having_checklists=having_checklists, automated=automated)
        return controls

    @staticmethod
    def from_dict(obj: Any) -> 'PlanInstance' or None:
        plan_intsnace = None
        if isinstance(obj, dict):
            id = name = domain_id = org_id = group_id = description = plan_id = type = config_id = from_date = to_date = started = ended = cn_plan_execution_start_time = cn_plan_execution_end_time = status = initiated_by = controls = None
            if dictutils.is_valid_key(obj, "id"):
                id = UUID(obj.get("id"))
            if dictutils.is_valid_key(obj, "name"):
                name = utils.from_str(obj.get("name"))
            if dictutils.is_valid_key(obj, "domainId"):
                domain_id = UUID(obj.get("domainId"))
            if dictutils.is_valid_key(obj, "orgId"):
                org_id = UUID(obj.get("orgId"))
            if dictutils.is_valid_key(obj, "groupId"):
                group_id = UUID(obj.get("groupId"))
            if dictutils.is_valid_key(obj, "description"):
                description = utils.from_str(obj.get("description"))
            if dictutils.is_valid_key(obj, "planId"):
                plan_id = UUID(obj.get("planId"))
            if dictutils.is_valid_key(obj, "type"):
                type = utils.from_str(obj.get("type"))
            if dictutils.is_valid_key(obj, "configId"):
                config_id = UUID(obj.get("configId"))
            if dictutils.is_valid_key(obj, "fromDate"):
                from_date = utils.from_str(obj.get("fromDate"))
            if dictutils.is_valid_key(obj, "toDate"):
                to_date = utils.from_str(obj.get("toDate"))
            if dictutils.is_valid_key(obj, "started"):
                started = utils.from_str(obj.get("started"))
            if dictutils.is_valid_key(obj, "ended"):
                ended = utils.from_datetime(obj.get("ended"))
            if dictutils.is_valid_key(obj, "cnPlanExecutionStartTime"):
                cn_plan_execution_start_time = utils.from_datetime(
                    obj.get("cnPlanExecutionStartTime"))
            if dictutils.is_valid_key(obj, "cnPlanExecutionEndTime"):
                cn_plan_execution_end_time = utils.from_datetime(
                    obj.get("cnPlanExecutionEndTime"))
            if dictutils.is_valid_key(obj, "status"):
                status = utils.from_str(obj.get("status"))
            if dictutils.is_valid_key(obj, "initiatedBy"):
                initiated_by = UUID(obj.get("initiatedBy"))
            if dictutils.is_valid_array(obj, "controls"):
                controls = utils.from_list(
                    PlanInstanceControl.from_dict, obj.get("controls"))
            plan_intsnace = PlanInstance(id, name, domain_id, org_id, group_id, description, plan_id, type, config_id, from_date,
                                         to_date, started, ended, cn_plan_execution_start_time, cn_plan_execution_end_time, status, initiated_by, controls)
        return plan_intsnace

    def to_dict(self) -> dict:
        result: dict = {}
        if self.id:
            result["id"] = str(self.id)
        if self.name:
            result["name"] = utils.from_str(self.name)
        if self.domain_id:
            result["domainId"] = str(self.domain_id)
        if self.org_id:
            result["orgId"] = str(self.org_id)
        if self.group_id:
            result["groupId"] = str(self.group_id)
        if self.description:
            result["description"] = utils.from_str(self.description)
        if self.plan_id:
            result["planId"] = str(self.plan_id)
        if self.type:
            result["type"] = utils.from_str(self.type)
        if self.config_id:
            result["configId"] = str(self.config_id)
        if self.from_date:
            result["fromDate"] = utils.from_str(self.from_date)
        if self.to_date:
            result["toDate"] = utils.from_str(self.to_date)
        if self.started:
            result["started"] = utils.from_str(self.started)
        if self.ended:
            result["ended"] = self.ended.isoformat()
        if self.cn_plan_execution_start_time:
            result["cnPlanExecutionStartTime"] = self.cn_plan_execution_start_time.isoformat()
        if self.cn_plan_execution_end_time:
            result["cnPlanExecutionEndTime"] = self.cn_plan_execution_end_time.isoformat()
        if self.status:
            result["status"] = utils.from_str(self.status)
        if self.initiated_by:
            result["initiatedBy"] = str(self.initiated_by)
        if self.controls:
            result["controls"] = utils.from_list(lambda x: utils.to_class(
                PlanInstanceControl, x), self.controls)
        return result


def planinstance_from_dict(s: Any) -> PlanInstance:
    return PlanInstance.from_dict(s)


def planinstance_to_dict(x: PlanInstance) -> Any:
    return utils.to_class(PlanInstance, x)


class Plan:
    id: UUID
    name: str
    domain_id: UUID
    org_id: UUID
    group_id: UUID
    type: str
    status: str
    plan_instances: List[PlanInstance]

    def __init__(self, id: UUID, name: str, domain_id: UUID, org_id: UUID, group_id: UUID, type: str, status: str, plan_instances: List[PlanInstance]) -> None:
        self.id = id
        self.name = name
        self.domain_id = domain_id
        self.org_id = org_id
        self.group_id = group_id
        self.type = type
        self.status = status

    @staticmethod
    def from_dict(obj: Any) -> 'Plan' or None:
        plan = None
        if isinstance(obj, dict):
            id = name = domain_id = org_id = group_id = type = status = plan_instances = None
            if dictutils.is_valid_key(obj, "id"):
                id = UUID(obj.get("id"))
            if dictutils.is_valid_key(obj, "name"):
                name = utils.from_str(obj.get("name"))
            if dictutils.is_valid_key(obj, "domainId"):
                domain_id = UUID(obj.get("domainId"))
            if dictutils.is_valid_key(obj, "orgId"):
                org_id = UUID(obj.get("orgId"))
            if dictutils.is_valid_key(obj, "groupId"):
                group_id = UUID(obj.get("groupId"))
            if dictutils.is_valid_key(obj, "type"):
                type = utils.from_str(obj.get("type"))
            if dictutils.is_valid_key(obj, "status"):
                status = utils.from_str(obj.get("status"))
            if dictutils.is_valid_array(obj, "planInstances"):
                plan_instances = utils.from_list(
                    PlanInstance.from_dict, obj.get("planInstances"))
            plan = Plan(id, name, domain_id, org_id, group_id,
                        type, status, plan_instances)
        return plan

    def to_dict(self) -> dict:
        result: dict = {}
        if self.id:
            result["id"] = str(self.id)
        if self.name:
            result["name"] = utils.from_str(self.name)
        if self.domain_id:
            result["domain_id"] = str(self.domain_id)
        if self.org_id:
            result["orgId"] = str(self.org_id)
        if self.group_id:
            result["groupId"] = str(self.group_id)
        if self.type:
            result["type"] = utils.from_str(self.type)
        if self.status:
            result["status"] = utils.from_str(self.status)
        return result


def plan_from_dict(s: Any) -> Plan:
    return Plan.from_dict(s)


def plan_to_dict(x: Plan) -> Any:
    return utils.to_class(Plan, x)
