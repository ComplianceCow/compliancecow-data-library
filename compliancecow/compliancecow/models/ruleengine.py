from typing import Optional, List, Any, TypeVar, Callable, Type, cast
from uuid import UUID
from enum import Enum
from datetime import datetime
import dateutil.parser


T = TypeVar("T")
EnumT = TypeVar("EnumT", bound=Enum)


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]


def from_none(x: Any) -> Any:
    assert x is None
    return x


def from_union(fs, x):
    for f in fs:
        try:
            return f(x)
        except:
            pass
    assert False


def from_str(x: Any) -> str:
    assert isinstance(x, str)
    return x


def to_class(c: Type[T], x: Any) -> dict:
    assert isinstance(x, c)
    return cast(Any, x).to_dict()


def is_type(t: Type[T], x: Any) -> T:
    assert isinstance(x, t)
    return x


def to_enum(c: Type[EnumT], x: Any) -> EnumT:
    assert isinstance(x, c)
    return x.value


def from_int(x: Any) -> int:
    assert isinstance(x, int) and not isinstance(x, bool)
    return x


def from_bool(x: Any) -> bool:
    assert isinstance(x, bool)
    return x


def from_datetime(x: Any) -> datetime:
    return dateutil.parser.parse(x)


class Body:
    plan_instance_control_ids: Optional[List[UUID]]
    plan_instance_id: Optional[UUID]

    def __init__(self, plan_instance_control_ids: Optional[List[UUID]], plan_instance_id: Optional[UUID]) -> None:
        self.plan_instance_control_ids = plan_instance_control_ids
        self.plan_instance_id = plan_instance_id

    @staticmethod
    def from_dict(obj: Any) -> 'Body':
        assert isinstance(obj, dict)
        plan_instance_control_ids = from_union([lambda x: from_list(
            lambda x: UUID(x), x), from_none], obj.get("planInstanceControlIds"))
        plan_instance_id = from_union(
            [lambda x: UUID(x), from_none], obj.get("planInstanceId"))
        return Body(plan_instance_control_ids, plan_instance_id)

    def to_dict(self) -> dict:
        result: dict = {}
        result["planInstanceControlIds"] = from_union([lambda x: from_list(
            lambda x: str(x), x), from_none], self.plan_instance_control_ids)
        result["planInstanceId"] = from_union(
            [lambda x: str(x), from_none], self.plan_instance_id)
        return result


class Headers:
    authorization: Optional[UUID]
    content_type: Optional[str]

    def __init__(self, authorization: Optional[UUID], content_type: Optional[str]) -> None:
        self.authorization = authorization
        self.content_type = content_type

    @staticmethod
    def from_dict(obj: Any) -> 'Headers':
        assert isinstance(obj, dict)
        authorization = from_union(
            [lambda x: UUID(x), from_none], obj.get("Authorization"))
        content_type = from_union(
            [from_str, from_none], obj.get("Content-Type"))
        return Headers(authorization, content_type)

    def to_dict(self) -> dict:
        result: dict = {}
        result["Authorization"] = from_union(
            [lambda x: str(x), from_none], self.authorization)
        result["Content-Type"] = from_union([from_str,
                                             from_none], self.content_type)
        return result


class APICallback:
    headers: Optional[Headers]
    url: Optional[str]
    method: Optional[str]
    body: Optional[Body]

    def __init__(self, headers: Optional[Headers], url: Optional[str], method: Optional[str], body: Optional[Body]) -> None:
        self.headers = headers
        self.url = url
        self.method = method
        self.body = body

    @staticmethod
    def from_dict(obj: Any) -> 'APICallback':
        assert isinstance(obj, dict)
        headers = from_union(
            [Headers.from_dict, from_none], obj.get("headers"))
        url = from_union([from_str, from_none], obj.get("url"))
        method = from_union([from_str, from_none], obj.get("method"))
        body = from_union([Body.from_dict, from_none], obj.get("body"))
        return APICallback(headers, url, method, body)

    def to_dict(self) -> dict:
        result: dict = {}
        result["headers"] = from_union(
            [lambda x: to_class(Headers, x), from_none], self.headers)
        result["url"] = from_union([from_str, from_none], self.url)
        result["method"] = from_union([from_str, from_none], self.method)
        result["body"] = from_union(
            [lambda x: to_class(Body, x), from_none], self.body)
        return result


class ComplianceStatus(Enum):
    COMPLIANT = "Compliant"
    NON_COMPLIANT = "Non Compliant"


class TionProgress(Enum):
    THE_100 = "100%"


class ControlStatus:
    validation_status: Optional[int]
    validation_progress: Optional[TionProgress]
    execution_progress: Optional[TionProgress]

    def __init__(self, validation_status: Optional[int], validation_progress: Optional[TionProgress], execution_progress: Optional[TionProgress]) -> None:
        self.validation_status = validation_status
        self.validation_progress = validation_progress
        self.execution_progress = execution_progress

    @staticmethod
    def from_dict(obj: Any) -> 'ControlStatus':
        assert isinstance(obj, dict)
        validation_status = from_union(
            [from_none, lambda x: int(from_str(x))], obj.get("ValidationStatus"))
        validation_progress = from_union(
            [TionProgress, from_none], obj.get("ValidationProgress"))
        execution_progress = from_union(
            [TionProgress, from_none], obj.get("ExecutionProgress"))
        return ControlStatus(validation_status, validation_progress, execution_progress)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ValidationStatus"] = from_union([lambda x: from_none((lambda x: is_type(type(None), x))(
            x)), lambda x: from_str((lambda x: str((lambda x: is_type(int, x))(x)))(x))], self.validation_status)
        result["ValidationProgress"] = from_union(
            [lambda x: to_enum(TionProgress, x), from_none], self.validation_progress)
        result["ExecutionProgress"] = from_union(
            [lambda x: to_enum(TionProgress, x), from_none], self.execution_progress)
        return result


class ControlType(Enum):
    SYSTEM = "system"


class Source:
    variable_name: Optional[str]

    def __init__(self, variable_name: Optional[str]) -> None:
        self.variable_name = variable_name

    @staticmethod
    def from_dict(obj: Any) -> 'Source':
        assert isinstance(obj, dict)
        variable_name = from_union(
            [from_str, from_none], obj.get("variableName"))
        return Source(variable_name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["variableName"] = from_union(
            [from_str, from_none], self.variable_name)
        return result


class Target:
    control_id: Optional[UUID]
    variable_name: Optional[str]

    def __init__(self, control_id: Optional[UUID], variable_name: Optional[str]) -> None:
        self.control_id = control_id
        self.variable_name = variable_name

    @staticmethod
    def from_dict(obj: Any) -> 'Target':
        assert isinstance(obj, dict)
        control_id = from_union(
            [lambda x: UUID(x), from_none], obj.get("controlId"))
        variable_name = from_union(
            [from_str, from_none], obj.get("variableName"))
        return Target(control_id, variable_name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["controlId"] = from_union(
            [lambda x: str(x), from_none], self.control_id)
        result["variableName"] = from_union(
            [from_str, from_none], self.variable_name)
        return result


class DependedControlInput:
    source: Optional[Source]
    target: Optional[Target]

    def __init__(self, source: Optional[Source], target: Optional[Target]) -> None:
        self.source = source
        self.target = target

    @staticmethod
    def from_dict(obj: Any) -> 'DependedControlInput':
        assert isinstance(obj, dict)
        source = from_union([Source.from_dict, from_none], obj.get("source"))
        target = from_union([Target.from_dict, from_none], obj.get("target"))
        return DependedControlInput(source, target)

    def to_dict(self) -> dict:
        result: dict = {}
        result["source"] = from_union(
            [lambda x: to_class(Source, x), from_none], self.source)
        result["target"] = from_union(
            [lambda x: to_class(Target, x), from_none], self.target)
        return result


class Aliasref(Enum):
    EMPTY = "*"
    T1 = "t1"


class Fieldtype(Enum):
    INPUT = "Input"
    OUTPUT = "Output"


class Ref:
    fieldtype: Optional[Fieldtype]
    aliasref: Optional[Aliasref]
    varname: Optional[str]

    def __init__(self, fieldtype: Optional[Fieldtype], aliasref: Optional[Aliasref], varname: Optional[str]) -> None:
        self.fieldtype = fieldtype
        self.aliasref = aliasref
        self.varname = varname

    @staticmethod
    def from_dict(obj: Any) -> 'Ref':
        assert isinstance(obj, dict)
        fieldtype = from_union([Fieldtype, from_none], obj.get("fieldtype"))
        aliasref = from_union([Aliasref, from_none], obj.get("aliasref"))
        varname = from_union([from_str, from_none], obj.get("varname"))
        return Ref(fieldtype, aliasref, varname)

    def to_dict(self) -> dict:
        result: dict = {}
        result["fieldtype"] = from_union(
            [lambda x: to_enum(Fieldtype, x), from_none], self.fieldtype)
        result["aliasref"] = from_union(
            [lambda x: to_enum(Aliasref, x), from_none], self.aliasref)
        result["varname"] = from_union([from_str, from_none], self.varname)
        return result


class Refmap:
    targetref: Optional[Ref]
    sourceref: Optional[Ref]

    def __init__(self, targetref: Optional[Ref], sourceref: Optional[Ref]) -> None:
        self.targetref = targetref
        self.sourceref = sourceref

    @staticmethod
    def from_dict(obj: Any) -> 'Refmap':
        assert isinstance(obj, dict)
        targetref = from_union(
            [Ref.from_dict, from_none], obj.get("targetref"))
        sourceref = from_union(
            [Ref.from_dict, from_none], obj.get("sourceref"))
        return Refmap(targetref, sourceref)

    def to_dict(self) -> dict:
        result: dict = {}
        result["targetref"] = from_union(
            [lambda x: to_class(Ref, x), from_none], self.targetref)
        result["sourceref"] = from_union(
            [lambda x: to_class(Ref, x), from_none], self.sourceref)
        return result


class App(Enum):
    AWS = "aws"


class Environment(Enum):
    LOGICAL = "logical"


class ObjectType(Enum):
    APP = "app"


class RuleTags:
    app: Optional[List[App]]
    environment: Optional[List[Environment]]
    execlevel: Optional[List[ObjectType]]

    def __init__(self, app: Optional[List[App]], environment: Optional[List[Environment]], execlevel: Optional[List[ObjectType]]) -> None:
        self.app = app
        self.environment = environment
        self.execlevel = execlevel

    @staticmethod
    def from_dict(obj: Any) -> 'RuleTags':
        assert isinstance(obj, dict)
        app = from_union([lambda x: from_list(
            App, x), from_none], obj.get("app"))
        environment = from_union([lambda x: from_list(
            Environment, x), from_none], obj.get("environment"))
        execlevel = from_union([lambda x: from_list(
            ObjectType, x), from_none], obj.get("execlevel"))
        return RuleTags(app, environment, execlevel)

    def to_dict(self) -> dict:
        result: dict = {}
        result["app"] = from_union([lambda x: from_list(
            lambda x: to_enum(App, x), x), from_none], self.app)
        result["environment"] = from_union([lambda x: from_list(
            lambda x: to_enum(Environment, x), x), from_none], self.environment)
        result["execlevel"] = from_union([lambda x: from_list(
            lambda x: to_enum(ObjectType, x), x), from_none], self.execlevel)
        return result


class BucketName(Enum):
    DEMO = "demo"


class Encoding(Enum):
    CSV_JSON = "csv,json"
    JSON_CSV = "json,csv"


class Inputs:
    bucket_name: Optional[BucketName]
    encoding: Optional[Encoding]
    recommended_password_hash: Optional[str]
    recommended_password_policy: Optional[str]
    aws_credential_report_file_hash: Optional[str]
    aws_credential_report_file_name: Optional[str]
    aws_instance_status_report_file_hash: Optional[str]
    aws_instance_status_report_file_name: Optional[str]
    aws_key_rotation_days: Optional[int]
    aws_acc_auth_details_report: Optional[str]
    aws_acc_auth_details_report_hash: Optional[str]
    awsmfa_recommendations: Optional[str]
    awsmfa_recommendations_hash: Optional[str]
    group_names: Optional[Aliasref]
    group_names_status: Optional[str]
    role_names: Optional[str]
    role_names_status: Optional[str]
    user_names: Optional[str]
    user_names_status: Optional[str]
    aws_unused_credential_days: Optional[int]

    def __init__(self, bucket_name: Optional[BucketName], encoding: Optional[Encoding], recommended_password_hash: Optional[str], recommended_password_policy: Optional[str], aws_credential_report_file_hash: Optional[str], aws_credential_report_file_name: Optional[str], aws_instance_status_report_file_hash: Optional[str], aws_instance_status_report_file_name: Optional[str], aws_key_rotation_days: Optional[int], aws_acc_auth_details_report: Optional[str], aws_acc_auth_details_report_hash: Optional[str], awsmfa_recommendations: Optional[str], awsmfa_recommendations_hash: Optional[str], group_names: Optional[Aliasref], group_names_status: Optional[str], role_names: Optional[str], role_names_status: Optional[str], user_names: Optional[str], user_names_status: Optional[str], aws_unused_credential_days: Optional[int]) -> None:
        self.bucket_name = bucket_name
        self.encoding = encoding
        self.recommended_password_hash = recommended_password_hash
        self.recommended_password_policy = recommended_password_policy
        self.aws_credential_report_file_hash = aws_credential_report_file_hash
        self.aws_credential_report_file_name = aws_credential_report_file_name
        self.aws_instance_status_report_file_hash = aws_instance_status_report_file_hash
        self.aws_instance_status_report_file_name = aws_instance_status_report_file_name
        self.aws_key_rotation_days = aws_key_rotation_days
        self.aws_acc_auth_details_report = aws_acc_auth_details_report
        self.aws_acc_auth_details_report_hash = aws_acc_auth_details_report_hash
        self.awsmfa_recommendations = awsmfa_recommendations
        self.awsmfa_recommendations_hash = awsmfa_recommendations_hash
        self.group_names = group_names
        self.group_names_status = group_names_status
        self.role_names = role_names
        self.role_names_status = role_names_status
        self.user_names = user_names
        self.user_names_status = user_names_status
        self.aws_unused_credential_days = aws_unused_credential_days

    @staticmethod
    def from_dict(obj: Any) -> 'Inputs':
        assert isinstance(obj, dict)
        bucket_name = from_union(
            [BucketName, from_none], obj.get("BucketName"))
        encoding = from_union([Encoding, from_none], obj.get("Encoding"))
        recommended_password_hash = from_union(
            [from_str, from_none], obj.get("RecommendedPasswordHash"))
        recommended_password_policy = from_union(
            [from_str, from_none], obj.get("RecommendedPasswordPolicy"))
        aws_credential_report_file_hash = from_union(
            [from_str, from_none], obj.get("AWSCredentialReportFileHash"))
        aws_credential_report_file_name = from_union(
            [from_str, from_none], obj.get("AWSCredentialReportFileName"))
        aws_instance_status_report_file_hash = from_union(
            [from_str, from_none], obj.get("AWSInstanceStatusReportFileHash"))
        aws_instance_status_report_file_name = from_union(
            [from_str, from_none], obj.get("AWSInstanceStatusReportFileName"))
        aws_key_rotation_days = from_union(
            [from_int, from_none], obj.get("AWSKeyRotationDays"))
        aws_acc_auth_details_report = from_union(
            [from_str, from_none], obj.get("AWSAccAuthDetailsReport"))
        aws_acc_auth_details_report_hash = from_union(
            [from_str, from_none], obj.get("AWSAccAuthDetailsReportHash"))
        awsmfa_recommendations = from_union(
            [from_str, from_none], obj.get("AWSMFARecommendations"))
        awsmfa_recommendations_hash = from_union(
            [from_str, from_none], obj.get("AWSMFARecommendationsHash"))
        group_names = from_union([Aliasref, from_none], obj.get("GroupNames"))
        group_names_status = from_union(
            [from_str, from_none], obj.get("GroupNamesStatus"))
        role_names = from_union([from_str, from_none], obj.get("RoleNames"))
        role_names_status = from_union(
            [from_str, from_none], obj.get("RoleNamesStatus"))
        user_names = from_union([from_str, from_none], obj.get("UserNames"))
        user_names_status = from_union(
            [from_str, from_none], obj.get("UserNamesStatus"))
        aws_unused_credential_days = from_union(
            [from_int, from_none], obj.get("AWSUnusedCredentialDays"))
        return Inputs(bucket_name, encoding, recommended_password_hash, recommended_password_policy, aws_credential_report_file_hash, aws_credential_report_file_name, aws_instance_status_report_file_hash, aws_instance_status_report_file_name, aws_key_rotation_days, aws_acc_auth_details_report, aws_acc_auth_details_report_hash, awsmfa_recommendations, awsmfa_recommendations_hash, group_names, group_names_status, role_names, role_names_status, user_names, user_names_status, aws_unused_credential_days)

    def to_dict(self) -> dict:
        result: dict = {}
        result["BucketName"] = from_union(
            [lambda x: to_enum(BucketName, x), from_none], self.bucket_name)
        result["Encoding"] = from_union(
            [lambda x: to_enum(Encoding, x), from_none], self.encoding)
        result["RecommendedPasswordHash"] = from_union(
            [from_str, from_none], self.recommended_password_hash)
        result["RecommendedPasswordPolicy"] = from_union(
            [from_str, from_none], self.recommended_password_policy)
        result["AWSCredentialReportFileHash"] = from_union(
            [from_str, from_none], self.aws_credential_report_file_hash)
        result["AWSCredentialReportFileName"] = from_union(
            [from_str, from_none], self.aws_credential_report_file_name)
        result["AWSInstanceStatusReportFileHash"] = from_union(
            [from_str, from_none], self.aws_instance_status_report_file_hash)
        result["AWSInstanceStatusReportFileName"] = from_union(
            [from_str, from_none], self.aws_instance_status_report_file_name)
        result["AWSKeyRotationDays"] = from_union(
            [from_int, from_none], self.aws_key_rotation_days)
        result["AWSAccAuthDetailsReport"] = from_union(
            [from_str, from_none], self.aws_acc_auth_details_report)
        result["AWSAccAuthDetailsReportHash"] = from_union(
            [from_str, from_none], self.aws_acc_auth_details_report_hash)
        result["AWSMFARecommendations"] = from_union(
            [from_str, from_none], self.awsmfa_recommendations)
        result["AWSMFARecommendationsHash"] = from_union(
            [from_str, from_none], self.awsmfa_recommendations_hash)
        result["GroupNames"] = from_union(
            [lambda x: to_enum(Aliasref, x), from_none], self.group_names)
        result["GroupNamesStatus"] = from_union(
            [from_str, from_none], self.group_names_status)
        result["RoleNames"] = from_union(
            [from_str, from_none], self.role_names)
        result["RoleNamesStatus"] = from_union(
            [from_str, from_none], self.role_names_status)
        result["UserNames"] = from_union(
            [from_str, from_none], self.user_names)
        result["UserNamesStatus"] = from_union(
            [from_str, from_none], self.user_names_status)
        result["AWSUnusedCredentialDays"] = from_union(
            [from_int, from_none], self.aws_unused_credential_days)
        return result


class InputsElement:
    name: Optional[str]
    display: Optional[str]
    type: Optional[str]
    showfieldinui: Optional[bool]

    def __init__(self, name: Optional[str], display: Optional[str], type: Optional[str], showfieldinui: Optional[bool]) -> None:
        self.name = name
        self.display = display
        self.type = type
        self.showfieldinui = showfieldinui

    @staticmethod
    def from_dict(obj: Any) -> 'InputsElement':
        assert isinstance(obj, dict)
        name = from_union([from_str, from_none], obj.get("name"))
        display = from_union([from_str, from_none], obj.get("display"))
        type = from_union([from_str, from_none], obj.get("type"))
        showfieldinui = from_union(
            [from_bool, from_none], obj.get("showfieldinui"))
        return InputsElement(name, display, type, showfieldinui)

    def to_dict(self) -> dict:
        result: dict = {}
        result["name"] = from_union([from_str, from_none], self.name)
        result["display"] = from_union([from_str, from_none], self.display)
        result["type"] = from_union([from_str, from_none], self.type)
        result["showfieldinui"] = from_union(
            [from_bool, from_none], self.showfieldinui)
        return result


class RuleRuleiovalues:
    inputs: Optional[Inputs]
    ruleiovalues_inputs: Optional[List[InputsElement]]

    def __init__(self, inputs: Optional[Inputs], ruleiovalues_inputs: Optional[List[InputsElement]]) -> None:
        self.inputs = inputs
        self.ruleiovalues_inputs = ruleiovalues_inputs

    @staticmethod
    def from_dict(obj: Any) -> 'RuleRuleiovalues':
        assert isinstance(obj, dict)
        inputs = from_union([Inputs.from_dict, from_none], obj.get("inputs"))
        ruleiovalues_inputs = from_union([lambda x: from_list(
            InputsElement.from_dict, x), from_none], obj.get("inputs_"))
        return RuleRuleiovalues(inputs, ruleiovalues_inputs)

    def to_dict(self) -> dict:
        result: dict = {}
        result["inputs"] = from_union(
            [lambda x: to_class(Inputs, x), from_none], self.inputs)
        result["inputs_"] = from_union([lambda x: from_list(lambda x: to_class(
            InputsElement, x), x), from_none], self.ruleiovalues_inputs)
        return result


class Ruletype(Enum):
    SEQUENTIAL = "sequential"


class TasksinfoType(Enum):
    TASK = "task"


class Tasksinfo:
    aliasref: Optional[Aliasref]
    description: Optional[str]
    purpose: Optional[str]
    taskguid: Optional[UUID]
    type: Optional[TasksinfoType]

    def __init__(self, aliasref: Optional[Aliasref], description: Optional[str], purpose: Optional[str], taskguid: Optional[UUID], type: Optional[TasksinfoType]) -> None:
        self.aliasref = aliasref
        self.description = description
        self.purpose = purpose
        self.taskguid = taskguid
        self.type = type

    @staticmethod
    def from_dict(obj: Any) -> 'Tasksinfo':
        assert isinstance(obj, dict)
        aliasref = from_union([Aliasref, from_none], obj.get("aliasref"))
        description = from_union([from_str, from_none], obj.get("description"))
        purpose = from_union([from_str, from_none], obj.get("purpose"))
        taskguid = from_union(
            [lambda x: UUID(x), from_none], obj.get("taskguid"))
        type = from_union([TasksinfoType, from_none], obj.get("type"))
        return Tasksinfo(aliasref, description, purpose, taskguid, type)

    def to_dict(self) -> dict:
        result: dict = {}
        result["aliasref"] = from_union(
            [lambda x: to_enum(Aliasref, x), from_none], self.aliasref)
        result["description"] = from_union(
            [from_str, from_none], self.description)
        result["purpose"] = from_union([from_str, from_none], self.purpose)
        result["taskguid"] = from_union(
            [lambda x: str(x), from_none], self.taskguid)
        result["type"] = from_union(
            [lambda x: to_enum(TasksinfoType, x), from_none], self.type)
        return result


class Rule:
    rulename: Optional[str]
    purpose: Optional[str]
    description: Optional[str]
    aliasref: Optional[Aliasref]
    ruletype: Optional[Ruletype]
    from_date: Optional[datetime]
    to_date: Optional[datetime]
    tasksinfo: Optional[List[Tasksinfo]]
    ruleiovalues: Optional[RuleRuleiovalues]
    refmaps: Optional[List[Refmap]]
    rule_tags: Optional[RuleTags]

    def __init__(self, rulename: Optional[str], purpose: Optional[str], description: Optional[str], aliasref: Optional[Aliasref], ruletype: Optional[Ruletype], from_date: Optional[datetime], to_date: Optional[datetime], tasksinfo: Optional[List[Tasksinfo]], ruleiovalues: Optional[RuleRuleiovalues], refmaps: Optional[List[Refmap]], rule_tags: Optional[RuleTags]) -> None:
        self.rulename = rulename
        self.purpose = purpose
        self.description = description
        self.aliasref = aliasref
        self.ruletype = ruletype
        self.from_date = from_date
        self.to_date = to_date
        self.tasksinfo = tasksinfo
        self.ruleiovalues = ruleiovalues
        self.refmaps = refmaps
        self.rule_tags = rule_tags

    @staticmethod
    def from_dict(obj: Any) -> 'Rule':
        assert isinstance(obj, dict)
        rulename = from_union([from_str, from_none], obj.get("rulename"))
        purpose = from_union([from_str, from_none], obj.get("purpose"))
        description = from_union([from_str, from_none], obj.get("description"))
        aliasref = from_union([Aliasref, from_none], obj.get("aliasref"))
        ruletype = from_union([Ruletype, from_none], obj.get("ruletype"))
        from_date = from_union([from_datetime, from_none], obj.get("fromDate"))
        to_date = from_union([from_datetime, from_none], obj.get("toDate"))
        tasksinfo = from_union([lambda x: from_list(
            Tasksinfo.from_dict, x), from_none], obj.get("tasksinfo"))
        ruleiovalues = from_union(
            [RuleRuleiovalues.from_dict, from_none], obj.get("ruleiovalues"))
        refmaps = from_union([lambda x: from_list(
            Refmap.from_dict, x), from_none], obj.get("refmaps"))
        rule_tags = from_union(
            [RuleTags.from_dict, from_none], obj.get("ruleTags"))
        return Rule(rulename, purpose, description, aliasref, ruletype, from_date, to_date, tasksinfo, ruleiovalues, refmaps, rule_tags)

    def to_dict(self) -> dict:
        result: dict = {}
        result["rulename"] = from_union([from_str, from_none], self.rulename)
        result["purpose"] = from_union([from_str, from_none], self.purpose)
        result["description"] = from_union(
            [from_str, from_none], self.description)
        result["aliasref"] = from_union(
            [lambda x: to_enum(Aliasref, x), from_none], self.aliasref)
        result["ruletype"] = from_union(
            [lambda x: to_enum(Ruletype, x), from_none], self.ruletype)
        result["fromDate"] = from_union(
            [lambda x: x.isoformat(), from_none], self.from_date)
        result["toDate"] = from_union(
            [lambda x: x.isoformat(), from_none], self.to_date)
        result["tasksinfo"] = from_union([lambda x: from_list(
            lambda x: to_class(Tasksinfo, x), x), from_none], self.tasksinfo)
        result["ruleiovalues"] = from_union(
            [lambda x: to_class(RuleRuleiovalues, x), from_none], self.ruleiovalues)
        result["refmaps"] = from_union([lambda x: from_list(
            lambda x: to_class(Refmap, x), x), from_none], self.refmaps)
        result["ruleTags"] = from_union(
            [lambda x: to_class(RuleTags, x), from_none], self.rule_tags)
        return result


class Roles(Enum):
    ADMIN = "admin"


class UserName(Enum):
    NEETHI_R_CONTINUBE_COM = "neethi.r@continube.com"


class User:
    user_name: Optional[UserName]
    roles: Optional[Roles]
    domain_id: Optional[UUID]
    org_id: Optional[UUID]
    group_id: Optional[UUID]
    id: Optional[UUID]

    def __init__(self, user_name: Optional[UserName], roles: Optional[Roles], domain_id: Optional[UUID], org_id: Optional[UUID], group_id: Optional[UUID], id: Optional[UUID]) -> None:
        self.user_name = user_name
        self.roles = roles
        self.domain_id = domain_id
        self.org_id = org_id
        self.group_id = group_id
        self.id = id

    @staticmethod
    def from_dict(obj: Any) -> 'User':
        assert isinstance(obj, dict)
        user_name = from_union([UserName, from_none], obj.get("UserName"))
        roles = from_union([Roles, from_none], obj.get("Roles"))
        domain_id = from_union(
            [lambda x: UUID(x), from_none], obj.get("DomainID"))
        org_id = from_union([lambda x: UUID(x), from_none], obj.get("OrgID"))
        group_id = from_union(
            [lambda x: UUID(x), from_none], obj.get("GroupID"))
        id = from_union([lambda x: UUID(x), from_none], obj.get("ID"))
        return User(user_name, roles, domain_id, org_id, group_id, id)

    def to_dict(self) -> dict:
        result: dict = {}
        result["UserName"] = from_union(
            [lambda x: to_enum(UserName, x), from_none], self.user_name)
        result["Roles"] = from_union(
            [lambda x: to_enum(Roles, x), from_none], self.roles)
        result["DomainID"] = from_union(
            [lambda x: str(x), from_none], self.domain_id)
        result["OrgID"] = from_union(
            [lambda x: str(x), from_none], self.org_id)
        result["GroupID"] = from_union(
            [lambda x: str(x), from_none], self.group_id)
        result["ID"] = from_union([lambda x: str(x), from_none], self.id)
        return result


class RuleSet:
    rules: Optional[List[Rule]]
    app_group_guid: Optional[UUID]
    plan_execution_guid: Optional[UUID]
    control_id: Optional[UUID]
    from_date: Optional[datetime]
    to_date: Optional[datetime]
    user: Optional[User]

    def __init__(self, rules: Optional[List[Rule]], app_group_guid: Optional[UUID], plan_execution_guid: Optional[UUID], control_id: Optional[UUID], from_date: Optional[datetime], to_date: Optional[datetime], user: Optional[User]) -> None:
        self.rules = rules
        self.app_group_guid = app_group_guid
        self.plan_execution_guid = plan_execution_guid
        self.control_id = control_id
        self.from_date = from_date
        self.to_date = to_date
        self.user = user

    @staticmethod
    def from_dict(obj: Any) -> 'RuleSet':
        assert isinstance(obj, dict)
        rules = from_union([lambda x: from_list(
            Rule.from_dict, x), from_none], obj.get("rules"))
        app_group_guid = from_union(
            [lambda x: UUID(x), from_none], obj.get("appGroupGUID"))
        plan_execution_guid = from_union(
            [lambda x: UUID(x), from_none], obj.get("planExecutionGUID"))
        control_id = from_union(
            [lambda x: UUID(x), from_none], obj.get("controlID"))
        from_date = from_union([from_datetime, from_none], obj.get("fromDate"))
        to_date = from_union([from_datetime, from_none], obj.get("toDate"))
        user = from_union([User.from_dict, from_none], obj.get("user"))
        return RuleSet(rules, app_group_guid, plan_execution_guid, control_id, from_date, to_date, user)

    def to_dict(self) -> dict:
        result: dict = {}
        result["rules"] = from_union([lambda x: from_list(
            lambda x: to_class(Rule, x), x), from_none], self.rules)
        result["appGroupGUID"] = from_union(
            [lambda x: str(x), from_none], self.app_group_guid)
        result["planExecutionGUID"] = from_union(
            [lambda x: str(x), from_none], self.plan_execution_guid)
        result["controlID"] = from_union(
            [lambda x: str(x), from_none], self.control_id)
        result["fromDate"] = from_union(
            [lambda x: x.isoformat(), from_none], self.from_date)
        result["toDate"] = from_union(
            [lambda x: x.isoformat(), from_none], self.to_date)
        result["user"] = from_union(
            [lambda x: to_class(User, x), from_none], self.user)
        return result


class InstanceName(Enum):
    AWS_CONSOLIDATED = "AWSConsolidated"


class PurpleOutputType(Enum):
    RULE = "Rule"


class FluffyOutputType(Enum):
    TASK = "Task"


class ComplianceStatusEnum(Enum):
    FAIL = "Fail"
    PASS = "Pass"


class Outputs:
    aws_password_policy_report_csv: Optional[str]
    aws_password_policy_report_json: Optional[str]
    compliance_pct: Optional[int]
    compliance_status: Optional[ComplianceStatusEnum]
    errors: None
    aws_full_admin_policy_report_csv: Optional[str]
    aws_full_admin_policy_report_json: Optional[str]
    aws_credential_report_csv: Optional[str]
    aws_credential_report_csv_hash: Optional[str]
    aws_credential_report_json: Optional[str]
    aws_credential_report_json_hash: Optional[str]
    aws_user_access_key_report_csv: Optional[str]
    aws_user_access_key_report_json: Optional[str]
    aws_acc_auth_details_hash: Optional[str]
    aws_acc_auth_details_report: Optional[str]
    aws_user_policy_report_csv: Optional[str]
    aws_user_policy_report_json: Optional[str]
    aws_latest_ami_report_csv: Optional[str]
    aws_latest_ami_report_json: Optional[str]
    aws_instance_status_report_csv: Optional[str]
    aws_instance_status_report_csv_hash: Optional[str]
    aws_instance_status_report_json: Optional[str]
    aws_instance_status_report_json_hash: Optional[str]
    aws_instance_type_report: Optional[str]
    aws_instance_type_report_hash: Optional[str]
    aws_root_account_report_csv: Optional[str]
    aws_root_account_report_json: Optional[str]
    aws_key_rotation_report_csv: Optional[str]
    aws_key_rotation_report_json: Optional[str]
    awsmfa_simulation_report_csv: Optional[str]
    awsmfa_simulation_report_json: Optional[str]
    awsmfa_report_csv: Optional[str]
    awsmfa_report_json: Optional[str]
    aws_unused_credential_report_csv: Optional[str]
    aws_unused_credential_report_json: Optional[str]

    def __init__(self, aws_password_policy_report_csv: Optional[str], aws_password_policy_report_json: Optional[str], compliance_pct: Optional[int], compliance_status: Optional[ComplianceStatusEnum], errors: None, aws_full_admin_policy_report_csv: Optional[str], aws_full_admin_policy_report_json: Optional[str], aws_credential_report_csv: Optional[str], aws_credential_report_csv_hash: Optional[str], aws_credential_report_json: Optional[str], aws_credential_report_json_hash: Optional[str], aws_user_access_key_report_csv: Optional[str], aws_user_access_key_report_json: Optional[str], aws_acc_auth_details_hash: Optional[str], aws_acc_auth_details_report: Optional[str], aws_user_policy_report_csv: Optional[str], aws_user_policy_report_json: Optional[str], aws_latest_ami_report_csv: Optional[str], aws_latest_ami_report_json: Optional[str], aws_instance_status_report_csv: Optional[str], aws_instance_status_report_csv_hash: Optional[str], aws_instance_status_report_json: Optional[str], aws_instance_status_report_json_hash: Optional[str], aws_instance_type_report: Optional[str], aws_instance_type_report_hash: Optional[str], aws_root_account_report_csv: Optional[str], aws_root_account_report_json: Optional[str], aws_key_rotation_report_csv: Optional[str], aws_key_rotation_report_json: Optional[str], awsmfa_simulation_report_csv: Optional[str], awsmfa_simulation_report_json: Optional[str], awsmfa_report_csv: Optional[str], awsmfa_report_json: Optional[str], aws_unused_credential_report_csv: Optional[str], aws_unused_credential_report_json: Optional[str]) -> None:
        self.aws_password_policy_report_csv = aws_password_policy_report_csv
        self.aws_password_policy_report_json = aws_password_policy_report_json
        self.compliance_pct = compliance_pct
        self.compliance_status = compliance_status
        self.errors = errors
        self.aws_full_admin_policy_report_csv = aws_full_admin_policy_report_csv
        self.aws_full_admin_policy_report_json = aws_full_admin_policy_report_json
        self.aws_credential_report_csv = aws_credential_report_csv
        self.aws_credential_report_csv_hash = aws_credential_report_csv_hash
        self.aws_credential_report_json = aws_credential_report_json
        self.aws_credential_report_json_hash = aws_credential_report_json_hash
        self.aws_user_access_key_report_csv = aws_user_access_key_report_csv
        self.aws_user_access_key_report_json = aws_user_access_key_report_json
        self.aws_acc_auth_details_hash = aws_acc_auth_details_hash
        self.aws_acc_auth_details_report = aws_acc_auth_details_report
        self.aws_user_policy_report_csv = aws_user_policy_report_csv
        self.aws_user_policy_report_json = aws_user_policy_report_json
        self.aws_latest_ami_report_csv = aws_latest_ami_report_csv
        self.aws_latest_ami_report_json = aws_latest_ami_report_json
        self.aws_instance_status_report_csv = aws_instance_status_report_csv
        self.aws_instance_status_report_csv_hash = aws_instance_status_report_csv_hash
        self.aws_instance_status_report_json = aws_instance_status_report_json
        self.aws_instance_status_report_json_hash = aws_instance_status_report_json_hash
        self.aws_instance_type_report = aws_instance_type_report
        self.aws_instance_type_report_hash = aws_instance_type_report_hash
        self.aws_root_account_report_csv = aws_root_account_report_csv
        self.aws_root_account_report_json = aws_root_account_report_json
        self.aws_key_rotation_report_csv = aws_key_rotation_report_csv
        self.aws_key_rotation_report_json = aws_key_rotation_report_json
        self.awsmfa_simulation_report_csv = awsmfa_simulation_report_csv
        self.awsmfa_simulation_report_json = awsmfa_simulation_report_json
        self.awsmfa_report_csv = awsmfa_report_csv
        self.awsmfa_report_json = awsmfa_report_json
        self.aws_unused_credential_report_csv = aws_unused_credential_report_csv
        self.aws_unused_credential_report_json = aws_unused_credential_report_json

    @staticmethod
    def from_dict(obj: Any) -> 'Outputs':
        assert isinstance(obj, dict)
        aws_password_policy_report_csv = from_union(
            [from_str, from_none], obj.get("AWSPasswordPolicyReportCSV"))
        aws_password_policy_report_json = from_union(
            [from_str, from_none], obj.get("AWSPasswordPolicyReportJSON"))
        compliance_pct = from_union(
            [from_int, from_none], obj.get("CompliancePCT_"))
        compliance_status = from_union(
            [ComplianceStatusEnum, from_none], obj.get("ComplianceStatus_"))
        errors = from_none(obj.get("Errors"))
        aws_full_admin_policy_report_csv = from_union(
            [from_str, from_none], obj.get("AWSFullAdminPolicyReportCSV"))
        aws_full_admin_policy_report_json = from_union(
            [from_str, from_none], obj.get("AWSFullAdminPolicyReportJSON"))
        aws_credential_report_csv = from_union(
            [from_str, from_none], obj.get("AWSCredentialReportCSV"))
        aws_credential_report_csv_hash = from_union(
            [from_str, from_none], obj.get("AWSCredentialReportCSVHash"))
        aws_credential_report_json = from_union(
            [from_str, from_none], obj.get("AWSCredentialReportJSON"))
        aws_credential_report_json_hash = from_union(
            [from_str, from_none], obj.get("AWSCredentialReportJSONHash"))
        aws_user_access_key_report_csv = from_union(
            [from_str, from_none], obj.get("AWSUserAccessKeyReportCSV"))
        aws_user_access_key_report_json = from_union(
            [from_str, from_none], obj.get("AWSUserAccessKeyReportJSON"))
        aws_acc_auth_details_hash = from_union(
            [from_str, from_none], obj.get("AWSAccAuthDetailsHash"))
        aws_acc_auth_details_report = from_union(
            [from_str, from_none], obj.get("AWSAccAuthDetailsReport"))
        aws_user_policy_report_csv = from_union(
            [from_str, from_none], obj.get("AWSUserPolicyReportCSV"))
        aws_user_policy_report_json = from_union(
            [from_str, from_none], obj.get("AWSUserPolicyReportJSON"))
        aws_latest_ami_report_csv = from_union(
            [from_str, from_none], obj.get("AWSLatestAMIReportCSV"))
        aws_latest_ami_report_json = from_union(
            [from_str, from_none], obj.get("AWSLatestAMIReportJSON"))
        aws_instance_status_report_csv = from_union(
            [from_str, from_none], obj.get("AWSInstanceStatusReportCSV"))
        aws_instance_status_report_csv_hash = from_union(
            [from_str, from_none], obj.get("AWSInstanceStatusReportCSVHash"))
        aws_instance_status_report_json = from_union(
            [from_str, from_none], obj.get("AWSInstanceStatusReportJSON"))
        aws_instance_status_report_json_hash = from_union(
            [from_str, from_none], obj.get("AWSInstanceStatusReportJSONHash"))
        aws_instance_type_report = from_union(
            [from_str, from_none], obj.get("AWSInstanceTypeReport"))
        aws_instance_type_report_hash = from_union(
            [from_str, from_none], obj.get("AWSInstanceTypeReportHash"))
        aws_root_account_report_csv = from_union(
            [from_str, from_none], obj.get("AWSRootAccountReportCSV"))
        aws_root_account_report_json = from_union(
            [from_str, from_none], obj.get("AWSRootAccountReportJSON"))
        aws_key_rotation_report_csv = from_union(
            [from_str, from_none], obj.get("AWSKeyRotationReportCSV"))
        aws_key_rotation_report_json = from_union(
            [from_str, from_none], obj.get("AWSKeyRotationReportJSON"))
        awsmfa_simulation_report_csv = from_union(
            [from_str, from_none], obj.get("AWSMFASimulationReportCSV"))
        awsmfa_simulation_report_json = from_union(
            [from_str, from_none], obj.get("AWSMFASimulationReportJSON"))
        awsmfa_report_csv = from_union(
            [from_str, from_none], obj.get("AWSMFAReportCSV"))
        awsmfa_report_json = from_union(
            [from_str, from_none], obj.get("AWSMFAReportJSON"))
        aws_unused_credential_report_csv = from_union(
            [from_str, from_none], obj.get("AWSUnusedCredentialReportCSV"))
        aws_unused_credential_report_json = from_union(
            [from_str, from_none], obj.get("AWSUnusedCredentialReportJSON"))
        return Outputs(aws_password_policy_report_csv, aws_password_policy_report_json, compliance_pct, compliance_status, errors, aws_full_admin_policy_report_csv, aws_full_admin_policy_report_json, aws_credential_report_csv, aws_credential_report_csv_hash, aws_credential_report_json, aws_credential_report_json_hash, aws_user_access_key_report_csv, aws_user_access_key_report_json, aws_acc_auth_details_hash, aws_acc_auth_details_report, aws_user_policy_report_csv, aws_user_policy_report_json, aws_latest_ami_report_csv, aws_latest_ami_report_json, aws_instance_status_report_csv, aws_instance_status_report_csv_hash, aws_instance_status_report_json, aws_instance_status_report_json_hash, aws_instance_type_report, aws_instance_type_report_hash, aws_root_account_report_csv, aws_root_account_report_json, aws_key_rotation_report_csv, aws_key_rotation_report_json, awsmfa_simulation_report_csv, awsmfa_simulation_report_json, awsmfa_report_csv, awsmfa_report_json, aws_unused_credential_report_csv, aws_unused_credential_report_json)

    def to_dict(self) -> dict:
        result: dict = {}
        result["AWSPasswordPolicyReportCSV"] = from_union(
            [from_str, from_none], self.aws_password_policy_report_csv)
        result["AWSPasswordPolicyReportJSON"] = from_union(
            [from_str, from_none], self.aws_password_policy_report_json)
        result["CompliancePCT_"] = from_union(
            [from_int, from_none], self.compliance_pct)
        result["ComplianceStatus_"] = from_union([lambda x: to_enum(
            ComplianceStatusEnum, x), from_none], self.compliance_status)
        result["Errors"] = from_none(self.errors)
        result["AWSFullAdminPolicyReportCSV"] = from_union(
            [from_str, from_none], self.aws_full_admin_policy_report_csv)
        result["AWSFullAdminPolicyReportJSON"] = from_union(
            [from_str, from_none], self.aws_full_admin_policy_report_json)
        result["AWSCredentialReportCSV"] = from_union(
            [from_str, from_none], self.aws_credential_report_csv)
        result["AWSCredentialReportCSVHash"] = from_union(
            [from_str, from_none], self.aws_credential_report_csv_hash)
        result["AWSCredentialReportJSON"] = from_union(
            [from_str, from_none], self.aws_credential_report_json)
        result["AWSCredentialReportJSONHash"] = from_union(
            [from_str, from_none], self.aws_credential_report_json_hash)
        result["AWSUserAccessKeyReportCSV"] = from_union(
            [from_str, from_none], self.aws_user_access_key_report_csv)
        result["AWSUserAccessKeyReportJSON"] = from_union(
            [from_str, from_none], self.aws_user_access_key_report_json)
        result["AWSAccAuthDetailsHash"] = from_union(
            [from_str, from_none], self.aws_acc_auth_details_hash)
        result["AWSAccAuthDetailsReport"] = from_union(
            [from_str, from_none], self.aws_acc_auth_details_report)
        result["AWSUserPolicyReportCSV"] = from_union(
            [from_str, from_none], self.aws_user_policy_report_csv)
        result["AWSUserPolicyReportJSON"] = from_union(
            [from_str, from_none], self.aws_user_policy_report_json)
        result["AWSLatestAMIReportCSV"] = from_union(
            [from_str, from_none], self.aws_latest_ami_report_csv)
        result["AWSLatestAMIReportJSON"] = from_union(
            [from_str, from_none], self.aws_latest_ami_report_json)
        result["AWSInstanceStatusReportCSV"] = from_union(
            [from_str, from_none], self.aws_instance_status_report_csv)
        result["AWSInstanceStatusReportCSVHash"] = from_union(
            [from_str, from_none], self.aws_instance_status_report_csv_hash)
        result["AWSInstanceStatusReportJSON"] = from_union(
            [from_str, from_none], self.aws_instance_status_report_json)
        result["AWSInstanceStatusReportJSONHash"] = from_union(
            [from_str, from_none], self.aws_instance_status_report_json_hash)
        result["AWSInstanceTypeReport"] = from_union(
            [from_str, from_none], self.aws_instance_type_report)
        result["AWSInstanceTypeReportHash"] = from_union(
            [from_str, from_none], self.aws_instance_type_report_hash)
        result["AWSRootAccountReportCSV"] = from_union(
            [from_str, from_none], self.aws_root_account_report_csv)
        result["AWSRootAccountReportJSON"] = from_union(
            [from_str, from_none], self.aws_root_account_report_json)
        result["AWSKeyRotationReportCSV"] = from_union(
            [from_str, from_none], self.aws_key_rotation_report_csv)
        result["AWSKeyRotationReportJSON"] = from_union(
            [from_str, from_none], self.aws_key_rotation_report_json)
        result["AWSMFASimulationReportCSV"] = from_union(
            [from_str, from_none], self.awsmfa_simulation_report_csv)
        result["AWSMFASimulationReportJSON"] = from_union(
            [from_str, from_none], self.awsmfa_simulation_report_json)
        result["AWSMFAReportCSV"] = from_union(
            [from_str, from_none], self.awsmfa_report_csv)
        result["AWSMFAReportJSON"] = from_union(
            [from_str, from_none], self.awsmfa_report_json)
        result["AWSUnusedCredentialReportCSV"] = from_union(
            [from_str, from_none], self.aws_unused_credential_report_csv)
        result["AWSUnusedCredentialReportJSON"] = from_union(
            [from_str, from_none], self.aws_unused_credential_report_json)
        return result


class PurpleRuleiovalues:
    inputs: Optional[Inputs]
    outputs: Optional[Outputs]

    def __init__(self, inputs: Optional[Inputs], outputs: Optional[Outputs]) -> None:
        self.inputs = inputs
        self.outputs = outputs

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleRuleiovalues':
        assert isinstance(obj, dict)
        inputs = from_union([Inputs.from_dict, from_none], obj.get("inputs"))
        outputs = from_union(
            [Outputs.from_dict, from_none], obj.get("outputs"))
        return PurpleRuleiovalues(inputs, outputs)

    def to_dict(self) -> dict:
        result: dict = {}
        result["inputs"] = from_union(
            [lambda x: to_class(Inputs, x), from_none], self.inputs)
        result["outputs"] = from_union(
            [lambda x: to_class(Outputs, x), from_none], self.outputs)
        return result


class RuleOutputRuleOutput:
    output_type: Optional[FluffyOutputType]
    purpose: Optional[str]
    description: Optional[str]
    aliasref: Optional[Aliasref]
    seqno: Optional[int]
    ruleiovalues: Optional[PurpleRuleiovalues]

    def __init__(self, output_type: Optional[FluffyOutputType], purpose: Optional[str], description: Optional[str], aliasref: Optional[Aliasref], seqno: Optional[int], ruleiovalues: Optional[PurpleRuleiovalues]) -> None:
        self.output_type = output_type
        self.purpose = purpose
        self.description = description
        self.aliasref = aliasref
        self.seqno = seqno
        self.ruleiovalues = ruleiovalues

    @staticmethod
    def from_dict(obj: Any) -> 'RuleOutputRuleOutput':
        assert isinstance(obj, dict)
        output_type = from_union(
            [FluffyOutputType, from_none], obj.get("outputType"))
        purpose = from_union([from_str, from_none], obj.get("purpose"))
        description = from_union([from_str, from_none], obj.get("description"))
        aliasref = from_union([Aliasref, from_none], obj.get("aliasref"))
        seqno = from_union([from_int, from_none], obj.get("seqno"))
        ruleiovalues = from_union(
            [PurpleRuleiovalues.from_dict, from_none], obj.get("ruleiovalues"))
        return RuleOutputRuleOutput(output_type, purpose, description, aliasref, seqno, ruleiovalues)

    def to_dict(self) -> dict:
        result: dict = {}
        result["outputType"] = from_union(
            [lambda x: to_enum(FluffyOutputType, x), from_none], self.output_type)
        result["purpose"] = from_union([from_str, from_none], self.purpose)
        result["description"] = from_union(
            [from_str, from_none], self.description)
        result["aliasref"] = from_union(
            [lambda x: to_enum(Aliasref, x), from_none], self.aliasref)
        result["seqno"] = from_union([from_int, from_none], self.seqno)
        result["ruleiovalues"] = from_union(
            [lambda x: to_class(PurpleRuleiovalues, x), from_none], self.ruleiovalues)
        return result


class OutputFiles:
    the_18_d6_d5_df38_d49248823_d00_a9_d135_fdf8821_dd866: Optional[str]
    the_6_dc51_fc88_ac543_be1_ea0_e9_ba3_eee189_c5_cd8_b988: Optional[str]
    ba0805_c0_bcda49_ed1_ed64_bbc6614_da479_d93932_b: Optional[str]
    the_5_de085_ef7394340491_afe01257_f9_a33_b6_d02_c654: Optional[str]
    the_87_fd68586_b9_bdb49_fa224_f12077_d8_e72277_da485: Optional[str]
    be330415341_c60_d015369_ac968_cd2_ecbe20_b47_f6: Optional[str]
    the_138826_a29_de8962_b475_db99_d3_d1145_d57209_a7_f6: Optional[str]
    the_844_aec88_a3_d9569_bf8_a80_bbc6_e1_c6_ec3_b92_edceb: Optional[str]
    d7_e71912_bb93_cad3_cac0_ec61_b4271458830_a8967: Optional[str]
    e3_f7586_c5_d5820_e39149404_cd6_b0_ce510_b752538: Optional[str]
    the_020343674_b8_b29_f760691_a336_b7_a25_c4_a19116_c2: Optional[str]
    the_1_b2_e92198_f3_e8_c847_aa97965_aa0_a6_b24_ad8_e34_dc: Optional[str]
    e7793822_ff314_b58_f30_c86_c1043_b401636_ff3_f4_e: Optional[str]
    the_7_b3711_b197499_f261_e9_b38_d941_fc9_e1_e43_dd8262: Optional[str]
    a4_f87379_f9_fe697_b7_e1_ece9_ca7_a150_f30_dfcc49_f: Optional[str]
    f4_b6_c7_bba7_fb6_d58441_cb6365_dc11440_b6252823: Optional[str]
    the_0_b23_ca630_e0_d50_b6_a263_c0857_c8_a8_d1178_e4727_d: Optional[str]
    d4_da6_dbb8_ff5_ba8_e99_c319_c20_baafe3_db3_c19_c59: Optional[str]
    e6_d0890_ddc13_f1_d8_e57_b23_c8_f1_d764_ce6_c1_bf2_cc: Optional[str]
    the_2_d26_f4_a43_efed7_f0_a8_f892629_a9_fa6_d92_f5_b780_c: Optional[str]
    the_309785_a720_d16975_b497_b3_a8_e91783_f25_fde21_e3: Optional[str]
    the_696292_b64_c7_b0_a431_ba26_c1_d28_a853712257_b32_d: Optional[str]
    the_301_a3_d58_a6_b07542_adbc4_dbbe795_d3_ad159_b4_bc1: Optional[str]
    the_39118_cd4_e47_a52_a41_f0_f4_d798_fc43645_f0_c2_db31: Optional[str]
    the_54_ad816_c0186_bca851_b0_af234431857169_d15_c1_d: Optional[str]
    cff89_d2_fdc6_a2_ab68671_f0_ae5_e632417_dea9_b39_f: Optional[str]
    e55_ed01_a52255_de2_f9_ad019_b320_fb97_c18576_a7_a: Optional[str]
    the_238987_c7313_c79_aa7_e7_d7_a4693_dbedcd7_f9_e16_f2: Optional[str]
    c0_a2233154_cd1_e7756_f3_a8_f8_f6_c49931_a13_d9_caf: Optional[str]
    dc0_bd4774598_c9_cb5_bdd5_d26_a1_c8_bc02_eedda7_fb: Optional[str]
    the_230068545_ef50_e942_c9_d81_fc758_ba5_a1564_a6_c89: Optional[str]
    the_39_ee6_b6854_ff8_b47917188_c12_d5_b424_c5673_cc07: Optional[str]
    the_8_c34_b480_a3814_bba1478266887_c81_c4_b252_af6_d7: Optional[str]
    the_4_b5_e6_cdc490_b659_b70_c3_ba96_b42329_b8160_ea786: Optional[str]
    cdfed346_dab57160331_db3_a62_e2_fc57_b7_feaf2_e0: Optional[str]
    d393_abf7_a1_ac6_b3_c65_df6417_bb9_b0414_a85_f97_bf: Optional[str]
    the_2910377_beb01_f97_d9_fe28_eab9496_bb57_bb9_dc8_df: Optional[str]
    dad7549768_f1_f3_dc6983_b929_a070342_cbc781_dff: Optional[str]
    ead484_e350_bb17_f86_d5_f62_e25_e7_ec56_bca64_ec1_c: Optional[str]
    the_5_f1_baa0803_ba4628_f58585_b9_fda8_c4_fbb31_b2770: Optional[str]
    aa0_a64_ad2_c219940_a19_e23_c25_d74_e60_f7_a77_b8_e9: Optional[str]
    de3_d308_ce0_f48_c7897296_d347_e79_ad3_d54_c0_c72_b: Optional[str]

    def __init__(self, the_18_d6_d5_df38_d49248823_d00_a9_d135_fdf8821_dd866: Optional[str], the_6_dc51_fc88_ac543_be1_ea0_e9_ba3_eee189_c5_cd8_b988: Optional[str], ba0805_c0_bcda49_ed1_ed64_bbc6614_da479_d93932_b: Optional[str], the_5_de085_ef7394340491_afe01257_f9_a33_b6_d02_c654: Optional[str], the_87_fd68586_b9_bdb49_fa224_f12077_d8_e72277_da485: Optional[str], be330415341_c60_d015369_ac968_cd2_ecbe20_b47_f6: Optional[str], the_138826_a29_de8962_b475_db99_d3_d1145_d57209_a7_f6: Optional[str], the_844_aec88_a3_d9569_bf8_a80_bbc6_e1_c6_ec3_b92_edceb: Optional[str], d7_e71912_bb93_cad3_cac0_ec61_b4271458830_a8967: Optional[str], e3_f7586_c5_d5820_e39149404_cd6_b0_ce510_b752538: Optional[str], the_020343674_b8_b29_f760691_a336_b7_a25_c4_a19116_c2: Optional[str], the_1_b2_e92198_f3_e8_c847_aa97965_aa0_a6_b24_ad8_e34_dc: Optional[str], e7793822_ff314_b58_f30_c86_c1043_b401636_ff3_f4_e: Optional[str], the_7_b3711_b197499_f261_e9_b38_d941_fc9_e1_e43_dd8262: Optional[str], a4_f87379_f9_fe697_b7_e1_ece9_ca7_a150_f30_dfcc49_f: Optional[str], f4_b6_c7_bba7_fb6_d58441_cb6365_dc11440_b6252823: Optional[str], the_0_b23_ca630_e0_d50_b6_a263_c0857_c8_a8_d1178_e4727_d: Optional[str], d4_da6_dbb8_ff5_ba8_e99_c319_c20_baafe3_db3_c19_c59: Optional[str], e6_d0890_ddc13_f1_d8_e57_b23_c8_f1_d764_ce6_c1_bf2_cc: Optional[str], the_2_d26_f4_a43_efed7_f0_a8_f892629_a9_fa6_d92_f5_b780_c: Optional[str], the_309785_a720_d16975_b497_b3_a8_e91783_f25_fde21_e3: Optional[str], the_696292_b64_c7_b0_a431_ba26_c1_d28_a853712257_b32_d: Optional[str], the_301_a3_d58_a6_b07542_adbc4_dbbe795_d3_ad159_b4_bc1: Optional[str], the_39118_cd4_e47_a52_a41_f0_f4_d798_fc43645_f0_c2_db31: Optional[str], the_54_ad816_c0186_bca851_b0_af234431857169_d15_c1_d: Optional[str], cff89_d2_fdc6_a2_ab68671_f0_ae5_e632417_dea9_b39_f: Optional[str], e55_ed01_a52255_de2_f9_ad019_b320_fb97_c18576_a7_a: Optional[str], the_238987_c7313_c79_aa7_e7_d7_a4693_dbedcd7_f9_e16_f2: Optional[str], c0_a2233154_cd1_e7756_f3_a8_f8_f6_c49931_a13_d9_caf: Optional[str], dc0_bd4774598_c9_cb5_bdd5_d26_a1_c8_bc02_eedda7_fb: Optional[str], the_230068545_ef50_e942_c9_d81_fc758_ba5_a1564_a6_c89: Optional[str], the_39_ee6_b6854_ff8_b47917188_c12_d5_b424_c5673_cc07: Optional[str], the_8_c34_b480_a3814_bba1478266887_c81_c4_b252_af6_d7: Optional[str], the_4_b5_e6_cdc490_b659_b70_c3_ba96_b42329_b8160_ea786: Optional[str], cdfed346_dab57160331_db3_a62_e2_fc57_b7_feaf2_e0: Optional[str], d393_abf7_a1_ac6_b3_c65_df6417_bb9_b0414_a85_f97_bf: Optional[str], the_2910377_beb01_f97_d9_fe28_eab9496_bb57_bb9_dc8_df: Optional[str], dad7549768_f1_f3_dc6983_b929_a070342_cbc781_dff: Optional[str], ead484_e350_bb17_f86_d5_f62_e25_e7_ec56_bca64_ec1_c: Optional[str], the_5_f1_baa0803_ba4628_f58585_b9_fda8_c4_fbb31_b2770: Optional[str], aa0_a64_ad2_c219940_a19_e23_c25_d74_e60_f7_a77_b8_e9: Optional[str], de3_d308_ce0_f48_c7897296_d347_e79_ad3_d54_c0_c72_b: Optional[str]) -> None:
        self.the_18_d6_d5_df38_d49248823_d00_a9_d135_fdf8821_dd866 = the_18_d6_d5_df38_d49248823_d00_a9_d135_fdf8821_dd866
        self.the_6_dc51_fc88_ac543_be1_ea0_e9_ba3_eee189_c5_cd8_b988 = the_6_dc51_fc88_ac543_be1_ea0_e9_ba3_eee189_c5_cd8_b988
        self.ba0805_c0_bcda49_ed1_ed64_bbc6614_da479_d93932_b = ba0805_c0_bcda49_ed1_ed64_bbc6614_da479_d93932_b
        self.the_5_de085_ef7394340491_afe01257_f9_a33_b6_d02_c654 = the_5_de085_ef7394340491_afe01257_f9_a33_b6_d02_c654
        self.the_87_fd68586_b9_bdb49_fa224_f12077_d8_e72277_da485 = the_87_fd68586_b9_bdb49_fa224_f12077_d8_e72277_da485
        self.be330415341_c60_d015369_ac968_cd2_ecbe20_b47_f6 = be330415341_c60_d015369_ac968_cd2_ecbe20_b47_f6
        self.the_138826_a29_de8962_b475_db99_d3_d1145_d57209_a7_f6 = the_138826_a29_de8962_b475_db99_d3_d1145_d57209_a7_f6
        self.the_844_aec88_a3_d9569_bf8_a80_bbc6_e1_c6_ec3_b92_edceb = the_844_aec88_a3_d9569_bf8_a80_bbc6_e1_c6_ec3_b92_edceb
        self.d7_e71912_bb93_cad3_cac0_ec61_b4271458830_a8967 = d7_e71912_bb93_cad3_cac0_ec61_b4271458830_a8967
        self.e3_f7586_c5_d5820_e39149404_cd6_b0_ce510_b752538 = e3_f7586_c5_d5820_e39149404_cd6_b0_ce510_b752538
        self.the_020343674_b8_b29_f760691_a336_b7_a25_c4_a19116_c2 = the_020343674_b8_b29_f760691_a336_b7_a25_c4_a19116_c2
        self.the_1_b2_e92198_f3_e8_c847_aa97965_aa0_a6_b24_ad8_e34_dc = the_1_b2_e92198_f3_e8_c847_aa97965_aa0_a6_b24_ad8_e34_dc
        self.e7793822_ff314_b58_f30_c86_c1043_b401636_ff3_f4_e = e7793822_ff314_b58_f30_c86_c1043_b401636_ff3_f4_e
        self.the_7_b3711_b197499_f261_e9_b38_d941_fc9_e1_e43_dd8262 = the_7_b3711_b197499_f261_e9_b38_d941_fc9_e1_e43_dd8262
        self.a4_f87379_f9_fe697_b7_e1_ece9_ca7_a150_f30_dfcc49_f = a4_f87379_f9_fe697_b7_e1_ece9_ca7_a150_f30_dfcc49_f
        self.f4_b6_c7_bba7_fb6_d58441_cb6365_dc11440_b6252823 = f4_b6_c7_bba7_fb6_d58441_cb6365_dc11440_b6252823
        self.the_0_b23_ca630_e0_d50_b6_a263_c0857_c8_a8_d1178_e4727_d = the_0_b23_ca630_e0_d50_b6_a263_c0857_c8_a8_d1178_e4727_d
        self.d4_da6_dbb8_ff5_ba8_e99_c319_c20_baafe3_db3_c19_c59 = d4_da6_dbb8_ff5_ba8_e99_c319_c20_baafe3_db3_c19_c59
        self.e6_d0890_ddc13_f1_d8_e57_b23_c8_f1_d764_ce6_c1_bf2_cc = e6_d0890_ddc13_f1_d8_e57_b23_c8_f1_d764_ce6_c1_bf2_cc
        self.the_2_d26_f4_a43_efed7_f0_a8_f892629_a9_fa6_d92_f5_b780_c = the_2_d26_f4_a43_efed7_f0_a8_f892629_a9_fa6_d92_f5_b780_c
        self.the_309785_a720_d16975_b497_b3_a8_e91783_f25_fde21_e3 = the_309785_a720_d16975_b497_b3_a8_e91783_f25_fde21_e3
        self.the_696292_b64_c7_b0_a431_ba26_c1_d28_a853712257_b32_d = the_696292_b64_c7_b0_a431_ba26_c1_d28_a853712257_b32_d
        self.the_301_a3_d58_a6_b07542_adbc4_dbbe795_d3_ad159_b4_bc1 = the_301_a3_d58_a6_b07542_adbc4_dbbe795_d3_ad159_b4_bc1
        self.the_39118_cd4_e47_a52_a41_f0_f4_d798_fc43645_f0_c2_db31 = the_39118_cd4_e47_a52_a41_f0_f4_d798_fc43645_f0_c2_db31
        self.the_54_ad816_c0186_bca851_b0_af234431857169_d15_c1_d = the_54_ad816_c0186_bca851_b0_af234431857169_d15_c1_d
        self.cff89_d2_fdc6_a2_ab68671_f0_ae5_e632417_dea9_b39_f = cff89_d2_fdc6_a2_ab68671_f0_ae5_e632417_dea9_b39_f
        self.e55_ed01_a52255_de2_f9_ad019_b320_fb97_c18576_a7_a = e55_ed01_a52255_de2_f9_ad019_b320_fb97_c18576_a7_a
        self.the_238987_c7313_c79_aa7_e7_d7_a4693_dbedcd7_f9_e16_f2 = the_238987_c7313_c79_aa7_e7_d7_a4693_dbedcd7_f9_e16_f2
        self.c0_a2233154_cd1_e7756_f3_a8_f8_f6_c49931_a13_d9_caf = c0_a2233154_cd1_e7756_f3_a8_f8_f6_c49931_a13_d9_caf
        self.dc0_bd4774598_c9_cb5_bdd5_d26_a1_c8_bc02_eedda7_fb = dc0_bd4774598_c9_cb5_bdd5_d26_a1_c8_bc02_eedda7_fb
        self.the_230068545_ef50_e942_c9_d81_fc758_ba5_a1564_a6_c89 = the_230068545_ef50_e942_c9_d81_fc758_ba5_a1564_a6_c89
        self.the_39_ee6_b6854_ff8_b47917188_c12_d5_b424_c5673_cc07 = the_39_ee6_b6854_ff8_b47917188_c12_d5_b424_c5673_cc07
        self.the_8_c34_b480_a3814_bba1478266887_c81_c4_b252_af6_d7 = the_8_c34_b480_a3814_bba1478266887_c81_c4_b252_af6_d7
        self.the_4_b5_e6_cdc490_b659_b70_c3_ba96_b42329_b8160_ea786 = the_4_b5_e6_cdc490_b659_b70_c3_ba96_b42329_b8160_ea786
        self.cdfed346_dab57160331_db3_a62_e2_fc57_b7_feaf2_e0 = cdfed346_dab57160331_db3_a62_e2_fc57_b7_feaf2_e0
        self.d393_abf7_a1_ac6_b3_c65_df6417_bb9_b0414_a85_f97_bf = d393_abf7_a1_ac6_b3_c65_df6417_bb9_b0414_a85_f97_bf
        self.the_2910377_beb01_f97_d9_fe28_eab9496_bb57_bb9_dc8_df = the_2910377_beb01_f97_d9_fe28_eab9496_bb57_bb9_dc8_df
        self.dad7549768_f1_f3_dc6983_b929_a070342_cbc781_dff = dad7549768_f1_f3_dc6983_b929_a070342_cbc781_dff
        self.ead484_e350_bb17_f86_d5_f62_e25_e7_ec56_bca64_ec1_c = ead484_e350_bb17_f86_d5_f62_e25_e7_ec56_bca64_ec1_c
        self.the_5_f1_baa0803_ba4628_f58585_b9_fda8_c4_fbb31_b2770 = the_5_f1_baa0803_ba4628_f58585_b9_fda8_c4_fbb31_b2770
        self.aa0_a64_ad2_c219940_a19_e23_c25_d74_e60_f7_a77_b8_e9 = aa0_a64_ad2_c219940_a19_e23_c25_d74_e60_f7_a77_b8_e9
        self.de3_d308_ce0_f48_c7897296_d347_e79_ad3_d54_c0_c72_b = de3_d308_ce0_f48_c7897296_d347_e79_ad3_d54_c0_c72_b

    @staticmethod
    def from_dict(obj: Any) -> 'OutputFiles':
        assert isinstance(obj, dict)
        the_18_d6_d5_df38_d49248823_d00_a9_d135_fdf8821_dd866 = from_union(
            [from_str, from_none], obj.get("18d6d5df38d49248823d00a9d135fdf8821dd866"))
        the_6_dc51_fc88_ac543_be1_ea0_e9_ba3_eee189_c5_cd8_b988 = from_union(
            [from_str, from_none], obj.get("6dc51fc88ac543be1ea0e9ba3eee189c5cd8b988"))
        ba0805_c0_bcda49_ed1_ed64_bbc6614_da479_d93932_b = from_union(
            [from_str, from_none], obj.get("ba0805c0bcda49ed1ed64bbc6614da479d93932b"))
        the_5_de085_ef7394340491_afe01257_f9_a33_b6_d02_c654 = from_union(
            [from_str, from_none], obj.get("5de085ef7394340491afe01257f9a33b6d02c654"))
        the_87_fd68586_b9_bdb49_fa224_f12077_d8_e72277_da485 = from_union(
            [from_str, from_none], obj.get("87fd68586b9bdb49fa224f12077d8e72277da485"))
        be330415341_c60_d015369_ac968_cd2_ecbe20_b47_f6 = from_union(
            [from_str, from_none], obj.get("be330415341c60d015369ac968cd2ecbe20b47f6"))
        the_138826_a29_de8962_b475_db99_d3_d1145_d57209_a7_f6 = from_union(
            [from_str, from_none], obj.get("138826a29de8962b475db99d3d1145d57209a7f6"))
        the_844_aec88_a3_d9569_bf8_a80_bbc6_e1_c6_ec3_b92_edceb = from_union(
            [from_str, from_none], obj.get("844aec88a3d9569bf8a80bbc6e1c6ec3b92edceb"))
        d7_e71912_bb93_cad3_cac0_ec61_b4271458830_a8967 = from_union(
            [from_str, from_none], obj.get("d7e71912bb93cad3cac0ec61b4271458830a8967"))
        e3_f7586_c5_d5820_e39149404_cd6_b0_ce510_b752538 = from_union(
            [from_str, from_none], obj.get("e3f7586c5d5820e39149404cd6b0ce510b752538"))
        the_020343674_b8_b29_f760691_a336_b7_a25_c4_a19116_c2 = from_union(
            [from_str, from_none], obj.get("020343674b8b29f760691a336b7a25c4a19116c2"))
        the_1_b2_e92198_f3_e8_c847_aa97965_aa0_a6_b24_ad8_e34_dc = from_union(
            [from_str, from_none], obj.get("1b2e92198f3e8c847aa97965aa0a6b24ad8e34dc"))
        e7793822_ff314_b58_f30_c86_c1043_b401636_ff3_f4_e = from_union(
            [from_str, from_none], obj.get("e7793822ff314b58f30c86c1043b401636ff3f4e"))
        the_7_b3711_b197499_f261_e9_b38_d941_fc9_e1_e43_dd8262 = from_union(
            [from_str, from_none], obj.get("7b3711b197499f261e9b38d941fc9e1e43dd8262"))
        a4_f87379_f9_fe697_b7_e1_ece9_ca7_a150_f30_dfcc49_f = from_union(
            [from_str, from_none], obj.get("a4f87379f9fe697b7e1ece9ca7a150f30dfcc49f"))
        f4_b6_c7_bba7_fb6_d58441_cb6365_dc11440_b6252823 = from_union(
            [from_str, from_none], obj.get("f4b6c7bba7fb6d58441cb6365dc11440b6252823"))
        the_0_b23_ca630_e0_d50_b6_a263_c0857_c8_a8_d1178_e4727_d = from_union(
            [from_str, from_none], obj.get("0b23ca630e0d50b6a263c0857c8a8d1178e4727d"))
        d4_da6_dbb8_ff5_ba8_e99_c319_c20_baafe3_db3_c19_c59 = from_union(
            [from_str, from_none], obj.get("d4da6dbb8ff5ba8e99c319c20baafe3db3c19c59"))
        e6_d0890_ddc13_f1_d8_e57_b23_c8_f1_d764_ce6_c1_bf2_cc = from_union(
            [from_str, from_none], obj.get("e6d0890ddc13f1d8e57b23c8f1d764ce6c1bf2cc"))
        the_2_d26_f4_a43_efed7_f0_a8_f892629_a9_fa6_d92_f5_b780_c = from_union(
            [from_str, from_none], obj.get("2d26f4a43efed7f0a8f892629a9fa6d92f5b780c"))
        the_309785_a720_d16975_b497_b3_a8_e91783_f25_fde21_e3 = from_union(
            [from_str, from_none], obj.get("309785a720d16975b497b3a8e91783f25fde21e3"))
        the_696292_b64_c7_b0_a431_ba26_c1_d28_a853712257_b32_d = from_union(
            [from_str, from_none], obj.get("696292b64c7b0a431ba26c1d28a853712257b32d"))
        the_301_a3_d58_a6_b07542_adbc4_dbbe795_d3_ad159_b4_bc1 = from_union(
            [from_str, from_none], obj.get("301a3d58a6b07542adbc4dbbe795d3ad159b4bc1"))
        the_39118_cd4_e47_a52_a41_f0_f4_d798_fc43645_f0_c2_db31 = from_union(
            [from_str, from_none], obj.get("39118cd4e47a52a41f0f4d798fc43645f0c2db31"))
        the_54_ad816_c0186_bca851_b0_af234431857169_d15_c1_d = from_union(
            [from_str, from_none], obj.get("54ad816c0186bca851b0af234431857169d15c1d"))
        cff89_d2_fdc6_a2_ab68671_f0_ae5_e632417_dea9_b39_f = from_union(
            [from_str, from_none], obj.get("cff89d2fdc6a2ab68671f0ae5e632417dea9b39f"))
        e55_ed01_a52255_de2_f9_ad019_b320_fb97_c18576_a7_a = from_union(
            [from_str, from_none], obj.get("e55ed01a52255de2f9ad019b320fb97c18576a7a"))
        the_238987_c7313_c79_aa7_e7_d7_a4693_dbedcd7_f9_e16_f2 = from_union(
            [from_str, from_none], obj.get("238987c7313c79aa7e7d7a4693dbedcd7f9e16f2"))
        c0_a2233154_cd1_e7756_f3_a8_f8_f6_c49931_a13_d9_caf = from_union(
            [from_str, from_none], obj.get("c0a2233154cd1e7756f3a8f8f6c49931a13d9caf"))
        dc0_bd4774598_c9_cb5_bdd5_d26_a1_c8_bc02_eedda7_fb = from_union(
            [from_str, from_none], obj.get("dc0bd4774598c9cb5bdd5d26a1c8bc02eedda7fb"))
        the_230068545_ef50_e942_c9_d81_fc758_ba5_a1564_a6_c89 = from_union(
            [from_str, from_none], obj.get("230068545ef50e942c9d81fc758ba5a1564a6c89"))
        the_39_ee6_b6854_ff8_b47917188_c12_d5_b424_c5673_cc07 = from_union(
            [from_str, from_none], obj.get("39ee6b6854ff8b47917188c12d5b424c5673cc07"))
        the_8_c34_b480_a3814_bba1478266887_c81_c4_b252_af6_d7 = from_union(
            [from_str, from_none], obj.get("8c34b480a3814bba1478266887c81c4b252af6d7"))
        the_4_b5_e6_cdc490_b659_b70_c3_ba96_b42329_b8160_ea786 = from_union(
            [from_str, from_none], obj.get("4b5e6cdc490b659b70c3ba96b42329b8160ea786"))
        cdfed346_dab57160331_db3_a62_e2_fc57_b7_feaf2_e0 = from_union(
            [from_str, from_none], obj.get("cdfed346dab57160331db3a62e2fc57b7feaf2e0"))
        d393_abf7_a1_ac6_b3_c65_df6417_bb9_b0414_a85_f97_bf = from_union(
            [from_str, from_none], obj.get("d393abf7a1ac6b3c65df6417bb9b0414a85f97bf"))
        the_2910377_beb01_f97_d9_fe28_eab9496_bb57_bb9_dc8_df = from_union(
            [from_str, from_none], obj.get("2910377beb01f97d9fe28eab9496bb57bb9dc8df"))
        dad7549768_f1_f3_dc6983_b929_a070342_cbc781_dff = from_union(
            [from_str, from_none], obj.get("dad7549768f1f3dc6983b929a070342cbc781dff"))
        ead484_e350_bb17_f86_d5_f62_e25_e7_ec56_bca64_ec1_c = from_union(
            [from_str, from_none], obj.get("ead484e350bb17f86d5f62e25e7ec56bca64ec1c"))
        the_5_f1_baa0803_ba4628_f58585_b9_fda8_c4_fbb31_b2770 = from_union(
            [from_str, from_none], obj.get("5f1baa0803ba4628f58585b9fda8c4fbb31b2770"))
        aa0_a64_ad2_c219940_a19_e23_c25_d74_e60_f7_a77_b8_e9 = from_union(
            [from_str, from_none], obj.get("aa0a64ad2c219940a19e23c25d74e60f7a77b8e9"))
        de3_d308_ce0_f48_c7897296_d347_e79_ad3_d54_c0_c72_b = from_union(
            [from_str, from_none], obj.get("de3d308ce0f48c7897296d347e79ad3d54c0c72b"))
        return OutputFiles(the_18_d6_d5_df38_d49248823_d00_a9_d135_fdf8821_dd866, the_6_dc51_fc88_ac543_be1_ea0_e9_ba3_eee189_c5_cd8_b988, ba0805_c0_bcda49_ed1_ed64_bbc6614_da479_d93932_b, the_5_de085_ef7394340491_afe01257_f9_a33_b6_d02_c654, the_87_fd68586_b9_bdb49_fa224_f12077_d8_e72277_da485, be330415341_c60_d015369_ac968_cd2_ecbe20_b47_f6, the_138826_a29_de8962_b475_db99_d3_d1145_d57209_a7_f6, the_844_aec88_a3_d9569_bf8_a80_bbc6_e1_c6_ec3_b92_edceb, d7_e71912_bb93_cad3_cac0_ec61_b4271458830_a8967, e3_f7586_c5_d5820_e39149404_cd6_b0_ce510_b752538, the_020343674_b8_b29_f760691_a336_b7_a25_c4_a19116_c2, the_1_b2_e92198_f3_e8_c847_aa97965_aa0_a6_b24_ad8_e34_dc, e7793822_ff314_b58_f30_c86_c1043_b401636_ff3_f4_e, the_7_b3711_b197499_f261_e9_b38_d941_fc9_e1_e43_dd8262, a4_f87379_f9_fe697_b7_e1_ece9_ca7_a150_f30_dfcc49_f, f4_b6_c7_bba7_fb6_d58441_cb6365_dc11440_b6252823, the_0_b23_ca630_e0_d50_b6_a263_c0857_c8_a8_d1178_e4727_d, d4_da6_dbb8_ff5_ba8_e99_c319_c20_baafe3_db3_c19_c59, e6_d0890_ddc13_f1_d8_e57_b23_c8_f1_d764_ce6_c1_bf2_cc, the_2_d26_f4_a43_efed7_f0_a8_f892629_a9_fa6_d92_f5_b780_c, the_309785_a720_d16975_b497_b3_a8_e91783_f25_fde21_e3, the_696292_b64_c7_b0_a431_ba26_c1_d28_a853712257_b32_d, the_301_a3_d58_a6_b07542_adbc4_dbbe795_d3_ad159_b4_bc1, the_39118_cd4_e47_a52_a41_f0_f4_d798_fc43645_f0_c2_db31, the_54_ad816_c0186_bca851_b0_af234431857169_d15_c1_d, cff89_d2_fdc6_a2_ab68671_f0_ae5_e632417_dea9_b39_f, e55_ed01_a52255_de2_f9_ad019_b320_fb97_c18576_a7_a, the_238987_c7313_c79_aa7_e7_d7_a4693_dbedcd7_f9_e16_f2, c0_a2233154_cd1_e7756_f3_a8_f8_f6_c49931_a13_d9_caf, dc0_bd4774598_c9_cb5_bdd5_d26_a1_c8_bc02_eedda7_fb, the_230068545_ef50_e942_c9_d81_fc758_ba5_a1564_a6_c89, the_39_ee6_b6854_ff8_b47917188_c12_d5_b424_c5673_cc07, the_8_c34_b480_a3814_bba1478266887_c81_c4_b252_af6_d7, the_4_b5_e6_cdc490_b659_b70_c3_ba96_b42329_b8160_ea786, cdfed346_dab57160331_db3_a62_e2_fc57_b7_feaf2_e0, d393_abf7_a1_ac6_b3_c65_df6417_bb9_b0414_a85_f97_bf, the_2910377_beb01_f97_d9_fe28_eab9496_bb57_bb9_dc8_df, dad7549768_f1_f3_dc6983_b929_a070342_cbc781_dff, ead484_e350_bb17_f86_d5_f62_e25_e7_ec56_bca64_ec1_c, the_5_f1_baa0803_ba4628_f58585_b9_fda8_c4_fbb31_b2770, aa0_a64_ad2_c219940_a19_e23_c25_d74_e60_f7_a77_b8_e9, de3_d308_ce0_f48_c7897296_d347_e79_ad3_d54_c0_c72_b)

    def to_dict(self) -> dict:
        result: dict = {}
        result["18d6d5df38d49248823d00a9d135fdf8821dd866"] = from_union(
            [from_str, from_none], self.the_18_d6_d5_df38_d49248823_d00_a9_d135_fdf8821_dd866)
        result["6dc51fc88ac543be1ea0e9ba3eee189c5cd8b988"] = from_union(
            [from_str, from_none], self.the_6_dc51_fc88_ac543_be1_ea0_e9_ba3_eee189_c5_cd8_b988)
        result["ba0805c0bcda49ed1ed64bbc6614da479d93932b"] = from_union(
            [from_str, from_none], self.ba0805_c0_bcda49_ed1_ed64_bbc6614_da479_d93932_b)
        result["5de085ef7394340491afe01257f9a33b6d02c654"] = from_union(
            [from_str, from_none], self.the_5_de085_ef7394340491_afe01257_f9_a33_b6_d02_c654)
        result["87fd68586b9bdb49fa224f12077d8e72277da485"] = from_union(
            [from_str, from_none], self.the_87_fd68586_b9_bdb49_fa224_f12077_d8_e72277_da485)
        result["be330415341c60d015369ac968cd2ecbe20b47f6"] = from_union(
            [from_str, from_none], self.be330415341_c60_d015369_ac968_cd2_ecbe20_b47_f6)
        result["138826a29de8962b475db99d3d1145d57209a7f6"] = from_union(
            [from_str, from_none], self.the_138826_a29_de8962_b475_db99_d3_d1145_d57209_a7_f6)
        result["844aec88a3d9569bf8a80bbc6e1c6ec3b92edceb"] = from_union(
            [from_str, from_none], self.the_844_aec88_a3_d9569_bf8_a80_bbc6_e1_c6_ec3_b92_edceb)
        result["d7e71912bb93cad3cac0ec61b4271458830a8967"] = from_union(
            [from_str, from_none], self.d7_e71912_bb93_cad3_cac0_ec61_b4271458830_a8967)
        result["e3f7586c5d5820e39149404cd6b0ce510b752538"] = from_union(
            [from_str, from_none], self.e3_f7586_c5_d5820_e39149404_cd6_b0_ce510_b752538)
        result["020343674b8b29f760691a336b7a25c4a19116c2"] = from_union(
            [from_str, from_none], self.the_020343674_b8_b29_f760691_a336_b7_a25_c4_a19116_c2)
        result["1b2e92198f3e8c847aa97965aa0a6b24ad8e34dc"] = from_union(
            [from_str, from_none], self.the_1_b2_e92198_f3_e8_c847_aa97965_aa0_a6_b24_ad8_e34_dc)
        result["e7793822ff314b58f30c86c1043b401636ff3f4e"] = from_union(
            [from_str, from_none], self.e7793822_ff314_b58_f30_c86_c1043_b401636_ff3_f4_e)
        result["7b3711b197499f261e9b38d941fc9e1e43dd8262"] = from_union(
            [from_str, from_none], self.the_7_b3711_b197499_f261_e9_b38_d941_fc9_e1_e43_dd8262)
        result["a4f87379f9fe697b7e1ece9ca7a150f30dfcc49f"] = from_union(
            [from_str, from_none], self.a4_f87379_f9_fe697_b7_e1_ece9_ca7_a150_f30_dfcc49_f)
        result["f4b6c7bba7fb6d58441cb6365dc11440b6252823"] = from_union(
            [from_str, from_none], self.f4_b6_c7_bba7_fb6_d58441_cb6365_dc11440_b6252823)
        result["0b23ca630e0d50b6a263c0857c8a8d1178e4727d"] = from_union(
            [from_str, from_none], self.the_0_b23_ca630_e0_d50_b6_a263_c0857_c8_a8_d1178_e4727_d)
        result["d4da6dbb8ff5ba8e99c319c20baafe3db3c19c59"] = from_union(
            [from_str, from_none], self.d4_da6_dbb8_ff5_ba8_e99_c319_c20_baafe3_db3_c19_c59)
        result["e6d0890ddc13f1d8e57b23c8f1d764ce6c1bf2cc"] = from_union(
            [from_str, from_none], self.e6_d0890_ddc13_f1_d8_e57_b23_c8_f1_d764_ce6_c1_bf2_cc)
        result["2d26f4a43efed7f0a8f892629a9fa6d92f5b780c"] = from_union(
            [from_str, from_none], self.the_2_d26_f4_a43_efed7_f0_a8_f892629_a9_fa6_d92_f5_b780_c)
        result["309785a720d16975b497b3a8e91783f25fde21e3"] = from_union(
            [from_str, from_none], self.the_309785_a720_d16975_b497_b3_a8_e91783_f25_fde21_e3)
        result["696292b64c7b0a431ba26c1d28a853712257b32d"] = from_union(
            [from_str, from_none], self.the_696292_b64_c7_b0_a431_ba26_c1_d28_a853712257_b32_d)
        result["301a3d58a6b07542adbc4dbbe795d3ad159b4bc1"] = from_union(
            [from_str, from_none], self.the_301_a3_d58_a6_b07542_adbc4_dbbe795_d3_ad159_b4_bc1)
        result["39118cd4e47a52a41f0f4d798fc43645f0c2db31"] = from_union(
            [from_str, from_none], self.the_39118_cd4_e47_a52_a41_f0_f4_d798_fc43645_f0_c2_db31)
        result["54ad816c0186bca851b0af234431857169d15c1d"] = from_union(
            [from_str, from_none], self.the_54_ad816_c0186_bca851_b0_af234431857169_d15_c1_d)
        result["cff89d2fdc6a2ab68671f0ae5e632417dea9b39f"] = from_union(
            [from_str, from_none], self.cff89_d2_fdc6_a2_ab68671_f0_ae5_e632417_dea9_b39_f)
        result["e55ed01a52255de2f9ad019b320fb97c18576a7a"] = from_union(
            [from_str, from_none], self.e55_ed01_a52255_de2_f9_ad019_b320_fb97_c18576_a7_a)
        result["238987c7313c79aa7e7d7a4693dbedcd7f9e16f2"] = from_union(
            [from_str, from_none], self.the_238987_c7313_c79_aa7_e7_d7_a4693_dbedcd7_f9_e16_f2)
        result["c0a2233154cd1e7756f3a8f8f6c49931a13d9caf"] = from_union(
            [from_str, from_none], self.c0_a2233154_cd1_e7756_f3_a8_f8_f6_c49931_a13_d9_caf)
        result["dc0bd4774598c9cb5bdd5d26a1c8bc02eedda7fb"] = from_union(
            [from_str, from_none], self.dc0_bd4774598_c9_cb5_bdd5_d26_a1_c8_bc02_eedda7_fb)
        result["230068545ef50e942c9d81fc758ba5a1564a6c89"] = from_union(
            [from_str, from_none], self.the_230068545_ef50_e942_c9_d81_fc758_ba5_a1564_a6_c89)
        result["39ee6b6854ff8b47917188c12d5b424c5673cc07"] = from_union(
            [from_str, from_none], self.the_39_ee6_b6854_ff8_b47917188_c12_d5_b424_c5673_cc07)
        result["8c34b480a3814bba1478266887c81c4b252af6d7"] = from_union(
            [from_str, from_none], self.the_8_c34_b480_a3814_bba1478266887_c81_c4_b252_af6_d7)
        result["4b5e6cdc490b659b70c3ba96b42329b8160ea786"] = from_union(
            [from_str, from_none], self.the_4_b5_e6_cdc490_b659_b70_c3_ba96_b42329_b8160_ea786)
        result["cdfed346dab57160331db3a62e2fc57b7feaf2e0"] = from_union(
            [from_str, from_none], self.cdfed346_dab57160331_db3_a62_e2_fc57_b7_feaf2_e0)
        result["d393abf7a1ac6b3c65df6417bb9b0414a85f97bf"] = from_union(
            [from_str, from_none], self.d393_abf7_a1_ac6_b3_c65_df6417_bb9_b0414_a85_f97_bf)
        result["2910377beb01f97d9fe28eab9496bb57bb9dc8df"] = from_union(
            [from_str, from_none], self.the_2910377_beb01_f97_d9_fe28_eab9496_bb57_bb9_dc8_df)
        result["dad7549768f1f3dc6983b929a070342cbc781dff"] = from_union(
            [from_str, from_none], self.dad7549768_f1_f3_dc6983_b929_a070342_cbc781_dff)
        result["ead484e350bb17f86d5f62e25e7ec56bca64ec1c"] = from_union(
            [from_str, from_none], self.ead484_e350_bb17_f86_d5_f62_e25_e7_ec56_bca64_ec1_c)
        result["5f1baa0803ba4628f58585b9fda8c4fbb31b2770"] = from_union(
            [from_str, from_none], self.the_5_f1_baa0803_ba4628_f58585_b9_fda8_c4_fbb31_b2770)
        result["aa0a64ad2c219940a19e23c25d74e60f7a77b8e9"] = from_union(
            [from_str, from_none], self.aa0_a64_ad2_c219940_a19_e23_c25_d74_e60_f7_a77_b8_e9)
        result["de3d308ce0f48c7897296d347e79ad3d54c0c72b"] = from_union(
            [from_str, from_none], self.de3_d308_ce0_f48_c7897296_d347_e79_ad3_d54_c0_c72_b)
        return result


class FluffyRuleiovalues:
    inputs: Optional[Inputs]
    outputs: Optional[Outputs]
    output_files: Optional[OutputFiles]

    def __init__(self, inputs: Optional[Inputs], outputs: Optional[Outputs], output_files: Optional[OutputFiles]) -> None:
        self.inputs = inputs
        self.outputs = outputs
        self.output_files = output_files

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyRuleiovalues':
        assert isinstance(obj, dict)
        inputs = from_union([Inputs.from_dict, from_none], obj.get("inputs"))
        outputs = from_union(
            [Outputs.from_dict, from_none], obj.get("outputs"))
        output_files = from_union(
            [OutputFiles.from_dict, from_none], obj.get("outputFiles"))
        return FluffyRuleiovalues(inputs, outputs, output_files)

    def to_dict(self) -> dict:
        result: dict = {}
        result["inputs"] = from_union(
            [lambda x: to_class(Inputs, x), from_none], self.inputs)
        result["outputs"] = from_union(
            [lambda x: to_class(Outputs, x), from_none], self.outputs)
        result["outputFiles"] = from_union(
            [lambda x: to_class(OutputFiles, x), from_none], self.output_files)
        return result


class State(Enum):
    COMPLETED = "Completed"


class TaskState:
    completed: Optional[int]

    def __init__(self, completed: Optional[int]) -> None:
        self.completed = completed

    @staticmethod
    def from_dict(obj: Any) -> 'TaskState':
        assert isinstance(obj, dict)
        completed = from_union([from_int, from_none], obj.get("Completed"))
        return TaskState(completed)

    def to_dict(self) -> dict:
        result: dict = {}
        result["Completed"] = from_union([from_int, from_none], self.completed)
        return result


class RuleOutputType(Enum):
    COMPLIANCE = "Compliance"


class RuleSetOutputRuleOutput:
    output_type: Optional[PurpleOutputType]
    type: Optional[RuleOutputType]
    purpose: Optional[str]
    description: Optional[str]
    aliasref: Optional[Aliasref]
    seqno: Optional[int]
    instance_name: Optional[InstanceName]
    object_type: Optional[ObjectType]
    object_guid: Optional[UUID]
    state: Optional[State]
    compliance_status: Optional[ComplianceStatus]
    compliance_pct: Optional[int]
    task_state: Optional[TaskState]
    ruleiovalues: Optional[FluffyRuleiovalues]
    rule_outputs: Optional[List[RuleOutputRuleOutput]]

    def __init__(self, output_type: Optional[PurpleOutputType], type: Optional[RuleOutputType], purpose: Optional[str], description: Optional[str], aliasref: Optional[Aliasref], seqno: Optional[int], instance_name: Optional[InstanceName], object_type: Optional[ObjectType], object_guid: Optional[UUID], state: Optional[State], compliance_status: Optional[ComplianceStatus], compliance_pct: Optional[int], task_state: Optional[TaskState], ruleiovalues: Optional[FluffyRuleiovalues], rule_outputs: Optional[List[RuleOutputRuleOutput]]) -> None:
        self.output_type = output_type
        self.type = type
        self.purpose = purpose
        self.description = description
        self.aliasref = aliasref
        self.seqno = seqno
        self.instance_name = instance_name
        self.object_type = object_type
        self.object_guid = object_guid
        self.state = state
        self.compliance_status = compliance_status
        self.compliance_pct = compliance_pct
        self.task_state = task_state
        self.ruleiovalues = ruleiovalues
        self.rule_outputs = rule_outputs

    @staticmethod
    def from_dict(obj: Any) -> 'RuleSetOutputRuleOutput':
        assert isinstance(obj, dict)
        output_type = from_union(
            [PurpleOutputType, from_none], obj.get("outputType"))
        type = from_union([RuleOutputType, from_none], obj.get("type"))
        purpose = from_union([from_str, from_none], obj.get("purpose"))
        description = from_union([from_str, from_none], obj.get("description"))
        aliasref = from_union([Aliasref, from_none], obj.get("aliasref"))
        seqno = from_union([from_int, from_none], obj.get("seqno"))
        instance_name = from_union(
            [InstanceName, from_none], obj.get("instanceName"))
        object_type = from_union(
            [ObjectType, from_none], obj.get("objectType"))
        object_guid = from_union(
            [lambda x: UUID(x), from_none], obj.get("objectGUID"))
        state = from_union([State, from_none], obj.get("state"))
        compliance_status = from_union(
            [ComplianceStatus, from_none], obj.get("complianceStatus"))
        compliance_pct = from_union(
            [from_int, from_none], obj.get("compliancePCT"))
        task_state = from_union(
            [TaskState.from_dict, from_none], obj.get("taskState"))
        ruleiovalues = from_union(
            [FluffyRuleiovalues.from_dict, from_none], obj.get("ruleiovalues"))
        rule_outputs = from_union([lambda x: from_list(
            RuleOutputRuleOutput.from_dict, x), from_none], obj.get("ruleOutputs"))
        return RuleSetOutputRuleOutput(output_type, type, purpose, description, aliasref, seqno, instance_name, object_type, object_guid, state, compliance_status, compliance_pct, task_state, ruleiovalues, rule_outputs)

    def to_dict(self) -> dict:
        result: dict = {}
        result["outputType"] = from_union(
            [lambda x: to_enum(PurpleOutputType, x), from_none], self.output_type)
        result["type"] = from_union(
            [lambda x: to_enum(RuleOutputType, x), from_none], self.type)
        result["purpose"] = from_union([from_str, from_none], self.purpose)
        result["description"] = from_union(
            [from_str, from_none], self.description)
        result["aliasref"] = from_union(
            [lambda x: to_enum(Aliasref, x), from_none], self.aliasref)
        result["seqno"] = from_union([from_int, from_none], self.seqno)
        result["instanceName"] = from_union(
            [lambda x: to_enum(InstanceName, x), from_none], self.instance_name)
        result["objectType"] = from_union(
            [lambda x: to_enum(ObjectType, x), from_none], self.object_type)
        result["objectGUID"] = from_union(
            [lambda x: str(x), from_none], self.object_guid)
        result["state"] = from_union(
            [lambda x: to_enum(State, x), from_none], self.state)
        result["complianceStatus"] = from_union(
            [lambda x: to_enum(ComplianceStatus, x), from_none], self.compliance_status)
        result["compliancePCT"] = from_union(
            [from_int, from_none], self.compliance_pct)
        result["taskState"] = from_union(
            [lambda x: to_class(TaskState, x), from_none], self.task_state)
        result["ruleiovalues"] = from_union(
            [lambda x: to_class(FluffyRuleiovalues, x), from_none], self.ruleiovalues)
        result["ruleOutputs"] = from_union([lambda x: from_list(
            lambda x: to_class(RuleOutputRuleOutput, x), x), from_none], self.rule_outputs)
        return result


class RuleSetOutput:
    state: Optional[State]
    compliance_status: Optional[ComplianceStatus]
    compliance_pct: Optional[int]
    type: Optional[RuleOutputType]
    rule_outputs: Optional[List[RuleSetOutputRuleOutput]]

    def __init__(self, state: Optional[State], compliance_status: Optional[ComplianceStatus], compliance_pct: Optional[int], type: Optional[RuleOutputType], rule_outputs: Optional[List[RuleSetOutputRuleOutput]]) -> None:
        self.state = state
        self.compliance_status = compliance_status
        self.compliance_pct = compliance_pct
        self.type = type
        self.rule_outputs = rule_outputs

    @staticmethod
    def from_dict(obj: Any) -> 'RuleSetOutput':
        assert isinstance(obj, dict)
        state = from_union([State, from_none], obj.get("state"))
        compliance_status = from_union(
            [ComplianceStatus, from_none], obj.get("complianceStatus"))
        compliance_pct = from_union(
            [from_int, from_none], obj.get("compliancePCT"))
        type = from_union([RuleOutputType, from_none], obj.get("type"))
        rule_outputs = from_union([lambda x: from_list(
            RuleSetOutputRuleOutput.from_dict, x), from_none], obj.get("ruleOutputs"))
        return RuleSetOutput(state, compliance_status, compliance_pct, type, rule_outputs)

    def to_dict(self) -> dict:
        result: dict = {}
        result["state"] = from_union(
            [lambda x: to_enum(State, x), from_none], self.state)
        result["complianceStatus"] = from_union(
            [lambda x: to_enum(ComplianceStatus, x), from_none], self.compliance_status)
        result["compliancePCT"] = from_union(
            [from_int, from_none], self.compliance_pct)
        result["type"] = from_union(
            [lambda x: to_enum(RuleOutputType, x), from_none], self.type)
        result["ruleOutputs"] = from_union([lambda x: from_list(lambda x: to_class(
            RuleSetOutputRuleOutput, x), x), from_none], self.rule_outputs)
        return result


class Tag:
    pass

    def __init__(self, ) -> None:
        pass

    @staticmethod
    def from_dict(obj: Any) -> 'Tag':
        assert isinstance(obj, dict)
        return Tag()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


class Control:
    id: Optional[UUID]
    control_id: Optional[UUID]
    alias: Optional[str]
    plan_execution_id: Optional[UUID]
    execution_status: Optional[int]
    compliance_status: Optional[ComplianceStatus]
    rule_set_guid: Optional[UUID]
    rule_set: Optional[RuleSet]
    control_status: Optional[ControlStatus]
    rule_set_output: Optional[RuleSetOutput]
    tag: Optional[Tag]
    control_type: Optional[ControlType]
    depended_control_inputs: Optional[List[DependedControlInput]]
    depends_on: Optional[List[UUID]]

    def __init__(self, id: Optional[UUID], control_id: Optional[UUID], alias: Optional[str], plan_execution_id: Optional[UUID], execution_status: Optional[int], compliance_status: Optional[ComplianceStatus], rule_set_guid: Optional[UUID], rule_set: Optional[RuleSet], control_status: Optional[ControlStatus], rule_set_output: Optional[RuleSetOutput], tag: Optional[Tag], control_type: Optional[ControlType], depended_control_inputs: Optional[List[DependedControlInput]], depends_on: Optional[List[UUID]]) -> None:
        self.id = id
        self.control_id = control_id
        self.alias = alias
        self.plan_execution_id = plan_execution_id
        self.execution_status = execution_status
        self.compliance_status = compliance_status
        self.rule_set_guid = rule_set_guid
        self.rule_set = rule_set
        self.control_status = control_status
        self.rule_set_output = rule_set_output
        self.tag = tag
        self.control_type = control_type
        self.depended_control_inputs = depended_control_inputs
        self.depends_on = depends_on

    @staticmethod
    def from_dict(obj: Any) -> 'Control':
        assert isinstance(obj, dict)
        id = from_union([lambda x: UUID(x), from_none], obj.get("ID"))
        control_id = from_union(
            [lambda x: UUID(x), from_none], obj.get("ControlID"))
        alias = from_union([from_str, from_none], obj.get("Alias"))
        plan_execution_id = from_union(
            [lambda x: UUID(x), from_none], obj.get("PlanExecutionID"))
        execution_status = from_union(
            [from_none, lambda x: int(from_str(x))], obj.get("ExecutionStatus"))
        compliance_status = from_union(
            [ComplianceStatus, from_none], obj.get("ComplianceStatus"))
        rule_set_guid = from_union(
            [lambda x: UUID(x), from_none], obj.get("RuleSetGUID"))
        rule_set = from_union(
            [RuleSet.from_dict, from_none], obj.get("RuleSet"))
        control_status = from_union(
            [ControlStatus.from_dict, from_none], obj.get("ControlStatus"))
        rule_set_output = from_union(
            [RuleSetOutput.from_dict, from_none], obj.get("RuleSetOutput"))
        tag = from_union([Tag.from_dict, from_none], obj.get("Tag"))
        control_type = from_union(
            [ControlType, from_none], obj.get("controlType"))
        depended_control_inputs = from_union([lambda x: from_list(
            DependedControlInput.from_dict, x), from_none], obj.get("dependedControlInputs"))
        depends_on = from_union([lambda x: from_list(
            lambda x: UUID(x), x), from_none], obj.get("dependsOn"))
        return Control(id, control_id, alias, plan_execution_id, execution_status, compliance_status, rule_set_guid, rule_set, control_status, rule_set_output, tag, control_type, depended_control_inputs, depends_on)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ID"] = from_union([lambda x: str(x), from_none], self.id)
        result["ControlID"] = from_union(
            [lambda x: str(x), from_none], self.control_id)
        result["Alias"] = from_union([from_str, from_none], self.alias)
        result["PlanExecutionID"] = from_union(
            [lambda x: str(x), from_none], self.plan_execution_id)
        result["ExecutionStatus"] = from_union([lambda x: from_none((lambda x: is_type(type(None), x))(
            x)), lambda x: from_str((lambda x: str((lambda x: is_type(int, x))(x)))(x))], self.execution_status)
        result["ComplianceStatus"] = from_union(
            [lambda x: to_enum(ComplianceStatus, x), from_none], self.compliance_status)
        result["RuleSetGUID"] = from_union(
            [lambda x: str(x), from_none], self.rule_set_guid)
        result["RuleSet"] = from_union(
            [lambda x: to_class(RuleSet, x), from_none], self.rule_set)
        result["ControlStatus"] = from_union(
            [lambda x: to_class(ControlStatus, x), from_none], self.control_status)
        result["RuleSetOutput"] = from_union(
            [lambda x: to_class(RuleSetOutput, x), from_none], self.rule_set_output)
        result["Tag"] = from_union(
            [lambda x: to_class(Tag, x), from_none], self.tag)
        result["controlType"] = from_union(
            [lambda x: to_enum(ControlType, x), from_none], self.control_type)
        result["dependedControlInputs"] = from_union([lambda x: from_list(lambda x: to_class(
            DependedControlInput, x), x), from_none], self.depended_control_inputs)
        result["dependsOn"] = from_union([lambda x: from_list(
            lambda x: str(x), x), from_none], self.depends_on)
        return result


class Tags:
    group: Optional[List[str]]
    plan_run_config: Optional[List[str]]
    plan_run_name: Optional[List[str]]

    def __init__(self, group: Optional[List[str]], plan_run_config: Optional[List[str]], plan_run_name: Optional[List[str]]) -> None:
        self.group = group
        self.plan_run_config = plan_run_config
        self.plan_run_name = plan_run_name

    @staticmethod
    def from_dict(obj: Any) -> 'Tags':
        assert isinstance(obj, dict)
        group = from_union([lambda x: from_list(
            from_str, x), from_none], obj.get("Group"))
        plan_run_config = from_union([lambda x: from_list(
            from_str, x), from_none], obj.get("PlanRunConfig"))
        plan_run_name = from_union([lambda x: from_list(
            from_str, x), from_none], obj.get("PlanRunName"))
        return Tags(group, plan_run_config, plan_run_name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["Group"] = from_union(
            [lambda x: from_list(from_str, x), from_none], self.group)
        result["PlanRunConfig"] = from_union(
            [lambda x: from_list(from_str, x), from_none], self.plan_run_config)
        result["PlanRunName"] = from_union(
            [lambda x: from_list(from_str, x), from_none], self.plan_run_name)
        return result


class RuleEnginePlanRun:
    id: Optional[UUID]
    plan_id: Optional[UUID]
    user_id: Optional[UUID]
    domain_id: Optional[UUID]
    org_id: Optional[UUID]
    group_id: Optional[UUID]
    audit_from_date: Optional[datetime]
    audit_to_date: Optional[datetime]
    application_scope_id: Optional[UUID]
    plan_name: Optional[str]
    framework: Optional[str]
    plan_created_by: Optional[str]
    controls: Optional[List[Control]]
    api_callback: Optional[APICallback]
    status: Optional[int]
    tags: Optional[Tags]
    created_at: Optional[datetime]
    compliance_status: Optional[ComplianceStatus]

    def __init__(self, id: Optional[UUID], plan_id: Optional[UUID], user_id: Optional[UUID], domain_id: Optional[UUID], org_id: Optional[UUID], group_id: Optional[UUID], audit_from_date: Optional[datetime], audit_to_date: Optional[datetime], application_scope_id: Optional[UUID], plan_name: Optional[str], framework: Optional[str], plan_created_by: Optional[str], controls: Optional[List[Control]], api_callback: Optional[APICallback], status: Optional[int], tags: Optional[Tags], created_at: Optional[datetime], compliance_status: Optional[ComplianceStatus]) -> None:
        self.id = id
        self.plan_id = plan_id
        self.user_id = user_id
        self.domain_id = domain_id
        self.org_id = org_id
        self.group_id = group_id
        self.audit_from_date = audit_from_date
        self.audit_to_date = audit_to_date
        self.application_scope_id = application_scope_id
        self.plan_name = plan_name
        self.framework = framework
        self.plan_created_by = plan_created_by
        self.controls = controls
        self.api_callback = api_callback
        self.status = status
        self.tags = tags
        self.created_at = created_at
        self.compliance_status = compliance_status

    @staticmethod
    def from_dict(obj: Any) -> 'RuleEnginePlanRun':
        assert isinstance(obj, dict)
        id = from_union([lambda x: UUID(x), from_none], obj.get("ID"))
        plan_id = from_union([lambda x: UUID(x), from_none], obj.get("PlanID"))
        user_id = from_union([lambda x: UUID(x), from_none], obj.get("UserID"))
        domain_id = from_union(
            [lambda x: UUID(x), from_none], obj.get("domainId"))
        org_id = from_union([lambda x: UUID(x), from_none], obj.get("orgId"))
        group_id = from_union(
            [lambda x: UUID(x), from_none], obj.get("groupId"))
        audit_from_date = from_union(
            [from_datetime, from_none], obj.get("AuditFromDate"))
        audit_to_date = from_union(
            [from_datetime, from_none], obj.get("AuditToDate"))
        application_scope_id = from_union(
            [lambda x: UUID(x), from_none], obj.get("ApplicationScopeID"))
        plan_name = from_union([from_str, from_none], obj.get("PlanName"))
        framework = from_union([from_str, from_none], obj.get("Framework"))
        plan_created_by = from_union(
            [from_str, from_none], obj.get("PlanCreatedBy"))
        controls = from_union([lambda x: from_list(
            Control.from_dict, x), from_none], obj.get("Controls"))
        api_callback = from_union(
            [APICallback.from_dict, from_none], obj.get("apiCallback"))
        status = from_union(
            [from_none, lambda x: int(from_str(x))], obj.get("Status"))
        tags = from_union([Tags.from_dict, from_none], obj.get("tags"))
        created_at = from_union(
            [from_datetime, from_none], obj.get("CreatedAt"))
        compliance_status = from_union(
            [ComplianceStatus, from_none], obj.get("ComplianceStatus"))
        return RuleEnginePlanRun(id, plan_id, user_id, domain_id, org_id, group_id, audit_from_date, audit_to_date, application_scope_id, plan_name, framework, plan_created_by, controls, api_callback, status, tags, created_at, compliance_status)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ID"] = from_union([lambda x: str(x), from_none], self.id)
        result["PlanID"] = from_union(
            [lambda x: str(x), from_none], self.plan_id)
        result["UserID"] = from_union(
            [lambda x: str(x), from_none], self.user_id)
        result["domainId"] = from_union(
            [lambda x: str(x), from_none], self.domain_id)
        result["orgId"] = from_union(
            [lambda x: str(x), from_none], self.org_id)
        result["groupId"] = from_union(
            [lambda x: str(x), from_none], self.group_id)
        result["AuditFromDate"] = from_union(
            [lambda x: x.isoformat(), from_none], self.audit_from_date)
        result["AuditToDate"] = from_union(
            [lambda x: x.isoformat(), from_none], self.audit_to_date)
        result["ApplicationScopeID"] = from_union(
            [lambda x: str(x), from_none], self.application_scope_id)
        result["PlanName"] = from_union([from_str, from_none], self.plan_name)
        result["Framework"] = from_union([from_str, from_none], self.framework)
        result["PlanCreatedBy"] = from_union(
            [from_str, from_none], self.plan_created_by)
        result["Controls"] = from_union([lambda x: from_list(
            lambda x: to_class(Control, x), x), from_none], self.controls)
        result["apiCallback"] = from_union(
            [lambda x: to_class(APICallback, x), from_none], self.api_callback)
        result["Status"] = from_union([lambda x: from_none((lambda x: is_type(type(None), x))(
            x)), lambda x: from_str((lambda x: str((lambda x: is_type(int, x))(x)))(x))], self.status)
        result["tags"] = from_union(
            [lambda x: to_class(Tags, x), from_none], self.tags)
        result["CreatedAt"] = from_union(
            [lambda x: x.isoformat(), from_none], self.created_at)
        result["ComplianceStatus"] = from_union(
            [lambda x: to_enum(ComplianceStatus, x), from_none], self.compliance_status)
        return result


def rule_engine_plan_run_from_dict(s: Any) -> RuleEnginePlanRun:
    return RuleEnginePlanRun.from_dict(s)


def rule_engine_plan_run_to_dict(x: RuleEnginePlanRun) -> Any:
    return to_class(RuleEnginePlanRun, x)
