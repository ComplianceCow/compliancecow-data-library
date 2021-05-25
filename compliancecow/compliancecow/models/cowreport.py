from uuid import UUID
from typing import Any, TypeVar, Type, cast, List, Union
from enum import Enum

from compliancecow.utils import constants, dictutils, authutils, utils, wsutils, validateutils


class ReportCategories:
    id: UUID
    name: str

    def __init__(self, id: UUID, name: str) -> None:
        self.id = id
        self.name = name

    @staticmethod
    def from_dict(obj: Any) -> 'ReportCategories':
        report_categories = None
        if isinstance(obj, dict):
            id = name = None
            if dictutils.is_valid_key(obj, "id"):
                id = UUID(obj.get("id"))
            if dictutils.is_valid_key(obj, "name"):
                name = utils.from_str(obj.get("name"))
            report_categories = ReportCategories(id, name)
        return report_categories

    def to_dict(self) -> dict:
        result: dict = {}
        if self.id:
            result["id"] = str(self.id)
        if self.name:
            result["name"] = utils.from_str(self.name)
        return result


def report_categories_from_dict(s: Any) -> ReportCategories:
    return ReportCategories.from_dict(s)


class Dashboard:
    id: UUID
    name: str

    def __init__(self, id: UUID, name: str) -> None:
        self.id = id
        self.name = name

    @staticmethod
    def from_dict(obj: Any) -> 'Dashboard':
        dashboard = None
        if isinstance(obj, dict):
            id = name = None
            if dictutils.is_valid_key(obj, "id"):
                id = UUID(obj.get("id"))
            if dictutils.is_valid_key(obj, "name"):
                name = utils.from_str(obj.get("name"))
            dashboard = Dashboard(id, name)
        return dashboard

    def to_dict(self) -> dict:
        result: dict = {}
        if self.id:
            result["id"] = str(self.id)
        if self.name:
            result["name"] = utils.from_str(self.name)
        return result


def dashboard_from_dict(s: Any) -> Dashboard:
    return Dashboard.from_dict(s)


class Report:
    id: UUID
    name: str
    category_name: str
    category_id: UUID
    plan_ids: List[UUID]
    tags: List[str]

    def __init__(self, id: UUID, name: str, category_name: str, category_id: UUID, plan_ids: List[UUID], tags: List[str]) -> None:
        self.id = id
        self.name = name
        self.category_name = category_name
        self.category_id = category_id
        self.plan_ids = plan_ids
        self.tags = tags

    @staticmethod
    def from_dict(obj: Any) -> 'Report':
        report = None
        if isinstance(obj, dict):
            id = name = category_name = category_id = plan_ids = tags = None
            if dictutils.is_valid_key(obj, "id"):
                id = UUID(obj.get("id"))
            if dictutils.is_valid_key(obj, "name"):
                name = utils.from_str(obj.get("name"))
            if dictutils.is_valid_key(obj, "categoryName"):
                category_name = utils.from_str(obj.get("categoryName"))
            if dictutils.is_valid_key(obj, "categoryId"):
                category_id = UUID(obj.get("categoryId"))
            if dictutils.is_valid_array(obj, "planIds"):
                plan_ids = utils.from_list(
                    lambda x: UUID(x), obj.get("planIds"))
            if dictutils.is_valid_array(obj, "tags"):
                tags = utils.from_list(utils.from_str, obj.get("tags"))
            report = Report(id, name, category_name,
                            category_id, plan_ids, tags)
        return report

    def to_dict(self) -> dict:
        result: dict = {}
        if self.id:
            result["id"] = str(self.id)
        if self.name:
            result["name"] = utils.from_str(self.name)
        if self.category_name:
            result["categoryName"] = utils.from_str(self.category_name)
        if self.category_id:
            result["categoryId"] = str(self.category_id)
        if self.plan_ids:
            result["planIds"] = utils.from_list(
                lambda x: str(x), self.plan_ids)
        if self.tags:
            result["tags"] = utils.from_list(utils.from_str, self.tags)
        return result


def report_from_dict(s: Any) -> Report:
    return Report.from_dict(s)


def report_to_dict(x: Report) -> Any:
    return utils.to_class(Report, x)


class ReportData:
    columns: List[str]
    data: List[dict]

    def __init__(self, columns:  List[str], data: List[dict]) -> None:
        self.columns = columns
        self.data = data

    @staticmethod
    def from_dict(obj: Any) -> 'ReportData':
        report_data = None
        if isinstance(obj, dict):
            columns = data = None
            if dictutils.is_valid_array(obj, "columns"):
                columns = utils.from_list(lambda x: str(x), obj.get("columns"))
            if dictutils.is_valid_array(obj, "data"):
                data = utils.from_list(lambda x: x, obj.get("data"))
            report_data = ReportData(columns, data)
        return report_data

    def to_dict(self) -> dict:
        result: dict = {}
        if self.columns:
            result["columns"] = utils.from_list(utils.from_str, self.columns)
        if self.data:
            result["data"] = self.data
        return result


def report_categories_from_dict(s: Any) -> ReportCategories:
    return ReportCategories.from_dict(s)


class Schema:
    mode: str
    name: str
    type: str
    field_name: str
    field_display_name: str
    is_field_indexed: bool
    is_field_visible: bool
    is_field_visible_for_client: bool
    is_required: bool
    is_repeated: bool
    html_element_type: str
    field_data_type: str
    field_order: int

    def __init__(self, mode: str, name: str, type: str, field_name: str, field_display_name: str, is_field_indexed: bool, is_field_visible: bool, is_field_visible_for_client: bool, is_required: bool, is_repeated: bool, html_element_type: str, field_data_type: str, field_order: int) -> None:
        self.mode = mode
        self.name = name
        self.type = type
        self.field_name = field_name
        self.field_display_name = field_display_name
        self.is_field_indexed = is_field_indexed
        self.is_field_visible = is_field_visible
        self.is_field_visible_for_client = is_field_visible_for_client
        self.is_required = is_required
        self.is_repeated = is_repeated
        self.html_element_type = html_element_type
        self.field_data_type = field_data_type
        self.field_order = field_order

    @staticmethod
    def from_dict(obj: Any) -> 'Schema':
        schema = None
        if isinstance(obj, dict):
            mode = name = type = field_name = field_display_name = is_field_indexed = is_field_visible = is_field_visible_for_client = is_required = is_repeated = html_element_type = field_data_type = field_order = None
            if dictutils.is_valid_key(obj, "mode"):
                mode = utils.from_str(obj.get("mode"))
            if dictutils.is_valid_key(obj, "name"):
                name = utils.from_str(obj.get("name"))
            if dictutils.is_valid_key(obj, "type"):
                type = utils.from_str(obj.get("type"))
            if dictutils.is_valid_key(obj, "fieldName"):
                field_name = utils.from_str(obj.get("fieldName"))
            if dictutils.is_valid_key(obj, "fieldDisplayName"):
                field_display_name = utils.from_str(
                    obj.get("fieldDisplayName"))
            if dictutils.is_valid_key(obj, "isFieldIndexed"):
                is_field_indexed = utils.from_bool(obj.get("isFieldIndexed"))
            if dictutils.is_valid_key(obj, "isFieldVisible"):
                is_field_visible = utils.from_bool(obj.get("isFieldVisible"))
            if dictutils.is_valid_key(obj, "isFieldVisibleForClient"):
                is_field_visible_for_client = utils.from_bool(
                    obj.get("isFieldVisibleForClient"))
            if dictutils.is_valid_key(obj, "isRequired"):
                is_required = utils.from_bool(obj.get("isRequired"))
            if dictutils.is_valid_key(obj, "isRepeated"):
                is_repeated = utils.from_bool(obj.get("isRepeated"))
            if dictutils.is_valid_key(obj, "htmlElementType"):
                html_element_type = utils.from_str(obj.get("htmlElementType"))
            if dictutils.is_valid_key(obj, "fieldDataType"):
                field_data_type = utils.from_str(obj.get("fieldDataType"))
            if dictutils.is_valid_key(obj, "fieldOrder"):
                field_order = utils.from_int(obj.get("fieldOrder"))

            schema = Schema(mode, name, type, field_name, field_display_name, is_field_indexed, is_field_visible,
                            is_field_visible_for_client, is_required, is_repeated, html_element_type, field_data_type, field_order)

        return schema

    def to_dict(self) -> dict:
        result: dict = {}
        if self.mode:
            result["mode"] = utils.from_str(self.mode)
        if self.name:
            result["name"] = utils.from_str(self.name)
        if self.type:
            result["type"] = utils.from_str(self.type)
        if self.field_name:
            result["fieldName"] = utils.from_str(self.field_name)
        if self.field_display_name:
            result["fieldDisplayName"] = utils.from_str(
                self.field_display_name)
        result["isFieldIndexed"] = utils.from_bool(self.is_field_indexed)
        result["isFieldVisible"] = utils.from_bool(self.is_field_visible)
        result["isFieldVisibleForClient"] = utils.from_bool(
            self.is_field_visible_for_client)
        result["isRequired"] = utils.from_bool(self.is_required)
        result["isRepeated"] = utils.from_bool(self.is_repeated)
        if self.html_element_type:
            result["htmlElementType"] = utils.from_str(self.html_element_type)
        if self.field_data_type:
            result["fieldDataType"] = utils.from_str(self.field_data_type)
        result["fieldOrder"] = utils.from_int(self.field_order)
        return result


class ReportSchema:
    schema: List[Schema]

    def __init__(self, schema: List[Schema]) -> None:
        self.schema = schema

    @staticmethod
    def from_dict(obj: Any) -> 'ReportSchema':
        src_schema = None
        if isinstance(obj, dict):
            schema = None
            if dictutils.is_valid_key(obj, "schema"):
                schema = utils.from_list(Schema.from_dict, obj.get("schema"))
            src_schema = ReportSchema(schema)
        return src_schema

    def to_dict(self) -> dict:
        result: dict = {}
        if self.schema:
            result["schema"] = utils.from_list(
                lambda x: utils.to_class(Schema, x), self.schema)
        return result


def report_schema_from_dict(s: Any) -> ReportSchema:
    return ReportSchema.from_dict(s)


def report_schema_to_dict(x: ReportSchema) -> Any:
    return utils.to_class(ReportSchema, x)


class SchemaType(Enum):
    DATA = "data"
    BOKEH = "bokeh"
    SCHEMA = "schema"
    PARQUET = "parquet"
    HTML = "html"
    PDF = "pdf"
    MARKDOWN = "md"
