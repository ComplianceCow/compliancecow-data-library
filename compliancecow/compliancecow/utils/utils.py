from enum import Enum
from uuid import UUID
from typing import Optional, Any, List, TypeVar, Type, Callable, cast
from datetime import datetime
import dateutil.parser
import pandas as pd
import pyarrow.parquet as pq
import base64
import pyarrow as pa

from compliancecow.utils import dictutils
from compliancecow.models import cowreport


T = TypeVar("T")
EnumT = TypeVar("EnumT", bound=Enum)


def from_str(x: Any) -> str:
    assert isinstance(x, str)
    return x


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


def to_enum(c: Type[EnumT], x: Any) -> EnumT:
    assert isinstance(x, c)
    return x.value


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]


def from_int(x: Any) -> int:
    assert isinstance(x, int) and not isinstance(x, bool)
    return x


def from_datetime(x: Any) -> datetime:
    return dateutil.parser.parse(x)


def to_class(c: Type[T], x: Any) -> dict:
    assert isinstance(x, c)
    return cast(Any, x).to_dict()


def from_stringified_bool(x: str) -> bool:
    if x == "true":
        return True
    if x == "false":
        return False
    assert False


def from_bool(x: Any) -> bool:
    assert isinstance(x, bool)
    return x


def fetch_leaf_controls(controls=None, leaf_controls=None, having_evidences=False, having_notes=False, having_attachments=False, having_checklists=False, automated=True):

    if leaf_controls is None:
        leaf_controls = []
    for control in controls:
        if control and control.controls:
            leaf_controls = fetch_leaf_controls(control.controls,
                                                leaf_controls, having_evidences, having_notes, having_attachments, having_checklists, automated)
        else:

            if having_evidences and not control.evidences:
                continue
            if having_notes and not control.notes:
                continue
            if having_attachments and not control.attachments:
                continue
            if having_checklists and not control.check_lists:
                continue

            leaf_controls.append(control)

    return leaf_controls


def fetch_controls_without_hierarchy(plan_instance=None, leaf_controls=None, having_evidences=False, having_notes=False, having_attachments=False, having_checklists=False, automated=True) -> List[Any] or None:
    leaf_controls = None
    if plan_instance and plan_instance.controls:
        leaf_controls = fetch_leaf_controls(plan_instance.controls,
                                            leaf_controls, having_evidences, having_notes, having_attachments, having_checklists, automated)
    return leaf_controls


def fetch_controls(plan_instance=None, leaf_controls=None, having_evidences=False, having_notes=False, having_attachments=False, having_checklists=False, automated=True) -> List[Any] or None:
    controls = None
    if plan_instance and plan_instance.controls:
        for control in plan_instance.controls:
            if control and control.controls:
                leaf_controls = fetch_leaf_controls(control.controls,
                                                    leaf_controls, having_evidences, having_notes, having_attachments, having_checklists, automated)
                if leaf_controls:
                    if controls is None:
                        controls = []
                    controls.append(control)
    return controls


def modify_plan_instances(plan_instances=None):

    if plan_instances:
        for plan_instance in plan_instances:
            add_plan_details_in_elements(
                plan_instance.controls, plan_instance.plan_id, plan_instance.id)


def add_plan_details_in_elements(controls=None, plan_id=None, plan_instance_id=None):
    if controls:
        for control in controls:
            if control and control.controls:
                add_plan_details_in_elements(
                    control.controls, plan_id, plan_instance_id)
            else:
                if control.evidences:
                    for evidence in control.evidences:
                        evidence.plan_id = plan_id
                        evidence.plan_instance_id = plan_instance_id
                        evidence.plan_control_id = control.control_id


def convert_data_to_df(response: cowreport.ReportData) -> pd.DataFrame and dict:
    data = pd.DataFrame()
    errors = None
    if response.data_type and response.data:
        if response.data_type == "json":
            data = pd.DataFrame(response.data)
        elif response.data_type == "parquet":
            data = parquet_bytes_to_df(response.data)
        else:
            errors = {'error': 'Cannot convert into pandas DataFrame'}
    return data, errors


def parquet_bytes_to_df(parquet_bytes):
    message_bytes = base64.b64decode(parquet_bytes)
    reader = pa.BufferReader(message_bytes)
    return pq.read_table(reader).to_pandas()
