from bokeh.resources import CDN
from compliancecow.utils import cowtemplateutils, dictutils
from bokeh.embed import file_html
import io
import base64
import os
import json
from jinja2 import Template
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import numpy as np
import datetime


def getdfasstrencoded(df):
    if not df.empty:
        df = df.replace({np.nan: None})
        f = io.BytesIO()
        if df.index.name != 'index':
            df.reset_index(level=0, inplace=True)
        df.to_parquet(f, index=False, engine='auto', compression='snappy')
        f.seek(0)
        content = f.read()
        return str(base64.b64encode(content), 'utf-8')
    return None


def getdfasdict(df):
    if not df.empty:
        df = df.replace({np.nan: None})
        return df.to_dict(orient='records')
    return None


def getdfasstrencodedjson(df):
    df_json = getdfasdict(df)
    if df_json:
        return json.dumps(df_json).encode('utf-8')
    return None


def findfiledataasbytes(filename=None):
    data = None
    if filename:
        if os.path.isfile(filename):
            with open(filename, 'r') as f:
                data = f.read()
    return data


def findfileandreturnmd(filename=None):
    data = None
    if filename:
        if os.path.isfile(filename):
            with open(filename, 'r') as f:
                data = json.load(f)
    return data


def fetchfileasjinjatemplate(filename=None):
    template = None
    if filename and os.path.exists(filename):
        if os.path.isfile(filename):
            with open(filename, 'r') as f:
                template = Template(f.read())
    return template


def getdatatableview(df):
    dataTableView = None
    if not df.empty:
        df = df.replace({np.nan: None})
        dataTableView = df.to_dict(orient='split')
        dataTableView.pop("index", None)
    return dataTableView


def getdatatableviewasencodedstr(df):
    view = getdatatableview(df)
    if view:
        view = json.dumps(view).encode('utf-8')
    return view


def getdffromencodedstr(encodedstr):
    df = pd.DataFrame()
    if encodedstr:
        message_bytes = base64.b64decode(encodedstr)
        reader = pa.BufferReader(message_bytes)
        df = pq.read_table(reader).to_pandas()
    return df


def buildresult(plot=None, title=None, template=None, file_name=None, template_variables={}):

    html_content = None
    if plot:

        if template is None:
            template = cowtemplateutils.fetchfileastemplate(file_name)

        if template is None:
            return {"error": "Not a valid template"}
        html_content = file_html(plot, CDN, title, template=template,
                                 template_variables=template_variables)

    if html_content is None:
        return None

    return html_content


def dfToMarkDownStr(df, extraMD, beforMD):
    if not df.index.name == 'type':
        df.set_index(df.columns[0], inplace=True)
    dfMD = df.to_markdown()

    if beforMD:
        dfMD = beforMD + '\n' + dfMD
    if extraMD:
        md = '\n'.join(extraMD)
        dfMD += '\n'+md

    return strToBase64(dfMD)


def strToBase64(val):
    encoded = base64.b64encode(val.encode("utf-8"))
    return str(encoded, "utf-8")


def findfileandloadjson(filename=None):
    data = None
    if filename:
        if os.path.isfile(filename):
            with open(filename, 'r') as f:
                data = json.load(f)
    return data


def findfileandloadjs(filename=None):
    data = None
    if filename:
        if os.path.isfile(filename):
            with open(filename, 'r') as f:
                data = f.read()
    return data


def dataframetodictionarserializer(obj):
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    if isinstance(obj, pd.Timestamp):
        return obj.to_pydatetime()
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()

    raise TypeError('Not serializable')


def fetchleafcontrolsfromplaninstance(controls=None, leafcontrols=None):
    if leafcontrols is None:
        leafcontrols = []

    if controls:
        for control in controls:
            if 'controls' in control:
                fetchleafcontrolsfromplaninstance(
                    control['controls'], leafcontrols)
            else:
                if 'leafControl' in control and control['leafControl']:
                    leafcontrols.append(control)

    return leafcontrols


def fetchleafcontrolsfromplan(controls=None, leafcontrols=None):
    if leafcontrols is None:
        leafcontrols = []

    if controls:
        for control in controls:
            if 'planControls' in control:
                fetchleafcontrolsfromplan(
                    control['planControls'], leafcontrols)
            else:
                if 'leafControl' in control and control['leafControl']:
                    leafcontrols.append(control)

    return leafcontrols
