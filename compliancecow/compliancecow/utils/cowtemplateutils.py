import os
from jinja2 import Template


def fetchfileastemplate(file_name):
    filepath = "cowreportssengine"+os.sep+"cowreports"+os.sep+file_name
    template = None

    if filepath and os.path.exists(filepath) and os.path.isfile(filepath):
        with open(filepath, 'r') as f:
            template = Template(f.read())
    return template
