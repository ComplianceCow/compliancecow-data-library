from bokeh.io import export_png
import time
import os
from IPython.display import Image, display
import string
import random

def show(plots):
    if plots and isinstance(plots, list) and len(plots) > 0:
        for i, plot in enumerate(plots):
            res = ''.join(random.choices(string.ascii_lowercase +
                                         string.digits, k=10))
            file_name = str(time.time())+"_"+str(res)+"_"+str(i)+".png"
            export_png(plot, filename=file_name)
            display(Image(file_name))
            os.remove(file_name)
       
