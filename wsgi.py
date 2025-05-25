import sys
import os

project_home = '/home/markclores/simple-banking-app-v2'
if project_home not in sys.path:
    sys.path.append(project_home)

os.environ['FLASK_APP'] = 'app.py'

from app import app as application
