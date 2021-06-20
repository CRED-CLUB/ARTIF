import os
import sys
import time
import yaml
from pathlib import Path

from pymongo import MongoClient

p = Path(__file__).parents[1]
sys.path.append(str(p))

from feed_ingestor import update_check
from database_connector import mongo_update

def to_update():
    config = open(f"{p}/config.yaml")
    parsed_yaml_file = yaml.load(config, Loader=yaml.FullLoader)
    os.environ['MISP_URL'] = parsed_yaml_file['credentials']['MISP_URL']
    os.environ['MISP_KEY'] = parsed_yaml_file['credentials']['MISP_KEY']
    config.close()

    print("Starting update")
    mongo_update.clean_ip()
    print("Reading setting.yaml to download feeds")
    update_check.check()
    #else:
    print("Adding IP")
    update_check.add_ip()
    print("Done updating")

def clear_history():
    config = open(f"{p}/config.yaml")
    parsed_yaml_file = yaml.load(config, Loader=yaml.FullLoader)
    os.environ['MISP_URL'] = parsed_yaml_file['credentials']['MISP_URL']
    os.environ['MISP_KEY'] = parsed_yaml_file['credentials']['MISP_KEY']
    config.close()

    print("[+] Clearing history_ip")
    db = os.environ.get('MONGO_DB', default='misp_feed')
    client = MongoClient('mongodb://root:rootpassword@localhost:27017/?authSource=admin')
    ip_info_db = client['ip_info']
    ip_info_db.history_ip.remove({})
    print("[+] Old IP cleared")
