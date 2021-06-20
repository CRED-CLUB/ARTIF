import os
import yaml
import hashlib
import importlib
import sys
import argparse
from time import sleep
from pathlib import Path

from pymongo import MongoClient

from feed import mainCaller
from database_connector import mongo_update
from front_end_scorer import pre_scorer

try:
    p = Path(__file__).parents[1]
    sys.path.append(str(p))
except IndexError:
    print("[!] Error: Use full path of the file")
    sys.exit(1)

def check():
    print("[+] Parsing settings.yaml to get feeds")
    fil = os.environ.get("CONFIG_FILE", default="settings.yaml")
    db = os.environ.get("MONGO_DB", default="misp_feed")
    client = MongoClient(
        "mongodb://root:password@localhost:27017/?authSource=admin"
    )
    all_dbs = client.list_database_names()
    if db in all_dbs:
        database = client[db]
        filename=str(Path(__file__).parents[1])+"/feed_ingestor/"+fil
        old_file = database.file.find_one({"filename": filename})
        if str(old_file["hash"]) != str(
            hashlib.md5(open(str(filename), "rb").read()).hexdigest()
        ):
            feed_updater = mainCaller()
            feed_list, event_list = feed_updater.update_misp(
                filename=str(filename),
                include_event_tags=False
            )
            # We add try except blocks here so that if function errors out,we need to basically pass. Next minute it will be called anyways and by then probably the feed must be indexed in misp as an event with all attributes and cached
            feed_list, event_list = feed_updater.update_file(
                filename=str(filename)
            )  
            # no feed_list and event_list is passed (basically errors out, then this is not called)
            mongo_update.update_feed(
                feed_list=feed_list, event_list=event_list
            )  
            # if no feed_list and event_list is passed (basically errors out, then this is not called). Error out means the event does not have all attributes.
            old_file["hash"] = str(
                hashlib.md5(open(str(filename), "rb").read()).hexdigest()
            )
            database.file.replace_one(
                filter={"_id": old_file["_id"]}, replacement=old_file
            )
        else:
            feed_updater = mainCaller()
            feed_list, event_list = feed_updater.update_file(filename=str(filename),include_event_tags=False)
            mongo_update.update_feed(feed_list=feed_list, event_list=event_list)
            old_file["hash"] = str(
                hashlib.md5(open(str(filename), "rb").read()).hexdigest()
            )
            database.file.replace_one(
                filter={"_id": old_file["_id"]}, replacement=old_file
            )
    else:
        database = client[db]
        filename=str(Path(__file__).parents[1])+"/feed_ingestor/"+fil
        database.file.insert_one(
            {
                "filename": filename,
                "hash": str(hashlib.md5(open(str(filename), "rb").read()).hexdigest()),
            }
        )
        feed_updater = mainCaller()
        feed_list, event_list = feed_updater.update_misp(filename=str(filename),include_event_tags=False)
        mongo_update.update_feed(feed_list=feed_list, event_list=event_list)
        feed_list = feed_updater.update_file(filename=str(filename))
        sleep(240)
        ip_list = feed_updater.update_attributes()
        mongo_update.add_ip(
            ip_list
        )  
        # Pulls all IPs and their properties into mongodb current.
        print("[+] Scoring engine started")
        print("[+] Loading complete")

def add_ip():
    print("[+] IP address being added to db")
    ip_updater = mainCaller()
    ip_list = ip_updater.update_attributes()
    mongo_update.add_ip(ip_list)
    print("[+] Scoring engine started")
    pre_scorer.score_attributes()
    print("[+] Loading Complete")


if __name__=='__main__':
    arg = argparse.ArgumentParser(description='IP reputation program')
    arg.add_argument('-s', const='start',required=False, help='Required only for the first run',nargs='?')

    config = open(f"{p}/config.yaml")
    parsed_yaml_file = yaml.load(config, Loader=yaml.FullLoader)
    os.environ['MISP_URL'] = parsed_yaml_file['credentials']['MISP_URL']
    os.environ['MISP_KEY'] = parsed_yaml_file['credentials']['MISP_KEY']
    config.close()

    args = arg.parse_args()

    if args.s != None:
        check()
    else:
        add_ip()
