import os
import sys
import requests
import numpy as np
import time
from datetime import datetime
from pathlib import Path

from pymongo import MongoClient
from pymongo import ReplaceOne, DeleteOne

p = Path(__file__).parents[1]
sys.path.append(str(p))

import feed_ingestor.feed
import feed_ingestor.listing


def update_feed(**kwargs):
    # Make a feed table by url and a corresponding event table to store events by name
    db = os.environ.get("MONGO_DB", default="misp_feed")
    client = MongoClient(
        "mongodb://root:rootpassword@localhost:27017/?authSource=admin"
    )
    misp_feed_db = client[db]
    collection = misp_feed_db.list_collection_names()
    if "feed" in collection:
        misp_feeds = kwargs["feed_list"]
        misp_events = kwargs["event_list"]
        current_feeds = list(misp_feed_db.feed.find({}))
        current_events = list(misp_feed_db.event.find({}))
        new_feeds = []
        old_feeds = []
        new_events = []
        old_events = []
        delete_feeds = []
        delete_events = []
        misp_feed_keys = list(misp_feeds.keys())
        misp_event_keys = list(misp_events.keys())
        for feed in current_feeds:
            if (
                feed["url"] in misp_feed_keys
            ):
                feed["last_updated"] = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
                old_feeds.append(ReplaceOne({"_id": feed["_id"]}, replacement=feed))
                misp_feed_keys.remove(feed["url"])
            else:
                delete_feeds.append(DeleteOne({"_id": feed["_id"]}))

        for feed in misp_feed_keys:
            if misp_feeds[feed]["enabled"] == False:
                continue
            new_feed = {
                "url": misp_feeds[feed]["url"],
                "name": misp_feeds[feed]["name"],
                "provider": misp_feeds[feed]["provider"],
                "last_updated": datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                "id": misp_feeds[feed][
                    "id"
                ],  
            }
            new_feeds.append(new_feed)

        for db_event in current_events:
            if db_event["name"] in misp_event_keys:
                db_event["attribute_count"] = misp_events[db_event["name"]][
                    "attribute_count"
                ]
                db_event["threat_level_id"] = misp_events[db_event["name"]][
                    "threat_level_id"
                ]
                tags = [
                    str(tag["Tag"]["name"]).lower()
                    for tag in misp_events[db_event["name"]]["EventTag"]
                ]  
                db_event["type"] = {
                    "botnet": 1 if "botnet" in tags else 0,
                    "tor": 1 if "tor" in tags else 0,
                    "c&c": 1 if "c&c" in tags else 0,
                    "malware": 1 if "malware" in tags else 0,
                    "spam": 1 if "spam" in tags else 0,
                    "proxy": 1 if "proxy" in tags else 0,
                    "vpn": 1 if "vpn" in tags else 0,
                    "voip": 1 if "voip" in tags else 0,
                    "general": 1 if "general" in tags else 0,
                }
                db_event["last_updated"] = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
                old_events.append(
                    ReplaceOne({"_id": db_event["_id"]}, replacement=db_event)
                )
                misp_event_keys.remove(db_event["name"])
            else:
                delete_events.append(DeleteOne({"_id": db_event["_id"]}))

        for event in misp_event_keys:
            tags = [
                str(tag["Tag"]["name"]).lower()
                for tag in misp_events[event]["EventTag"]
            ]
            new_event = {
                "name": misp_events[event]["info"],
                "id": misp_events[event]["id"],
                "uuid": misp_events[event]["uuid"],
                "attribute_count": misp_events[event]["attribute_count"],
                "threat_level_id": misp_events[event]["threat_level_id"],
                "type": {
                    "botnet": 1 if "botnet" in tags else 0,
                    "tor": 1 if "tor" in tags else 0,
                    "c&c": 1 if "c&c" in tags else 0,
                    "malware": 1 if "malware" in tags else 0,
                    "spam": 1 if "spam" in tags else 0,
                    "proxy": 1 if "proxy" in tags else 0,
                    "vpn": 1 if "vpn" in tags else 0,
                    "voip": 1 if "voip" in tags else 0,
                    "general": 1 if "general" in tags else 0,
                },
                "last_updated": datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            }
            new_events.append(new_event)

        if len(delete_feeds)>0:
            misp_feed_db.feed.bulk_write(delete_feeds)

        if len(delete_events)>0:
            misp_feed_db.event.bulk_write(delete_events)

        if len(old_feeds)>0:
            misp_feed_db.feed.bulk_write(old_feeds)

        if len(old_events)>0:
            misp_feed_db.event.bulk_write(old_events)

        if len(new_feeds)>0:
            misp_feed_db.feed.insert_many(new_feeds)

        if len(new_events)>0:
            misp_feed_db.event.insert_many(new_events)

    else:
        misp_feeds = kwargs["feed_list"]
        misp_events = kwargs["event_list"]
        new_feeds = []
        new_events = []
        for feed in misp_feeds.keys():
            if misp_feeds[feed]["enabled"] == False:
                continue
            new_feed = {
                "url": misp_feeds[feed]["url"],
                "name": misp_feeds[feed]["name"],
                "provider": misp_feeds[feed]["provider"],
                "last_updated": datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                "id": misp_feeds[feed]["id"],
            }
            new_feeds.append(new_feed)

        for event in misp_events.keys():
            tags = [
                str(tag["Tag"]["name"]).lower()
                for tag in misp_events[event]["EventTag"]
            ]
            new_event = {
                "name": misp_events[event]["info"],
                "id": misp_events[event]["id"],
                "uuid": misp_events[event]["uuid"],
                "attribute_count": misp_events[event]["attribute_count"],
                "threat_level_id": misp_events[event]["threat_level_id"],
                "type": {
                    "botnet": 1 if "botnet" in tags else 0,
                    "tor": 1 if "tor" in tags else 0,
                    "c&c": 1 if "c&c" in tags else 0,
                    "malware": 1 if "malware" in tags else 0,
                    "spam": 1 if "spam" in tags else 0,
                    "proxy": 1 if "proxy" in tags else 0,
                    "vpn": 1 if "vpn" in tags else 0,
                    "voip": 1 if "voip" in tags else 0,
                    "general": 1 if "general" in tags else 0,
                },
                "last_updated": datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            }
            new_events.append(new_event)

        misp_feed_db.feed.insert_many(new_feeds)
        misp_feed_db.event.insert_many(new_events)


def add_ip(ip_dict):
    # Adds IP to the mongodb
    db = os.environ.get("IP_DB", default="ip_info")
    client = MongoClient(
        "mongodb://root:rootpassword@localhost:27017/?authSource=admin"
    )
    databases = client.list_database_names()
    if db in databases:
        ip_info_db = client[db]
        current_ips = ip_info_db.current_ips.find({})
        ip_key_list = list(ip_dict.keys())
        remove_current_ip = []
        add_current_ip = []  
        replace_current_ip = []
        new_blacklist_keys = [
            black_list for black_list in ip_dict[list(ip_dict.keys())[0]]["blacklists"]
        ]
        iterator = set(ip_key_list)
        for ip_doc in current_ips:
            if ip_doc["ip"] in iterator:
                ip_doc["blacklists"] = ip_dict[ip_doc["ip"]]["blacklists"]
                ip_doc["type"] = ip_dict[ip_doc["ip"]]["type"]
                ip_doc["threat_level_id"] = ip_dict[ip_doc["ip"]]["threat_level_id"]
                ip_doc["last_updated"] = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
                ip_doc["historical_time"] = int(ip_doc["historical_time"]) + 1
                ip_doc["active_time"] = int(ip_doc["active_time"]) + 1
                ip_doc["in_history"] = 0
                ip_doc["asn"] = ip_dict[ip_doc["ip"]]["asn"]
                ip_doc["country"] = ip_dict[ip_doc["ip"]]["country"]
                ip_doc["org"] = ip_dict[ip_doc["ip"]]["org"]

                replace_current_ip.append(
                    ReplaceOne(filter={"_id": ip_doc["_id"]}, replacement=ip_doc)
                )
                if len(ip_key_list)>0:
                    ip_key_list.remove(ip_doc["ip"])
        
            else:
                remove_current_ip.append(DeleteOne(filter={"_id": ip_doc["_id"]}))

                ip_doc.pop("_id")
                ip_doc["last_updated"] = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
                ip_doc["active_time"] = 0
                ip_doc["historical_time"] = int(ip_doc["historical_time"]) + 1
                ip_doc["in_history"] = 0

                black_list = list(ip_doc["blacklists"].keys())

                for blacklist in black_list:
                    if blacklist not in new_blacklist_keys:
                        del ip_doc["blacklists"][blacklist]

                asn_ip = requests.get(
                    str("http://localhost:3001/json?ip=" + str(ip_doc["ip"]))
                )
                asn_ip = asn_ip.json()

                ip_doc["asn"] = asn_ip["asn"] if "asn" in asn_ip else "NA"
                ip_doc["country"] = asn_ip["country"] if "country" in asn_ip else "NA"
                ip_doc["org"] = asn_ip["asn_org"] if "asn_org" in asn_ip else "NA"

        del iterator

        for ip in ip_key_list:
            add_current_ip.append(ip_dict[ip])

        if len(remove_current_ip)>0:
            ip_info_db.current_ips.bulk_write(remove_current_ip)

        if len(replace_current_ip)>0:
            ip_info_db.current_ips.bulk_write(replace_current_ip)

        if len(add_current_ip)>0:
            ip_info_db.current_ips.insert_many(add_current_ip)

    else:
        ip_info_db = client[db]
        ip_list = list(ip_dict.values())
        ip_info_db.current_ips.insert_many(ip_list)
        ip_info_db.create_collection("history_ips")

def get_epoch_time(date):
    data = date.split(',')[0].split('/')
    return datetime(int(data[2]),int(data[0]),int(data[1])).timestamp()

def clean_ip():    
    # Used to clean current ip and move them to history_ips
    db = os.environ.get('IP_DB', default='ip_info')
    client = MongoClient('mongodb://root:rootpassword@localhost:27017/?authSource=admin')
    databases = client.list_database_names()
    ttl = int(os.environ.get('CLEAN_IP',default=24))
    today = time.time()
    if db in databases:
        ip_info_db = client[db]
        page_limit = 50000;
        total_number = ip_info_db.current_ips.count_documents({})
        iterations = int(total_number/page_limit)
        for num in range(0,iterations+1):
            history=[]
            current=[]
            if num==iterations:
                current_ips = np.array(list(map(lambda x:x,ip_info_db.current_ips.find({}).skip(num*page_limit))))
            else:
                current_ips = np.array(list(map(lambda x: x, ip_info_db.current_ips.find({}).skip(num*page_limit).limit(page_limit))))
            for ip in current_ips:
                last_updated = ip['last_updated']
                epoch_time = get_epoch_time(last_updated)
                if today-(ttl*60*60) > epoch_time:
                    # Move the entry to history_ip
                    history_ip = ip_info_db.history_ips.find_one({"ip":ip['ip']})
                    if not history_ip:
                        history.append(ip)
                    current.append(ip["_id"])
            ip_info_db.current_ips.remove({'_id':{'$in':current}})
            if len(history)>0:
                ip_info_db.history_ips.insert_many(history)
            del current_ips
