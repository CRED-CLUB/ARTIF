import os
import numpy as np
import pymisp
import math
import pprint
import sys
from datetime import datetime
from pathlib import Path

from pymongo import ReplaceOne, DeleteOne
from pymongo import MongoClient

p = Path(__file__).parents[1]
sys.path.append(str(p))

import feed_ingestor.feed
import feed_ingestor.listing

def score_attributes():
    feed_db = os.environ.get("MONGO_DB", default="misp_feed")
    ip_db = os.environ.get("IP_DB", default="ip_info")
    score_db = os.environ.get("SCORE_DB", default="score_db")
    client = MongoClient(
        "mongodb://root:rootpassword@localhost:27017/?authSource=admin"
    )
    databases = client.list_database_names()
    misp_feed_db = client[feed_db]
    ip_info_db = client[ip_db]
    # Go through all the IPs to gather this info. Each value is either 1 or 0. For first IP check if abc in ASN_blacklist if it xyz country, abc ASN and wasd org, variables to be made are:
    # ASN_blacklist['abc'] = {All blacklist names: 1/0}, ASN_type['abc'] = {All types: 1/0}, same for country and org
    # After that if same come then keep adding to them +1 . Also within this (every of the down 6 variables) only add threat level for each blacklist and the weights for each tag for ease of compute.
    # Aggregate the attributes by ASN, Country, Org (Make 3 variables to hold them)
    # ASN['abc'] = {{blacklists: {1/0 wala}, {type: 1/0}, ASN_blacklist['abc'], ASN_type['abc'], total_ip, blacklist_score, type_score, nominal_freq, recency_score, final_score} -> Same for country and
    # Total IP must be counted too => total_ip = {'total': xyz, 'blacklists': {'bl_a':xyz, ... }, 'type': {'tor':xyz, ...}, 'asn': {'asn_a':xyz}, 'country': {'country_a: xyz}, 'org':{'org_a': xyz}}
    # Make 6 variables to store ASN_blacklist, ASN_type, Country_blacklist, Country_type, Org_blacklist, Org_type basically
    # {'ASN_name': {'blacklist_name': number of IPs}}

    events = misp_feed_db.event.find({})
    type_wt = {  
        "botnet": 2,
        "tor": 4,
        "c&c": 4,
        "malware": 3,
        "spam": 2,
        "proxy": 2,
        "vpn": 1,
        "voip": 1,
        "general": 1,
        "crawlerbot": 1,
        "abuse": 2,
        "attack": 2,
        "recon": 2,
        "research": 1,
        "cloud": 1,
        "miner": 4,
        "reputation": 1,
    }
    type_max = 0
    for wt in type_wt.keys():
        type_max += 1 / (5 - float(type_wt[wt]))

    blacklist_tl = {}

    for event in events:
        blacklist_tl[event["name"]] = event["threat_level_id"]

    blacklist_max = 0
    for b_wt in blacklist_tl.keys():
        blacklist_max += 1 / (5 - float(blacklist_tl[b_wt]))

    asn_blacklist = {}
    asn_type = {}
    country_blacklist = {}
    country_type = {}
    org_blacklist = {}
    org_type = {}
    asn = {}
    country = {}
    org = {}
    total_ip = {
        "total": 0,
        "blacklists": {},
        "type": {},
        "asn": {},
        "country": {},
        "org": {},
    }
    total_history_ip = {"asn": {}, "country": {}, "org": {}}

    max_score = {
        "asn": float(-math.inf),
        "country": float(-math.inf),
        "org": float(-math.inf),
    }
    page_limit = 100000;

    total_number = ip_info_db.current_ips.count_documents({})
    iterations = int(total_number/page_limit)

    for num in range(iterations+1):
        if num==iterations+1:
            current_ips = np.array(list(map(lambda x:x,ip_info_db.current_ips.find({},{"_id":False}).skip(num*100000))))
        else:
            current_ips = np.array(list(map(lambda x: x, ip_info_db.current_ips.find({},{"_id": False}).skip(num*100000).limit(100000))))
        for ip_doc in current_ips:
            if ip_doc["asn"] not in asn_blacklist:
                blacklist = {}
                for bl in ip_doc["blacklists"].keys():
                    blacklist[bl] = float(ip_doc["blacklists"][bl])
                asn_blacklist[ip_doc["asn"]] = blacklist
                tag = {}
                for tg in ip_doc["type"].keys():
                    tag[tg] = float(ip_doc["type"][tg])
                asn_type[ip_doc["asn"]] = tag

                if not total_ip["blacklists"]:
                    blacklist = {}
                    for bl in ip_doc["blacklists"].keys():
                        blacklist[bl] = float(ip_doc["blacklists"][bl])
                    total_ip["blacklists"] = blacklist

                    tag = {}
                    for tg in ip_doc["type"].keys():
                        tag[tg] = float(ip_doc["type"][tg])
                    total_ip["type"] = tag

                else:
                    for blacklist in ip_doc["blacklists"].keys():
                        total_ip["blacklists"][blacklist] += float(
                            ip_doc["blacklists"][blacklist]
                        )
                    for tag in ip_doc["type"].keys():
                        total_ip["type"][tag] += float(ip_doc["type"][tag])

                total_ip["total"] = float(total_ip["total"]) + 1
                total_ip["asn"][ip_doc["asn"]] = (
                    1
                    if ip_doc["asn"] not in total_ip["asn"]
                    else float(total_ip["asn"][ip_doc["asn"]]) + 1
                )
            else:
                for blacklist in ip_doc["blacklists"].keys():
                    asn_blacklist[ip_doc["asn"]][blacklist] += ip_doc["blacklists"][
                        blacklist
                    ]
                for tag in ip_doc["type"].keys():
                    asn_type[ip_doc["asn"]][tag] += ip_doc["type"][tag]

                for blacklist in ip_doc["blacklists"].keys():
                    total_ip["blacklists"][blacklist] += float(
                        ip_doc["blacklists"][blacklist]
                    )
                for tag in ip_doc["type"].keys():
                    total_ip["type"][tag] += float(ip_doc["type"][tag])

                total_ip["total"] = float(total_ip["total"]) + 1
                total_ip["asn"][ip_doc["asn"]] = (
                    1
                    if ip_doc["asn"] not in total_ip["asn"]
                    else float(total_ip["asn"][ip_doc["asn"]]) + 1
                )

            if ip_doc["country"] not in country_blacklist:
                blacklist = {}
                for bl in ip_doc["blacklists"].keys():
                    blacklist[bl] = float(ip_doc["blacklists"][bl])
                country_blacklist[ip_doc["country"]] = blacklist
                tag = {}
                for tg in ip_doc["type"].keys():
                    tag[tg] = float(ip_doc["type"][tg])
                country_type[ip_doc["country"]] = tag

                total_ip["country"][ip_doc["country"]] = (
                    1
                    if ip_doc["country"] not in total_ip["country"]
                    else float(total_ip["country"][ip_doc["country"]]) + 1
                )
            else:
                for blacklist in ip_doc["blacklists"].keys():
                    country_blacklist[ip_doc["country"]][blacklist] += float(
                        ip_doc["blacklists"][blacklist]
                    )
                for tag in ip_doc["type"].keys():
                    country_type[ip_doc["country"]][tag] += float(ip_doc["type"][tag])
                total_ip["country"][ip_doc["country"]] = (
                    1
                    if ip_doc["country"] not in total_ip["country"]
                    else float(total_ip["country"][ip_doc["country"]]) + 1
                )

            if ip_doc["org"] not in org_blacklist:
                blacklist = {}
                for bl in ip_doc["blacklists"].keys():
                    blacklist[bl] = float(ip_doc["blacklists"][bl])
                org_blacklist[ip_doc["org"]] = blacklist
                tag = {}
                for tg in ip_doc["type"].keys():
                    tag[tg] = float(ip_doc["type"][tg])
                org_type[ip_doc["org"]] = tag

                total_ip["org"][ip_doc["org"]] = (
                    1
                    if ip_doc["org"] not in total_ip["org"]
                    else float(total_ip["org"][ip_doc["org"]]) + 1
                )
            else:
                for blacklist in ip_doc["blacklists"].keys():
                    org_blacklist[ip_doc["org"]][blacklist] += float(
                        ip_doc["blacklists"][blacklist]
                    )
                for tag in ip_doc["type"].keys():
                    org_type[ip_doc["org"]][tag] += float(ip_doc["type"][tag])

                total_ip["org"][ip_doc["org"]] = (
                    1
                    if ip_doc["org"] not in total_ip["org"]
                    else float(total_ip["org"][ip_doc["org"]]) + 1
                )
        del current_ips
    
    
    total_number = ip_info_db.history_ips.count_documents({})
    iterations = int(total_number/page_limit)

    for num in range(0,iterations+1):
        if num==iterations:
            history_ips = np.array(list(map(lambda x:x,ip_info_db.history_ips.find({},{"_id":False}).skip(num*100000))))
        else:
            history_ips = np.array(list(map(lambda x: x, ip_info_db.history_ips.find({},{"_id": False}).skip(num*100000).limit(100000))))

        for ip_doc in history_ips:
            if ip_doc["asn"] not in asn_blacklist:
                blacklist = ip_doc["blacklists"]
                for bl in blacklist.keys():
                    blacklist[bl] = ((30 - float(ip_doc["in_history"])) / 30) * float(
                        blacklist[bl]
                    )
                asn_blacklist[ip_doc["asn"]] = blacklist

                tag = ip_doc["type"]
                for tg in tag.keys():
                    tag[tg] = ((30 - float(ip_doc["in_history"])) / 30) * float(tag[tg])
                asn_type[ip_doc["asn"]] = tag

                for blacklist in ip_doc["blacklists"].keys():
                    total_ip["blacklists"][blacklist] += float(
                        ip_doc["blacklists"][blacklist]
                    )  
                for tag in ip_doc["type"].keys():
                    total_ip["type"][tag] += float(
                        ip_doc["type"][tag]
                    )  

                total_ip["total"] = float(total_ip["total"]) + 1
                total_ip["asn"][ip_doc["asn"]] = (
                    1
                    if ip_doc["asn"] not in total_ip["asn"]
                    else float(total_ip["asn"][ip_doc["asn"]]) + 1
                )

                total_history_ip["asn"][ip_doc["asn"]] = {
                    "ip_count": 1
                    if ip_doc["asn"] not in total_history_ip["asn"]
                    else float(total_history_ip["asn"][ip_doc["asn"]]["ip_count"]) + 1
                }
                total_history_ip["asn"][ip_doc["asn"]]["cum_time"] = (
                    float(ip_doc["in_history"])
                    if "cum_time" not in total_history_ip["asn"][ip_doc["asn"]]
                    else float(total_history_ip["asn"][ip_doc["asn"]]["cum_time"])
                    + float(ip_doc["in_history"])
                )

            else:
                for blacklist in ip_doc["blacklists"].keys():
                    asn_blacklist[ip_doc["asn"]][blacklist] += (
                        (30 - float(ip_doc["in_history"])) / 30
                    ) * float(ip_doc["blacklists"][blacklist])
                for tag in ip_doc["type"].keys():
                    asn_type[ip_doc["asn"]][tag] += (
                        (30 - float(ip_doc["in_history"])) / 30
                    ) * float(ip_doc["type"][tag])

                for blacklist in ip_doc["blacklists"].keys():
                    total_ip["blacklists"][blacklist] += float(ip_doc["blacklists"][blacklist])
                
                for tag in ip_doc["type"].keys():
                    total_ip["type"][tag] += float(ip_doc["type"][tag])

                total_ip["total"] = float(total_ip["total"]) + 1
                total_ip["asn"][ip_doc["asn"]] = (
                    1
                    if ip_doc["asn"] not in total_ip["asn"]
                    else float(total_ip["asn"][ip_doc["asn"]]) + 1
                )

                total_history_ip["asn"][ip_doc["asn"]] = {
                    "ip_count": 1
                    if ip_doc["asn"] not in total_history_ip["asn"]
                    else float(total_history_ip["asn"][ip_doc["asn"]]["ip_count"]) + 1
                }
                total_history_ip["asn"][ip_doc["asn"]]["cum_time"] = (
                    float(ip_doc["in_history"])
                    if "cum_time" not in total_history_ip["asn"][ip_doc["asn"]]
                    else float(total_history_ip["asn"][ip_doc["asn"]]["cum_time"])
                    + float(ip_doc["in_history"])
                )

            if ip_doc["country"] not in country_blacklist:
                blacklist = ip_doc["blacklists"]
                for bl in blacklist.keys():
                    blacklist[bl] = ((30 - float(ip_doc["in_history"])) / 30) * float(
                        blacklist[bl]
                    )
                country_blacklist[ip_doc["country"]] = blacklist

                tag = ip_doc["type"]
                for tg in tag.keys():
                    tag[tg] = ((30 - float(ip_doc["in_history"])) / 30) * float(tag[tg])
                country_type[ip_doc["country"]] = tag

                total_ip["country"][ip_doc["country"]] = (
                    1
                    if ip_doc["country"] not in total_ip["country"]
                    else float(total_ip["country"][ip_doc["country"]]) + 1
                )

                total_history_ip["country"][ip_doc["country"]] = {
                    "ip_count": 1
                    if ip_doc["country"] not in total_history_ip["country"]
                    else float(total_history_ip["country"][ip_doc["country"]]["ip_count"])
                    + 1
                }
                total_history_ip["country"][ip_doc["country"]]["cum_time"] = (
                    float(ip_doc["in_history"])
                    if "cum_time" not in total_history_ip["country"][ip_doc["country"]]
                    else float(total_history_ip["country"][ip_doc["country"]]["cum_time"])
                    + float(ip_doc["in_history"])
                )
            else:
                for blacklist in ip_doc["blacklists"].keys():
                    country_blacklist[ip_doc["country"]][blacklist] += (
                        (30 - float(ip_doc["in_history"])) / 30
                    ) * float(ip_doc["blacklists"][blacklist])
                for tag in ip_doc["type"].keys():
                    country_type[ip_doc["country"]][tag] += (
                        (30 - float(ip_doc["in_history"])) / 30
                    ) * float(ip_doc["type"][tag])

                total_ip["country"][ip_doc["country"]] = (
                    1
                    if ip_doc["country"] not in total_ip["country"]
                    else float(total_ip["country"][ip_doc["country"]]) + 1
                )

                total_history_ip["country"][ip_doc["country"]] = {
                    "ip_count": 1
                    if ip_doc["country"] not in total_history_ip["country"]
                    else float(total_history_ip["country"][ip_doc["country"]]["ip_count"])
                    + 1
                }
                total_history_ip["country"][ip_doc["country"]]["cum_time"] = (
                    float(ip_doc["in_history"])
                    if "cum_time" not in total_history_ip["country"][ip_doc["country"]]
                    else float(total_history_ip["country"][ip_doc["country"]]["cum_time"])
                    + float(ip_doc["in_history"])
                )

            if ip_doc["org"] not in org_blacklist:
                blacklist = ip_doc["blacklists"]
                for bl in blacklist.keys():
                    blacklist[bl] = ((30 - float(ip_doc["in_history"])) / 30) * float(
                        blacklist[bl]
                    )
                org_blacklist[ip_doc["org"]] = blacklist

                tag = ip_doc["type"]
                for tg in tag.keys():
                    tag[tg] = ((30 - float(ip_doc["in_history"])) / 30) * float(tag[tg])
                org_type[ip_doc["org"]] = tag

                total_ip["org"][ip_doc["org"]] = (
                    1
                    if ip_doc["org"] not in total_ip["org"]
                    else float(total_ip["org"][ip_doc["org"]]) + 1
                )

                total_history_ip["org"][ip_doc["org"]] = {
                    "ip_count": 1
                    if ip_doc["org"] not in total_history_ip["org"]
                    else float(total_history_ip["org"][ip_doc["org"]]["ip_count"]) + 1
                }
                total_history_ip["org"][ip_doc["org"]]["cum_time"] = (
                    float(ip_doc["in_history"])
                    if "cum_time" not in total_history_ip["org"][ip_doc["org"]]
                    else float(total_history_ip["org"][ip_doc["org"]]["cum_time"])
                    + float(ip_doc["in_history"])
                )
            else:
                for blacklist in ip_doc["blacklists"].keys():
                    org_blacklist[ip_doc["org"]][blacklist] += (
                        (30 - float(ip_doc["in_history"])) / 30
                    ) * float(ip_doc["blacklists"][blacklist])
                for tag in ip_doc["type"].keys():
                    org_type[ip_doc["org"]][tag] += (
                        (30 - float(ip_doc["in_history"])) / 30
                    ) * float(ip_doc["type"][tag])

                total_ip["org"][ip_doc["org"]] = (
                    1
                    if ip_doc["org"] not in total_ip["org"]
                    else float(total_ip["org"][ip_doc["org"]]) + 1
                )

                total_history_ip["org"][ip_doc["org"]] = {
                    "ip_count": 1
                    if ip_doc["org"] not in total_history_ip["org"]
                    else float(total_history_ip["org"][ip_doc["org"]]["ip_count"]) + 1
                }
                total_history_ip["org"][ip_doc["org"]]["cum_time"] = (
                    float(ip_doc["in_history"])
                    if "cum_time" not in total_history_ip["org"][ip_doc["org"]]
                    else float(total_history_ip["org"][ip_doc["org"]]["cum_time"])
                    + float(ip_doc["in_history"])
                )
        del history_ips

    for asname in asn_blacklist.keys():
        if asname not in total_history_ip["asn"]:
            total_history_ip["asn"][asname] = {"ip_count": 0, "cum_time": 0}
        asn[asname] = {
            "asn": asname,
            "blacklists": asn_blacklist[asname],
            "type": asn_type[asname],
            "total_ip": {
                "total": float(total_ip["total"]),
                "blacklists": total_ip["blacklists"],
                "type": total_ip["type"],
                "asn": float(total_ip["asn"][asname]),
            },
            "history_ip": {"asn": float(total_history_ip["asn"][asname]["ip_count"])},
        }
        blacklist_score = 0.0
        type_score = 0.0
        nominal_freq = float(asn[asname]["total_ip"]["asn"]) / float(
            asn[asname]["total_ip"]["total"]
        )
        recency_score = 1 - (
            (float(total_history_ip["asn"][asname]["cum_time"]))
            * float(total_history_ip["asn"][asname]["ip_count"])
        ) / (
            (1 + float(total_history_ip["asn"][asname]["ip_count"]))
            * (float(asn[asname]["total_ip"]["asn"]))
        )

        for blacklist in asn[asname]["blacklists"].keys():
            try:
                blacklist_score += float(asn[asname]["blacklists"][blacklist]) / (
                    (5 - float(blacklist_tl[blacklist]))
                    * float(asn[asname]["total_ip"]["blacklists"][blacklist])
                )
            except ZeroDivisionError:
                blacklist_score += 0
        for tag in asn[asname]["type"].keys():
            try:
                type_score += float(asn[asname]["type"][tag]) / (
                    (5 - float(type_wt[tag]))
                    * float(asn[asname]["total_ip"]["type"][tag])
                )
            except ZeroDivisionError:
                type_score += 0

        blacklist_score = blacklist_score / blacklist_max
        type_score = type_score / type_max

        asn[asname]["blacklist_score"] = blacklist_score
        asn[asname]["type_score"] = type_score
        asn[asname]["nominal_freq"] = nominal_freq
        asn[asname]["recency_score"] = recency_score
        asn[asname]["final_score"] = (
            (nominal_freq + type_score + blacklist_score) * recency_score
        ) / 3

        if asn[asname]["final_score"] > float(max_score["asn"]):
            max_score["asn"] = float(asn[asname]["final_score"])

    for country_name in country_blacklist.keys():
        if country_name not in total_history_ip["country"]:
            total_history_ip["country"][country_name] = {"ip_count": 0, "cum_time": 0}
        country[country_name] = {
            "country": country_name,
            "blacklists": country_blacklist[country_name],
            "type": country_type[country_name],
            "total_ip": {
                "total": float(total_ip["total"]),
                "blacklists": total_ip["blacklists"],
                "type": total_ip["type"],
                "country": float(total_ip["country"][country_name]),
            },
            "history_ip": {
                "country": float(total_history_ip["country"][country_name]["ip_count"])
            },
        }
        blacklist_score = 0.0
        type_score = 0.0
        nominal_freq = float(country[country_name]["total_ip"]["country"]) / float(
            country[country_name]["total_ip"]["total"]
        )
        recency_score = 1 - (
            float(total_history_ip["country"][country_name]["cum_time"])
            * float(total_history_ip["country"][country_name]["ip_count"])
        ) / (
            (1 + float(total_history_ip["country"][country_name]["ip_count"]))
            * float(country[country_name]["total_ip"]["country"])
        )

        for blacklist in country[country_name]["blacklists"].keys():
            try:
                blacklist_score += float(
                    country[country_name]["blacklists"][blacklist]
                ) / (
                    (5 - float(blacklist_tl[blacklist]))
                    * float(country[country_name]["total_ip"]["blacklists"][blacklist])
                )
            except ZeroDivisionError:
                blacklist_score += 0
        for tag in country[country_name]["type"].keys():
            try:
                type_score += float(country[country_name]["type"][tag]) / (
                    (5 - float(type_wt[tag]))
                    * float(country[country_name]["total_ip"]["type"][tag])
                )
            except ZeroDivisionError:
                type_score += 0
        blacklist_score = blacklist_score / blacklist_max
        type_score = type_score / type_max

        country[country_name]["blacklist_score"] = blacklist_score
        country[country_name]["type_score"] = type_score
        country[country_name]["nominal_freq"] = nominal_freq
        country[country_name]["recency_score"] = recency_score
        country[country_name]["final_score"] = (
            (nominal_freq + type_score + blacklist_score) * recency_score
        ) / 3

        if country[country_name]["final_score"] > float(max_score["country"]):
            max_score["country"] = float(country[country_name]["final_score"])

    for orgname in org_blacklist.keys():
        if orgname not in total_history_ip["org"]:
            total_history_ip["org"][orgname] = {"ip_count": 0, "cum_time": 0}
        org[orgname] = {
            "org": orgname,
            "blacklists": org_blacklist[orgname],
            "type": org_type[orgname],
            "total_ip": {
                "total": float(total_ip["total"]),
                "blacklists": total_ip["blacklists"],
                "type": total_ip["type"],
                "org": float(total_ip["org"][orgname]),
            },
            "history_ip": {"org": float(total_history_ip["org"][orgname]["ip_count"])},
        }
        blacklist_score = 0
        type_score = 0
        nominal_freq = float(org[orgname]["total_ip"]["org"]) / float(
            org[orgname]["total_ip"]["total"]
        )
        recency_score = 1 - (
            float(total_history_ip["org"][orgname]["cum_time"])
            * float(total_history_ip["org"][orgname]["ip_count"])
        ) / (
            (1 + float(total_history_ip["org"][orgname]["ip_count"]))
            * float(org[orgname]["total_ip"]["org"])
        )

        for blacklist in org[orgname]["blacklists"].keys():
            try:
                blacklist_score += float(org[orgname]["blacklists"][blacklist]) / (
                    (5 - float(blacklist_tl[blacklist]))
                    * float(org[orgname]["total_ip"]["blacklists"][blacklist])
                )
            except ZeroDivisionError:
                blacklist_score += 0
        for tag in org[orgname]["type"].keys():
            try:
                type_score += float(org[orgname]["type"][tag]) / (
                    (5 - float(type_wt[tag]))
                    * float(org[orgname]["total_ip"]["type"][tag])
                )
            except ZeroDivisionError:
                type_score += 0

        blacklist_score = blacklist_score / blacklist_max
        type_score = type_score / type_max

        org[orgname]["blacklist_score"] = blacklist_score
        org[orgname]["type_score"] = type_score
        org[orgname]["nominal_freq"] = nominal_freq
        org[orgname]["recency_score"] = recency_score
        org[orgname]["final_score"] = (
            (nominal_freq + type_score + blacklist_score) * recency_score
        ) / 3

        if org[orgname]["final_score"] > float(max_score["org"]):
            max_score["org"] = float(org[orgname]["final_score"])

    if score_db in databases:
        current_asn = list(client[score_db].asn.find({}))
        current_country = list(client[score_db].country.find({}))
        current_org = list(client[score_db].org.find({}))
        asn_list = list(asn.keys())
        country_list = list(country.keys())
        org_list = list(org.keys())
        remove_asn = []
        remove_country = []
        remove_org = []
        add_asn = []
        add_country = []
        add_org = []
        replace_org = []
        replace_asn = []
        replace_country = []

        for c_asn in current_asn:
            if c_asn["asn"] in asn_list:
                replace_asn.append(ReplaceOne(filter={"_id": c_asn["_id"]}, replacement=asn[c_asn["asn"]]))
                asn_list.remove(c_asn["asn"])
            else:
                remove_asn.append(DeleteOne(c_asn))
                asn_list.remove(c_asn["asn"])

        for c_asn in asn_list:
            add_asn.append(asn[c_asn])

        for c_country in current_country:
            if c_country["country"] in country_list:
                replace_country.append(
                    ReplaceOne(
                        filter={"_id": c_country["_id"]},
                        replacement=country[c_country["country"]],
                    )
                )
                country_list.remove(c_country["country"])
            else:
                remove_country.append(DeleteOne(c_country))
                country_list.remove(c_country["country"])

        for c_country in country_list:
            add_country.append(country[c_country])

        for c_org in current_org:
            if c_org["org"] in org_list:
                replace_org.append(
                    ReplaceOne(
                        filter={"_id": c_org["_id"]}, replacement=org[c_org["org"]]
                    )
                )
                org_list.remove(c_org["org"])
            else:
                remove_org.append(DeleteOne(c_org))
                org_list.remove(c_org["org"])

        for c_org in org_list:
            add_org.append(org[c_org])

        if len(remove_asn)>0:
            client[score_db].asn.bulk_write(remove_asn)

        if len(remove_country)>0:
            client[score_db].country.bulk_write(remove_country)

        if len(remove_org)>0:
            client[score_db].org.bulk_write(remove_org)

        if len(replace_asn)>0:
            client[score_db].asn.bulk_write(replace_asn)

        if len(replace_country)>0:
            client[score_db].country.bulk_write(replace_country)

        if len(replace_org)>0:
            client[score_db].org.bulk_write(replace_org)

        if len(add_country)>0:
            client[score_db].country.bulk_write(add_country)

        if len(add_org)>0:
            client[score_db].org.bulk_write(add_org)

        if len(add_asn)>0:
            client[score_db].asn.bulk_write(add_asn)

        collections = client[score_db].list_collection_names()
        if "max" not in collections:
            client[score_db].max.insert(max_score)
        else:
            c_max_score = client[score_db].max.find_one({})
            c_max_score["asn"] = max_score["asn"]
            c_max_score["country"] = max_score["country"]
            c_max_score["org"] = max_score["org"]
            client[score_db].max.replace_one(
                filter={"id": c_max_score["_id"]}, replacement=c_max_score
            )

    else:
        asn_list = list(asn.values())
        country_list = list(country.values())
        org_list = list(org.values())
        client[score_db].asn.insert_many(asn_list)
        client[score_db].country.insert_many(country_list)
        client[score_db].org.insert_many(org_list)
        client[score_db].max.insert(max_score)
