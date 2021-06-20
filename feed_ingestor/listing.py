import requests
from datetime import datetime

import pymisp

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class MISPReader:
    def list_feeds(self, misp):
        feeds = misp.feeds()
        feedlist = {}
        for i in feeds:
            feedlist[i["Feed"]["url"]] = i["Feed"]
        return feedlist

    def list_events(self, misp):
        events = misp.events()
        eventdict = {}
        for i in events:
            eventdict[i["info"]] = i
        return eventdict

    def list_attributes(self, misp):
        attributes = {"Attribute": []}
        c_pg_no = 1
        while True:
            misp_attr = misp.search(
                controller="attributes",
                type_attribute="ip-dst",
                include_context=True,
                include_correlations=True,
                page=c_pg_no,
                limit=100,
                deleted=False,
            )
            current_length = len(misp_attr["Attribute"])
            attributes["Attribute"].extend(misp_attr["Attribute"])
            if current_length < 100:
                break
            else:
                c_pg_no += 1
        added_ip = set()
        trimmed_attributes = {}
        events_list = self.list_events(misp)
        event_names = list(events_list.keys())
        vale = 0
        for attribute in attributes["Attribute"]:
            vale += 1
            if attribute["value"] not in added_ip:
                added_ip.add(attribute["value"])
                tags = set()
                for tag in attribute["Event"]["Tag"]:
                    tags.add(tag["name"])
                threat_level = int(attribute["Event"]["threat_level_id"])
                blacklists = [attribute["Event"]["info"]]
                for related in attribute["RelatedAttribute"]:
                    event = events_list[related["Event"]["info"]]
                    blacklists.append(related["Event"]["info"])
                    threat_level += int(related["Event"]["threat_level_id"])
                    for tag in event["EventTag"]:
                        tags.add(str(tag["Tag"]["name"]).lower())
                threat_level = float(threat_level) / len(blacklists)
                blacklist_names = {}
                for blacklist in event_names:
                    blacklist_names[blacklist] = 1 if blacklist in blacklists else 0
                asn_ip = requests.get(
                    str("http://localhost:3001/json?ip=" + str(attribute["value"]))
                )
                asn_ip = asn_ip.json()
                trimmed_attributes[attribute["value"]] = {
                    "ip": attribute["value"],
                    "blacklists": blacklist_names,
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
                        "crawlerbot": 1 if "crawlerbot" in tags else 0,
                        "abuse": 1 if "abuse" in tags else 0,
                        "attack": 1 if "attack" in tags else 0,
                        "recon": 1 if "recon" in tags else 0,
                        "research": 1 if "research" in tags else 0,
                        "cloud": 1 if "cloud" in tags else 0,
                        "miner": 1 if "miner" in tags else 0,
                        "reputation": 1 if "reputation" in tags else 0,
                    },
                    "threat_level_id": threat_level,
                    "last_updated": datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                    "historical_time": 0,
                    "active_time": 0,
                    "in_history": 0,
                    "asn": asn_ip["asn"] if "asn" in asn_ip else "NA",
                    "country": asn_ip["country"] if "country" in asn_ip else "NA",
                    "org": asn_ip["asn_org"] if "asn_org" in asn_ip else "NA",
                }
            else:
                continue
        return trimmed_attributes
