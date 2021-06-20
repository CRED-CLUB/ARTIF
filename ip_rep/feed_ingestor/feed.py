import pprint
import yaml
import json
import os
import sys
import pymisp
from pathlib import Path

from pymisp import MISPEvent
from pymisp import PyMISP

p = Path(__file__).parents[1]
sys.path.append(str(p))

from database_connector import mongo_update
from feed_ingestor import listing


class mainCaller:
    def update_misp(self, **kwargs):
        misp_inst = PyMISP(
            url=os.environ.get("MISP_URL", default="https://localhost"),
            ssl=os.environ.get("MISP_SSL", default=False),
            debug=os.environ.get("MISP_DEBUG", default=False),
            key=os.environ.get(
                "MISP_KEY"
            ),
        )
        read_feeds = listing.MISPReader()
        feed_list = read_feeds.list_feeds(misp_inst)
        event_list = read_feeds.list_events(misp_inst)
        with open(kwargs["filename"], "r") as filej:
            data = yaml.full_load(filej)
        if data["feeds"]:
            for feed in data["feeds"]:
                if "url" not in feed["feed"]:
                    print("[!] Download link to feed absent. Please add feed in correct format")
                    sys.exit(-1);
                elif feed["feed"]["url"] not in feed_list.keys():
                    if (str(feed["feed"]["name"]) + " feed") not in event_list.keys():
                        feed = {
                            "source_format": feed["feed"]["source_format"],
                            "name": feed["feed"]["name"],
                            "url": feed["feed"]["url"],
                            "input_source": feed["feed"]["input_source"],
                            "provider": feed["feed"]["provider"],
                            "publish": True,
                            "lookup_visible": True,
                            "enabled": True,
                            "caching_enabled": True,
                            "fixed_event": True,
                            "delta_merge": True,
                        }
                        response_feed = misp_inst.add_feed(feed)
                        misp_inst.fetch_feed(response_feed["Feed"]["id"])
                        misp_inst.enable_feed_cache(response_feed["Feed"]["id"])
                        misp_inst.cache_feed(response_feed["Feed"]["id"])
                    else:
                        print("Only one feed can be added to an event")
                else:
                    if (str(feed["feed"]["name"]) + " feed") not in event_list.keys():
                        misp_inst.fetch_feed(feed_list[feed["feed"]["url"]]["id"])
                        misp_inst.enable_feed_cache(
                            feed_list[feed["feed"]["url"]]["id"]
                        )
                        misp_inst.cache_feed(feed_list[feed["feed"]["url"]]["id"])
                    else:
                        event_id = event_list[str(feed["feed"]["name"]) + " feed"][
                            "uuid"
                        ]
                        event = {
                            "Event": {
                                "info": event_list[feed["feed"]["name"] + " feed"][
                                    "info"
                                ],
                                "threat_level_id": feed["feed"]["threat_level_id"],
                                "published": True,
                            }
                        }
                        accepted_tags = [
                            "botnet",
                            "tor",
                            "c&c",
                            "malware",
                            "spam",
                            "proxy",
                            "vpn",
                            "voip",
                            "general",
                            "crawlerbot",
                            "abuse",
                            "attack",
                            "recon",
                            "research",
                            "cloud",
                            "miner",
                            "reputation",
                        ]
                        for tags in feed["feed"]["type"]:
                            if tags.lower() in accepted_tags:
                                misp_inst.tag(event_id, tags.lower())
                        misp_inst.update_event(event, event_id=event_id)
                        misp_inst.fetch_feed(feed_list[feed["feed"]["url"]]["id"])
                        misp_inst.enable_feed_cache(
                            feed_list[feed["feed"]["url"]]["id"]
                        )
                        misp_inst.cache_feed(feed_list[feed["feed"]["url"]]["id"])
        feed_list = read_feeds.list_feeds(misp_inst)
        event_list = read_feeds.list_events(misp_inst)
        return feed_list, event_list

    def update_file(self, **kwargs):
        try:
            misp_inst = PyMISP(
                url=os.environ.get("MISP_URL"),
                ssl=os.environ.get("MISP_SSL", default=False),
                debug=os.environ.get("MISP_DEBUG", default=False),
                key=os.environ.get(
                    "MISP_KEY"
                ),
            )
        except Exception as e:
            sys.stderr.write("[!] PyMISP Exception: %s" %e)
            sys.exit(1)
        
        read_feeds = listing.MISPReader()
        feed_list = read_feeds.list_feeds(misp_inst)
        event_list = read_feeds.list_events(misp_inst)
        feed_list_keys = list(feed_list.keys())
        with open(kwargs["filename"], "r") as filej:
            data = yaml.full_load(filej)
        feed_objs = (
            [] if not data["feeds"] else [feed["feed"] for feed in data["feeds"]]
        )
        
        update = []
        
        for feed in feed_objs:
            if feed["url"] in feed_list_keys:
                update_feed = {
                    "source_format": feed_list[feed["url"]]["source_format"],
                    "url": feed_list[feed["url"]]["url"],
                    "name": feed_list[feed["url"]]["name"],
                    "input_source": feed_list[feed["url"]]["input_source"],
                    "provider": feed_list[feed["url"]]["provider"],
                    "publish": False,
                    "lookup_visible": True,
                    "enabled": True,
                    "threat_level_id": event_list[
                        feed_list[feed["url"]]["name"] + " feed"
                    ]["threat_level_id"],
                    "type": [
                        str(tag["Tag"]["name"]).lower()
                        for tag in event_list[feed_list[feed["url"]]["name"] + " feed"][
                            "EventTag"
                        ]
                    ],
                }
                update.append({"feed": update_feed})
                feed_list_keys.remove(feed["url"])
        
        for url in feed_list_keys:
            if feed_list[url]["name"] + " feed" not in event_list.keys():
                if feed_list[url]["enabled"] == True:
                    misp_inst.fetch_feed(feed_list[url]["id"])
                    misp_inst.enable_feed_cache(feed_list[url]["id"])
                    misp_inst.cache_feed(feed_list[url]["id"])
                
                    update_feeds = {
                        "source_format": feed_list[url]["source_format"],
                        "url": feed_list[url]["url"],
                        "name": feed_list[url]["name"],
                        "input_source": feed_list[url]["input_source"],
                        "provider": feed_list[url]["provider"],
                        "publish": feed_list[url]["publish"],
                        "lookup_visible": feed_list[url]["lookup_visible"],
                        "enabled": feed_list[url]["enabled"],
                        "threat_level_id": event_list[feed_list[url]["name"] + " feed"]["threat_level_id"],
                        "type": [
                            str(tag["Tag"]["name"]).lower()
                            for tag in event_list[feed_list[url]["name"] + " feed"]["EventTag"]
                        ]
                    }
                    
                    update.append({"feed": update_feed})

            else:
                update_feed = {
                    "source_format": feed_list[url]["source_format"],
                    "url": feed_list[url]["url"],
                    "name": feed_list[url]["name"],
                    "input_source": feed_list[url]["input_source"],
                    "provider": feed_list[url]["provider"],
                    "publish": False,
                    "lookup_visible": True,
                    "enabled": True,
                    "threat_level_id": event_list[feed_list[url]["name"] + " feed"][
                        "threat_level_id"
                    ],
                    "type": [
                        str(tag["Tag"]["name"]).lower()
                        for tag in event_list[feed_list[url]["name"] + " feed"][
                            "EventTag"
                        ]
                    ],
                }
                update.append({"feed": update_feed})

        data["feeds"] = update
        with open(kwargs["filename"], "w") as f:
            yaml.dump(data, f)
        return feed_list, event_list

    def update_attributes(self, **kwargs):
        misp_inst = PyMISP(
            url=os.environ.get("MISP_URL", default="https://localhost"),
            ssl=os.environ.get("MISP_SSL", default=False),
            debug=os.environ.get("MISP_DEBUG", default=False),
            key=os.environ.get(
                "MISP_KEY"
            ),
        )
        read_feeds = listing.MISPReader()
        attributes = read_feeds.list_attributes(misp_inst)
        return attributes
