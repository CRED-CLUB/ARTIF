import sys
import requests
import os
import math
from pathlib import Path

import pymongo

p = Path(__file__).parents[1]
sys.path.append(str(p))

def check_ip(ip):
    # First check if it is an IoC, if yes, then return that along with json info and then a score of the same. If not IoC,
    # send the score and if matches either asn, country, org add in description like follows
    # Description, if country matches it will say that this country has a lot of xyz type and xyz feed is maximum observed.
    # Similar for org and similar for ASN

    client = pymongo.MongoClient(
        "mongodb://root:rootpassword@localhost:27017/?authSource=admin"
    )
    ip_db = os.environ.get("IP_DB", default="ip_info")
    score_db = os.environ.get("SCORE_DB", default="score_db")
    ip_info = client[ip_db].history_ips.find_one({"ip": str(ip)})
    return_info = {
        "is_IoC": False,
        "is_Active": False,
        "metadata": {},
        "score": 0,
        "description": "",
	"historical":False,
        "blacklists": "",
        "type": "",
        "verdict": "",
    }
    if not ip_info:
        ip_info = client[ip_db].current_ips.find_one({"ip": str(ip)})
        if not ip_info:
            # new_ip
            meta_ip = requests.get(
                str("http://localhost:3001/json?ip=" + str(ip))
            ).json()
            asn_score = 0
            country_score = 0
            org_score = 0

            maximum = client[score_db].max.find_one({})

            if "asn" in meta_ip:
                asn = client[score_db].asn.find_one({"asn": str(meta_ip["asn"])})
                if asn:
                    asn_score = float(asn["final_score"])

            if "country" in meta_ip:
                country = client[score_db].country.find_one(
                    {"country": str(meta_ip["country"])}
                )
                if country:
                    country_score = float(country["final_score"])

            if "asn_org" in meta_ip:
                org = client[score_db].org.find_one({"org": str(meta_ip["asn_org"])})
                if org:
                    org_score = float(org["final_score"])

            score = math.sqrt(asn_score ** 2 + country_score ** 2 + org_score ** 2)
            max_score = math.sqrt(
                float(maximum["asn"]) ** 2
                + float(maximum["country"]) ** 2
                + float(maximum["org"]) ** 2
            )

            return_info["metadata"] = {
                "asn": meta_ip["asn"] if "asn" in meta_ip else "NA",
                "country": meta_ip["country"] if "country" in meta_ip else "NA",
                "org": meta_ip["asn_org"] if "asn_org" in meta_ip else "NA",
            }

            return_info["score"] = (1 - score / max_score) * 100
            return_info["description"] = "Benign IP according to feeds"
            return_info["verdict"] = (
                "Manual triage needed"
                if return_info["score"] < 40
                else "No action needed"
            )

            return return_info

        else:
            asn = client[score_db].asn.find_one({"asn": str(ip_info["asn"])})
            asn_score = (
                0 if not asn else 0 if asn["asn"] == "NA" else float(asn["final_score"])
            )

            country = client[score_db].country.find_one(
                {"country": str(ip_info["country"])}
            )
            country_score = (
                0
                if not country
                else 0
                if country["country"] == "NA"
                else float(country["final_score"])
            )

            org = client[score_db].org.find_one({"org": str(ip_info["org"])})
            org_score = (
                0 if not org else 0 if org["org"] == "NA" else float(org["final_score"])
            )

            maximum = client[score_db].max.find_one({})

            score = math.sqrt(asn_score ** 2 + country_score ** 2 + org_score ** 2)
            max_score = math.sqrt(
                float(maximum["asn"]) ** 2
                + float(maximum["country"]) ** 2
                + float(maximum["org"]) ** 2
            )

            bl_a_max = {}
            bl_c_max = {}
            bl_o_max = {}
            tg_a_max = {}
            tg_c_max = {}
            tg_o_max = {}
            blacklists_fd = set()
            type_ip = set()
            
            for bl in ip_info["blacklists"]:
                if ip_info["blacklists"][bl] > 0:
                    blacklists_fd.add(bl)

            for ty in ip_info["type"]:
                if ip_info["type"][ty] > 0:
                    type_ip.add(ty)

            country_desc = "{} has "
            return_info["is_IoC"] = True
            return_info["is_Active"] = True
            return_info["metadata"] = (
                {
                    "asn": ip_info["asn"],
                    "country": ip_info["country"],
                    "org": ip_info["org"],
                },
            )
            return_info["score"] = 0
            return_info[
                "description"
            ] = "IP is an active IoC"  
            return_info["verdict"] = "dangerous"
            return_info["blacklists"] = list(blacklists_fd)
            return_info["type"] = list(type_ip)
            return return_info

    else:
        asn = client[score_db].asn.find_one({"asn": str(ip_info["asn"])})
        asn_score = float(asn["final_score"]) if asn else 0

        country = client[score_db].country.find_one(
            {"country": str(ip_info["country"])}
        )
        country_score = float(country["final_score"]) if country else 0

        org = client[score_db].org.find_one({"org": str(ip_info["org"])})
        org_score = float(org["final_score"]) if org else 0

        maximum = client[score_db].max.find_one({})

        score = math.sqrt(asn_score ** 2 + country_score ** 2 + org_score ** 2)
        max_score = math.sqrt(
            float(maximum["asn"]) ** 2
            + float(maximum["country"]) ** 2
            + float(maximum["org"]) ** 2
        )

        bl_a_max = {}
        bl_c_max = {}
        bl_o_max = {}
        tg_a_max = {}
        tg_c_max = {}
        tg_o_max = {}
        blacklists_fd = set()
        type_ip = set()

        for bl in ip_info["blacklists"]:
            if ip_info["blacklists"][bl] > 0:
                blacklists_fd.add(bl)

        for ty in ip_info["type"]:
            if ip_info["type"][ty] > 0:
                type_ip.add(ty)

        country_desc = "{} has "
	
        return_info["blacklists"] = list(blacklists_fd)
        return_info["is_IoC"] = True
        return_info["historical"] = True
        return_info["is_Active"] = False
        return_info["metadata"] = (
            {
                "asn": ip_info["asn"],
                "country": ip_info["country"],
                "org": ip_info["org"],
            },
        )
        return_info["score"] = (score / max_score) * 100
        return_info["description"] = "IP is a historically malicious IP"  
        # If an ip was queried at this endpoint, it goes into the logs from where a sweeper can check scores and on a custom rule alert/add to custom database
        return_info["verdict"] = "suspicious"

        return return_info
