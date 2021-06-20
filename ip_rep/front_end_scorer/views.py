import re
import json

from django.shortcuts import render
from django.http import JsonResponse

from . import main_scorer

def test(request):
    ip = request.GET.get("ip", "")
    return get_response(ip)

def get_response(ip):
    if not ip:
        return JsonResponse({"description":"Enter IP"})
    elif bool(re.search('^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',ip)):
        if ip.startswith("172.") or ip.startswith("192.168.") or ip.startswith("10."):
            return JsonResponse({"description": "Private IP"})
        else:
            info = main_scorer.check_ip(ip)
            return JsonResponse(info)
    else:
        return JsonResponse({"description":"Enter valid IP"})
