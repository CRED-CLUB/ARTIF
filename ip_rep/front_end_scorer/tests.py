import requests
import json

from front_end_scorer.views import get_response
from django.test import TestCase

# Create your tests here.
class front_end_scorer_test(TestCase):
    
    def test_for_negative_ip(self):
        response = get_response("-127.0.0.1")
        self.assertEqual(response.content.decode(),'{"description": "Enter valid IP"}')

    def test_for_empty_ip(self):
        response = get_response("")
        self.assertEqual(response.content.decode(),'{"description": "Enter IP"}')
    
    def test_for_private_ip(self):
        response = get_response("192.168.122.2")
        self.assertEqual(response.content.decode(),'{"description": "Private IP"}')

    def test_for_ip(self):
        response = get_response("127.0.0.1")
        resp = json.loads(response.content.decode())
        self.assertEqual(len(resp.keys()),9)
