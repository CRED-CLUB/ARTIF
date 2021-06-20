from django.shortcuts import render
from pymongo import MongoClient

# Create your views here.
def home(request):
    return render(request, "database_connector/home.html", context={"hi": "data_hello"})


def test(request):
    mongo = MongoClient("mongodb://root:rootpassword@localhost:27017/?authSource=admin")
    dbnames = mongo.list_database_names()
    if "ip_rep" in dbnames:
        ret_names = {"hi": "ip_rep is present"}
    else:
        ret_names = {"hi": "ip_rep is not present"}
    return render(request, "database_connector/home.html", context=ret_names)
