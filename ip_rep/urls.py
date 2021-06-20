"""ip_rep URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.urls import include

urlpatterns = [
    path("admin/", admin.site.urls),
    path(
        "",
        include(
            ("front_end_scorer.urls", "front_end_scorer"), namespace="front_end_scorer"
        ),
    ),  # active scoring mechanism for each ip
    path(
        "feed/",
        include(("feed_ingestor.urls", "feed_ingestor"), namespace="feed_ingestor"),
    ),  # for feed related activities like listing all feeds/events and their properties. Also adding or removing a feed/event
    path(
        "data/",
        include(
            ("database_connector.urls", "database_connector"),
            namespace="database_connector",
        ),
    ),  # for historical data on a particular ASN or ORG (ips seen, feeds spotted in, trend)
]