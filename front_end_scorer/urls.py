from django.urls import path
from . import views


urlpatterns = [
    path("ip/", views.test, name="test"),
]
