import sys
from pathlib import Path

from django.apps import AppConfig

p = Path(__file__).parents[1]
sys.path.append(str(p)+"/feed_ingestor")

class FeedIngestorConfig(AppConfig):
    name = "feed_ingestor"

