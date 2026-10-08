import json
import os


BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

KNOWLEDGE_FILE = os.path.join(
    BASE_DIR,
    "data",
    "threat_knowledge.json"
)


def load_knowledge():
    with open(KNOWLEDGE_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def retrieve_ioc(indicator):
    indicator = indicator.strip()

    knowledge = load_knowledge()

    for item in knowledge:
        if item["indicator"].lower() == indicator.lower():
            return item

    return None