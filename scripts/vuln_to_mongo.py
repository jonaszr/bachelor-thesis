import json

from pymongo import MongoClient

client = MongoClient("localhost", 42692)
db = client.s5_snyk_libio
patch_urls_mongo_collection = db.patchUrls

with open("snyk_maven_vulnerabilities.json") as f:
    new_df = json.load(f)

    db.patchUrls.drop()
    db.patchUrls.insert_many(new_df)