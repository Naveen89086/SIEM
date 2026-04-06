from mongodb_storage import atlas_client
import certifi
import pymongo

print(f"Certifi path: {certifi.where()}")
print(f"PyMongo version: {pymongo.version}")

if atlas_client.connect():
    print("SUCCESS: Connected to MongoDB Atlas")
else:
    print("FAILED: Could not connect to MongoDB Atlas")
