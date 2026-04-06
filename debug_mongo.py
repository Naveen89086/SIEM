import pymongo
import certifi

uri = "mongodb+srv://Naveen:shreya6@cluster0.ancn7wb.mongodb.net/siemdb?retryWrites=true&w=majority"

print("Attempting connection to MongoDB Atlas...")
try:
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000, tlsCAFile=certifi.where())
    client.admin.command('ping')
    print("SUCCESS: Ping successful with certifi!")
except Exception as e:
    print(f"FAILED with certifi: {e}")
    try:
        print("Attempting without certifi...")
        client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        print("SUCCESS: Ping successful without certifi!")
    except Exception as e2:
        print(f"FAILED without certifi: {e2}")
