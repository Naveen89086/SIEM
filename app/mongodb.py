import os
import time
import socket
import json
import logging
import certifi
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure
from app.config import MONGODB_URI, MONGODB_DB_NAME, MONGODB_COLLECTION

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("MongoDBStorage")

class MongoDBAtlasClient:
    def __init__(self):
        self.uri = MONGODB_URI
        self.db_name = MONGODB_DB_NAME
        self.collection_name = MONGODB_COLLECTION
        self.client = None
        self.db = None
        self.collection = None
        self._connected = False

    def connect(self):
        """Establish connection to MongoDB Atlas."""
        if self._connected:
            return True
        
        if not self.uri or "<db_username>" in self.uri:
            logger.warning("MongoDB Atlas URI is not configured correctly.")
            return False

        try:
            self.client = MongoClient(
                self.uri, 
                serverSelectionTimeoutMS=5000,
                tlsCAFile=certifi.where()
            )
            self.client.admin.command('ping')
            self.db = self.client[self.db_name]
            self.collection = self.db[self.collection_name]
            self._connected = True
            logger.info(f"Connected to MongoDB Atlas: {self.db_name}")
            return True
        except (ConnectionFailure, OperationFailure) as e:
            logger.error(f"Could not connect to MongoDB Atlas: {e}")
            self._connected = False
            return False
        except Exception as e:
            logger.error(f"Unexpected error connecting to MongoDB: {e}")
            self._connected = False
            return False

    def insert_log(self, log_data):
        if not self._connected:
            if not self.connect():
                return False

        try:
            if "hostname" not in log_data:
                log_data["hostname"] = socket.gethostname()
            if "timestamp" not in log_data:
                log_data["timestamp"] = time.time()

            result = self.collection.insert_one(log_data)
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Failed to insert log into MongoDB: {e}")
            return False

atlas_client = MongoDBAtlasClient()

def insert_log_to_atlas(event_type, message, details=None, severity="MEDIUM",
                        src_ip="", dst_ip="", protocol="", port=""):
    log_document = {
        "timestamp": time.time(),
        "event_type": event_type,
        "message": message,
        "severity": severity,
        "src_ip": src_ip or "0.0.0.0",
        "dst_ip": dst_ip or "0.0.0.0",
        "protocol": protocol or "UNKNOWN",
        "port": port,
        "details": details or {},
        "hostname": socket.gethostname()
    }
    return atlas_client.insert_log(log_document)
