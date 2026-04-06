import os
import time
import socket
import json
import logging
import certifi
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure
from config import MONGODB_URI, MONGODB_DB_NAME, MONGODB_COLLECTION

# Set up logging for MongoDB operations
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
        
        # Check if URI is still the placeholder
        if "<db_username>" in self.uri or "cluster_url" in self.uri:
            logger.warning("MongoDB Atlas URI is not configured correctly. Please update config.py.")
            return False

        try:
            # Use certifi to fix SSL handshake errors on Windows
            self.client = MongoClient(
                self.uri, 
                serverSelectionTimeoutMS=5000,
                tlsCAFile=certifi.where()
            )
            # Trigger a simple command to verify connection
            self.client.admin.command('ping')
            self.db = self.client[self.db_name]
            self.collection = self.db[self.collection_name]
            self._connected = True
            logger.info(f"Successfully connected to MongoDB Atlas database: {self.db_name}")
            return True
        except (ConnectionFailure, OperationFailure) as e:
            logger.error(f"Could not connect to MongoDB Atlas: {e}")
            self._connected = False
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred while connecting to MongoDB: {e}")
            self._connected = False
            return False

    def insert_log(self, log_data):
        """Insert a security log into the Atlas collection."""
        if not self._connected:
            if not self.connect():
                return False

        try:
            # Add metadata if not present
            if "hostname" not in log_data:
                log_data["hostname"] = socket.gethostname()
            
            if "timestamp" not in log_data:
                log_data["timestamp"] = time.time()
            
            # Ensure details is a dict (raw log data)
            if "details" in log_data and isinstance(log_data["details"], str):
                try:
                    log_data["details"] = json.loads(log_data["details"])
                except:
                    pass

            result = self.collection.insert_one(log_data)
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Failed to insert log into MongoDB: {e}")
            return False

# Singleton instance for the project
atlas_client = MongoDBAtlasClient()

def insert_log_to_atlas(event_type, message, details=None, severity="MEDIUM",
                        src_ip="", dst_ip="", protocol="", port=""):
    """
    Wrapper function to be called from the main database layer.
    """
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
