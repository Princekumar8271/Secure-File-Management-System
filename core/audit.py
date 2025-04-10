from datetime import datetime
import sqlite3
import json
import logging
from typing import Dict, Any

class AuditLogger:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._setup_logging()
        
    def _setup_logging(self):
        logging.basicConfig(
            filename='audit.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
    def log_event(self, 
                 user_id: str,
                 action: str,
                 resource_id: str,
                 status: str,
                 metadata: Dict[str, Any] = None):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO audit_logs 
                    (timestamp, user_id, action, resource_id, status, additional_data)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    datetime.now().isoformat(),
                    user_id,
                    action,
                    resource_id,
                    status,
                    json.dumps(metadata or {})
                ))
            logging.info(f"Audit log: {action} by {user_id} on {resource_id}")
        except Exception as e:
            logging.error(f"Audit logging failed: {str(e)}")