import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "phantomwatch.db")

class DatabaseHandler:
    """Handles database operations for PhantomWatch."""
    
    def __init__(self, db_path=DB_PATH):
        """Initialize database connection."""
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self.initialize_db()

    def initialize_db(self):
        """Initialize the database schema if not already created."""
        with open(os.path.join(os.path.dirname(__file__), "schema.sql"), "r") as schema_file:
            self.conn.executescript(schema_file.read())
        self.conn.commit()

    def execute_query(self, query, params=(), fetch_one=False, fetch_all=False):
        """Executes a query with optional fetching."""
        try:
            self.cursor.execute(query, params)
            self.conn.commit()
            if fetch_one:
                return self.cursor.fetchone()
            if fetch_all:
                return self.cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return None

    def insert_incident(self, title, description, severity):
        """Inserts a new incident into the database."""
        query = """
        INSERT INTO incidents (title, description, severity) 
        VALUES (?, ?, ?)
        """
        self.execute_query(query, (title, description, severity))

    def get_incidents(self, severity=None, status=None):
        """Retrieves incidents based on severity and status filters."""
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        if status:
            query += " AND status = ?"
            params.append(status)

        return self.execute_query(query, params, fetch_all=True)

    def update_incident_status(self, incident_id, status):
        """Updates the status of an incident."""
        query = "UPDATE incidents SET status = ? WHERE id = ?"
        self.execute_query(query, (status, incident_id))

    def insert_threat_intel(self, source, indicator, type, confidence):
        """Inserts new threat intelligence data."""
        query = """
        INSERT INTO threat_intel (source, indicator, type, confidence) 
        VALUES (?, ?, ?, ?)
        """
        self.execute_query(query, (source, indicator, type, confidence))

    def get_threat_intel(self, indicator=None):
        """Retrieves threat intelligence data."""
        query = "SELECT * FROM threat_intel WHERE 1=1"
        params = []
        
        if indicator:
            query += " AND indicator = ?"
            params.append(indicator)

        return self.execute_query(query, params, fetch_all=True)

    def insert_log(self, module, message, level):
        """Inserts a log entry into the database."""
        query = "INSERT INTO logs (module, message, level) VALUES (?, ?, ?)"
        self.execute_query(query, (module, message, level))

    def get_logs(self, level=None, module=None):
        """Retrieves logs based on level or module."""
        query = "SELECT * FROM logs WHERE 1=1"
        params = []
        
        if level:
            query += " AND level = ?"
            params.append(level)
        
        if module:
            query += " AND module = ?"
            params.append(module)

        return self.execute_query(query, params, fetch_all=True)

    def close(self):
        """Closes the database connection."""
        self.conn.close()
