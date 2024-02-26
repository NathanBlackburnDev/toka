import sqlite3

# Database class for CRUD operations
class Database:
    # Initalise database name
    def __init__(self):
        self.DBname = 'database.db'

    # Connection method
    def connect(self):
        conn = None
        try:
            conn = sqlite3.connect(self.DBname)
        except Exception as e:
            print(e)

        return conn
    
    # Close database method
    def disconnect(self, conn):
        conn.close()

    # Query database method
    def queryDB(self, command, params=[]):
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(command, params)
        result = cur.fetchall()
        self.disconnect(conn)
        return result
    
    # Update database method
    def updateDB(self, command, params=[]):
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(command, params)
        conn.commit()                           # Commit changes
        result = cur.fetchall()
        self.disconnect(conn)
        return result