# test_db.py
from database.config import DatabaseConfig

def test_connection():
    try:
        db = DatabaseConfig()
        conn = db.get_connection()
        if conn.is_connected():
            print("Successfully connected to MySQL database!")
            
            # Test a simple query
            cursor = conn.cursor()
            cursor.execute("SHOW TABLES")
            tables = cursor.fetchall()
            print("Database tables:")
            for table in tables:
                print(f"- {table[0]}")
            
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"Connection test failed: {e}")

if __name__ == "__main__":
    test_connection()