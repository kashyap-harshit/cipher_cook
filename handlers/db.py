from database.db import conn_to_db


def store_fingerprint(fingerprint: str):
    hex_fingerprint = fingerprint.encode().hex()

    conn = conn_to_db()
    cursor = conn.cursor()
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS fingerprints(
        id SERIAL PRIMARY KEY,
        hex_fingerprint TEXT UNIQUE NOT NULL
                   )
"""
    
    )
    cursor.execute("""
    SELECT 1 FROM fingerprints WHERE hex_fingerprint = %s
""", (hex_fingerprint,))
    exists = cursor.fetchone()
    if exists:
        print("fingerprint already exists in database")
    else:
        cursor.execute("""
    INSERT INTO fingerprints (hex_fingerprint) VALUES(%s)
""", (hex_fingerprint,))
    conn.commit()
    print(f"stored fingerprint : {hex_fingerprint}")
    cursor.close()
    conn.close()
