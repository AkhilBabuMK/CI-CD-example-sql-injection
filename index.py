import sqlite3

def vulnerable_query(user_input):
    # Connecting to an in-memory SQLite database
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()
    # Create a dummy users table
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")

    cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'password123')")

    cursor.execute("INSERT INTO users (username, password) VALUES ('user', 'userpass')")
    # Vulnerable SQL query
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    print(f"Executing query: {query}")

    try:
        cursor.execute(query)
        results = cursor.fetchall()
        print("Query results:"
        for row in results:
            print(row)
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        connection.close()
# Simulated user input (potentially malicious)
vulnerable_query("admin' OR '1'='1")

