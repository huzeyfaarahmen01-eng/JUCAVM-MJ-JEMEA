import sqlite3

connection = sqlite3.connect("jemea.db")
cursor = connection.cursor()

cursor.execute("""
    ALTER TABLE messages
    ADD COLUMN created_at TIMESTAMP
""")

connection.commit()
connection.close()

print("Database updated successfully!")