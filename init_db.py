import sqlite3

connection = sqlite3.connect('moneybase.db')

with open('schema.sql') as f:
    connection.executescript(f.read())

cur = connection.cursor()

cur.execute("INSERT INTO posts (title, content) VALUES (?, ?)",("post1", "content1"))

connection.commit()
connection.close()


