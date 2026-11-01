"""A helper in another module exercises interprocedural source mapping."""

import sqlite3


def find_book(reference):
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE books (ref TEXT, title TEXT)")
    connection.execute("INSERT INTO books VALUES ('BK1', 'A Different Application')")
    result = connection.execute("SELECT ref, title FROM books WHERE ref = '" + reference + "'").fetchall()
    connection.close()
    return result
