from sqlcrypt import *

# run tests
if __name__ == "__main__":
    os.system("rm ./_test_sqlcrypt_")
    conn = Connection("./_test_sqlcrypt_", "pass")
    cursor = conn.cursor()

    with conn:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  value INTEGER DEFAULT 0,
                  name TEXT DEFAULT ''
                )
            """
        )

    with conn:
        for i in range(20):
            cursor.execute(
                """
                INSERT INTO accounts (value, name)
                     VALUES (?, ?)
                """,
                [i, hex(i) * 9999],
            )
            cursor.execute(
                """
                INSERT INTO accounts (value)
                     VALUES (?)
                """,
                [i],
            )

    conn.close()

    # re-open the database

    conn = Connection("./_test_sqlcrypt_", "pass")
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT COUNT(DISTINCT value), COUNT(*), SUM(value)
          FROM accounts
        """
    )
    assert cursor.fetchall() == [(20, 40, 380)]

    for i in range(10):
        cursor.execute(
            """
            SELECT id
              FROM accounts
             WHERE name = ?
            """,
            [hex(i) * 9999],
        )
        assert cursor.fetchall() == [(i * 2 + 1,)]

    # change the password
    conn.change_password("azerty")

    cursor.execute(
        """
        SELECT COUNT(DISTINCT value), COUNT(*), SUM(value)
          FROM accounts
        """
    )
    assert cursor.fetchall() == [(20, 40, 380)]

    conn.close()

    conn = Connection("./_test_sqlcrypt_", "azerty")
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT COUNT(DISTINCT value), COUNT(*), SUM(value)
          FROM accounts
        """
    )
    assert cursor.fetchall() == [(20, 40, 380)]

    for i in range(10):
        cursor.execute(
            """
            SELECT id
              FROM accounts
             WHERE name = ?
            """,
            [hex(i) * 9999],
        )
        assert cursor.fetchall() == [(i * 2 + 1,)]

    with conn:
        cursor.execute(
            """
            UPDATE accounts
               SET name = 'test'
            """
        )

    cursor.execute(
        """
        SELECT COUNT(DISTINCT name)
          FROM accounts
        """
    )
    assert cursor.fetchall() == [(1,)]

    # test with and without key
    # if decrypted version is the same as the "not-encrypted" one
    os.system("rm ./_test_sqlcrypt_")
    conn = Connection("./_test_sqlcrypt_", "pass")
    cursor = conn.cursor()

    with conn:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  value INTEGER DEFAULT 0,
                  name TEXT DEFAULT ''
                )
            """
        )

    with conn:
        for i in range(200):
            cursor.execute(
                """
                INSERT INTO accounts (value, name)
                     VALUES (?, ?)
                """,
                [i, hex(i) * 9999],
            )

    conn.close()

    encrytped_database = open("./_test_sqlcrypt_", "rb").read()
    decrypted_database = decrypt_database("pass", "./_test_sqlcrypt_")
    os.system("rm ./_test_sqlcrypt_")

    conn = apsw.Connection("./_test_sqlcrypt_")
    cursor = conn.cursor()

    with conn:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  value INTEGER DEFAULT 0,
                  name TEXT DEFAULT ''
                )
            """
        )

    with conn:
        for i in range(200):
            cursor.execute(
                """
                INSERT INTO accounts (value, name)
                     VALUES (?, ?)
                """,
                [i, hex(i) * 9999],
            )
    conn.close()

    plain_database = open("./_test_sqlcrypt_", "rb").read()

    assert decrypted_database.startswith(plain_database)
    assert len(decrypted_database) - len(plain_database) < BLOCK_SIZE
    os.system("rm ./_test_sqlcrypt_")
