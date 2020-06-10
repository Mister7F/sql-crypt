# SQLCrypt

Protect your SQLite database with AES !


SQLCrypt use AES in CBC mode to encrypt your database, HMAC-SHA256 to sign your data and scrypt as key derivation function.

# Installation
Just run
> pip install sqlcrypt

Or, if you want to be sure to have the latest version
> pip install git+ssh://git@github.com/mister7f/sqlcrypt.git

# Usage
SQLCrypt is based on APSW, you can initialize your database with your password and then just use it use you use APSW.

```python
from sqlcrypt import Connection


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
```


