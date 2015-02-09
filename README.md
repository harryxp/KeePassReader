A KeePass 1.x database (.kdb) reader in Python.  It's very easy to read so you can use it to:

- understand KeePass 1.x format
- integrate functionality into your own application

Dependency:

- Python >= 2.6
- pycrypto

This repo includes a test database.  The password is kee.  To use it:

    python KeePassReader test.kdb
