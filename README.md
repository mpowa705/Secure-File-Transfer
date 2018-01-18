# Secure-File-Transfer
This program transfers any files between the systems running Client.py and Server.py, encrypted using AES266-CBC with SHA-3 based message integrity verification.

To run, for Server.py run as "python server.py [port] [key]"
For Client.py run as "python Client.py [command] [filename] [hostname:port] [cipher] [key]"

Your choices of commands are "read" or "write" noting whether you wish to download or upload a file from/to the server.

Your choices of ciphers are "aes256", "aes128", or "null" if you want to send/receive files unencrypted.
