creds.py
========

Harvest FTP/POP/IMAP/HTTP/IRC credentials along with interesting data from each of the protocols. If no interface is specified with the -i option the script will use the internet connected interface it finds via `ip route`. Concatenates fragmented packets so as to not miss any important info.


FTP
* credentials

HTTP
* credentials
* searches made on any site
* URLs visited
* POSTs made

POP/IMAP
* credentials
* To:, From:, Date:, and Subject: headers on emails sent or received

IRC
* credentials
* channels joined/parted
* servers joined/quit
* messages sent and which channel they were sent to







