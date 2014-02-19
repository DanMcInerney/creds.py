creds.py
========

Harvest FTP/POP/IMAP/HTTP/IRC credentials along with interesting data from each of the protocols. If no interface is specified with the -i option the script will use the internet connected interface it finds via `ip route`. Concatenates fragmented packets so as to not miss any important info. Upon catching a Ctrl-C, will print a list of credentials for each IP address that was sniffed on the network along with the server they sent them to.


``` shell
python creds.py [-i INTERFACE] [-v] [-p PCAPFILE]
```


### Info gathered:
FTP
* credentials per server

HTTP
* credentials per server
* searches made on any site
* URLs visited
* POSTs made

POP/IMAP
* credentials per server
* To:, From:, Date:, and Subject: headers on emails sent or received

IRC
* credentials per server
* channels joined/parted
* servers joined/quit
* messages sent and which channel they were sent to

------
* danmcinerney.org
* [![Flattr this](http://api.flattr.com/button/flattr-badge-large.png)](https://flattr.com/submit/auto?user_id=DanMcInerney&url=https://github.com/DanMcInerneycreds.py&title=creds.py&language=&tags=github&category=software) 
