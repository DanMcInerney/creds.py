*****************************************************************************
New version with lots more parsing: https://github.com/DanMcInerney/net-creds
*****************************************************************************


creds.py
========

Harvest FTP/POP/IMAP/HTTP/IRC credentials along with interesting data from each of the protocols. If no interface is specified with the -i option the script will use the internet connected interface it finds via `ip route`. Concatenates fragmented packets so as to not miss any important info. Upon catching a Ctrl-C, will print a list of credentials for each IP address that was sniffed on the network along with the server they sent them to.


``` shell
python creds.py [-i INTERFACE] [-v] [-p PCAPFILE]
```

Requires: python 2.7, scapy python module, linux


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

License
-------
Copyright (c) 2013, Dan McInerney
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
* Neither the name of Dan McInerney nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


***
* danmcinerney.org
* [![Flattr this](http://api.flattr.com/button/flattr-badge-large.png)](https://flattr.com/submit/auto?user_id=DanMcInerney&url=https://github.com/DanMcInerneycreds.py&title=creds.py&language=&tags=github&category=software) 
