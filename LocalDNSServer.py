import socket
import time
import dnslib
import random

# UDP socket as server
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(('127.0.0.1', 12000))

# List about the domain name and IPv4 address of root DNS servers
root = [('a.root-servers.net', '198.41.0.4'),
        ('b.root-servers.net', '199.9.14.201'),
        ('c.root-servers.net', '192.33.4.12'),
        ('d.root-servers.net', '199.7.91.13'),
        ('e.root-servers.net', '192.203.230.10'),
        ('f.root-servers.net', '192.5.5.241'),
        ('g.root-servers.net', '192.112.36.4'),
        ('h.root-servers.net', '198.97.190.53'),
        ('i.root-servers.net', '192.36.148.17'),
        ('j.root-servers.net', '192.58.128.30'),
        ('k.root-servers.net', '193.0.14.129'),
        ('l.root-servers.net', '199.7.83.42'),
        ('m.root-servers.net', '202.12.27.33')]

# UDP socket as client to forward query
dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

cache = {}


def has_cached(qname, qtype):
    # check if the content is cached
    if qname not in cache:
        cache[qname] = {}
    if qtype not in cache[qname]:
        return False

    # check if the content is time out
    content = cache[qname][qtype]
    current_time = (time.time())
    if current_time - content[0] >= content[1]:
        return False
    return True


def get_from_cache(qname, qtype, qheader):
    # create response message from cache
    res = dnslib.DNSRecord(
        dnslib.DNSHeader(id=qheader.id, qr=1, q=qheader.q, r=cache[qname][qtype][2], auth=cache[qname][qtype][3],
                         ra=cache[qname][qtype][4]), q=dnslib.DNSQuestion(qname, qtype), rr=cache[qname][qtype][5],
        auth=cache[qname][qtype][6], ar=cache[qname][qtype][7])
    return bytes(res.pack())


def add_cache(qname, qtype, message):
    record = dnslib.DNSRecord.parse(message)

    cur_t = int(time.time())  # record current time
    ttl = 9999999999999999999999999999

    # calculate the minimum ttl
    for rr in record.rr:
        ttl = min(ttl, rr.ttl)

    # store all information in cache
    cache[str(qname)][qtype] = [cur_t, ttl, record.header.a, record.header.auth, record.header.ar,
                                record.rr, record.auth, record.ar]


# implement iterative query

def get_address(message):
    tmp = []
    tmpreq = dnslib.DNSRecord.parse(message)
    tmpreq.header.rd = 0
    message = bytes(tmpreq.pack())
    if has_cached(str(tmpreq.q.qname), tmpreq.q.qtype):  # check if the query is cached
        return get_from_cache(str(tmpreq.q.qname), tmpreq.q.qtype, tmpreq.header)  # get reply from cache
    nextaddr = root[random.randint(0, 12)][1]  # initiate next address with the address of root name server
    while True:
        dns.sendto(message, (nextaddr, 53))  # forward query to next name server
        msgg = dns.recv(4096)
        tmpreq = dnslib.DNSRecord.parse(msgg)
        if tmpreq.header.a != 0:  # if the response has response RR
            flag = False
            for rr in tmpreq.rr:
                if rr.rtype == 1:
                    flag = True
                    break
            # if no A RR
            if not flag:
                tmp.extend(tmpreq.rr)
                # modify query message
                tmppreq = dnslib.DNSRecord.parse(msg)
                tmppreq.q.qname = str(tmpreq.rr[0].rdata)
                msgg = bytes(tmppreq.pack())
                msgg = get_address(msgg)
                # add the CNAME RR
                tmppreq = dnslib.DNSRecord.parse(msgg)
                tmp.extend(tmppreq.rr)
                tmppreq.rr = tmp
                msgg = bytes(tmppreq.pack())
                add_cache(str(req.q.qname), req.q.qtype, msgg)  # add cache
                response_msg = get_from_cache(str(req.q.qname), req.q.qtype,
                                              req.header)  # use cache to create answer
                return response_msg
            else:
                # if no A RR
                # add the CNAME RR
                tmppreq = dnslib.DNSRecord.parse(msgg)
                tmp.extend(tmppreq.rr)
                tmppreq.rr = tmp
                tmppreq.header.a = len(tmpreq.rr)
                msgg = bytes(tmppreq.pack())
                add_cache(str(req.q.qname), req.q.qtype, msgg)  # add cache
                response_msg = get_from_cache(str(req.q.qname), req.q.qtype,
                                              req.header)  # use cache to create answer
                return response_msg
        flag = False
        for rr in tmpreq.ar:  # find if next address is in ar
            if rr.rtype == 1:
                nextaddr = str(rr.rdata)  # set the address of the next server
                flag=True
                break
        if not flag and tmpreq.header.auth != 0 and tmpreq.header.a == 0:  # if next address is not in ar
            # find next address
            tmppreq = dnslib.DNSRecord.parse(message)
            tmppreq.q.qname = dnslib.DNSLabel(str(tmpreq.auth[0].rdata))
            msggg = bytes(tmppreq.pack())
            msggg = get_address(msggg)
            tmppreq = dnslib.DNSRecord.parse(msggg)
            nextaddr = str(tmppreq.rr[0].rdata)


if __name__ == '__main__':
    while True:
        msg, addr = server.recvfrom(2048)  # receive query from client
        req = dnslib.DNSRecord.parse(msg)  # convert bytes to DNSRecord
        print('Query [name=%s, type=%s]' % (
            str(req.q.qname), dnslib.QTYPE.get(req.q.qtype)))
        resmsg = b''
        if has_cached(str(req.q.qname), req.q.qtype):  # check if the query is cached
            print('Get from cache')
            resmsg = get_from_cache(str(req.q.qname), req.q.qtype, req.header)  # get reply from cache
            server.sendto(resmsg, addr)
        else:
            if not req.header.rd:
                print('Get from iterative query')
                dns.sendto(msg, ('114.114.114.114', 53))  # forward query to a public dns server
                msg = dns.recv(2048)
                add_cache(str(req.q.qname), req.q.qtype, msg)  # add cache
                resmsg = get_from_cache(str(req.q.qname), req.q.qtype,
                                        req.header)  # use cache to create answer
            else:
                print('Get from recursive query')
                resmsg = get_address(msg)
        server.sendto(resmsg, addr)  # send answer to client
