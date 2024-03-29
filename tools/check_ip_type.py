# encoding=utf-8
import pymongo
import ipaddr


def check_ip_type():
    db = pymongo.MongoClient('localhost', 27017)['virustotal']['domain']
    ips = db.distinct('iplist.ip', {'tags': 'sinkhole'})
    for ip in ips:
        if ipaddr.IPv4Address(ip).is_unspecified:
            # print '%s -> unspecified' % ip
            continue
        if ipaddr.IPv4Address(ip).is_reserved:
            # print '%s -> reserved' % ip
            continue
        if ipaddr.IPv4Address(ip).is_private:
            # print '%s -> private' % ip
            continue
        if ipaddr.IPv4Address(ip).is_multicast:
            # print '%s -> multicast' % ip
            continue
        if ipaddr.IPv4Address(ip).is_loopback:
            # print '%s -> loopback' % ip
            continue
        if ipaddr.IPv4Address(ip).is_link_local:
            # print '%s -> link_local' % ip
            continue
        print '%s' % ip
        db.update({'iplist.ip': ip, 'tags':'sinkhole'}, {'$pull': {'tags':'sinkhole'}}, multi=True)


check_ip_type()
