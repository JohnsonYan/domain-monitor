# encoding=utf-8
import pymongo


class MatchC2(object):
    def __init__(self):
        # domain mongodb config
        self.client_domain = pymongo.MongoClient('localhost', 27017)
        self.db_domain = self.client_domain['virustotal']
        self.domain = self.db_domain['domain']
        self.c2 = self.db_domain['c2']
        # # c2 ip mongodb config
        # self.client_c2 = pymongo.MongoClient('172.16.100.32', 27017)
        # self.db_c2 = self.client_c2['HanSight']
        # self.ioc = self.db_c2['ioc']

    def get_domain(self):
        ips = []
        with open('c2-ip.list', 'r') as f:
            for line in f:
                ips.append(line.strip())
        count = 0
        for ip in ips:
            if self.match(ip):
                count += 1
                print '[%d] Matched %s' % (count, ip)
        print 'FINISH...'

    def match(self, ip):
        flag = False
        data = self.domain.find({'iplist.ip': ip})
        if data.count() > 0:
            results = dict()
            results['ip'] = ip
            results['match_record'] = []
            for d in data:
                results['match_record'].append({'timestamp': d['timestamp'],
                                                'original_domain': d['original_domain'],
                                                'parsed_domain': d['parsed_domain']})
            self.c2.insert(results)
            flag = True
        return flag


if __name__ == '__main__':
    MatchC2().get_domain()
