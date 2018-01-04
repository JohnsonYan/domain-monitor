# encoding=utf-8
import pymongo
import configparser


class Detector(object):
    def __init__(self):
        # config init
        cfg = configparser.ConfigParser()
        cfg.read('config.ini')
        # mongodb init
        self.ddns = pymongo.MongoClient(
            cfg.get('mongodb', 'host'),
            cfg.getint('mongodb', 'port'))[cfg.get('mongodb', 'db')]['test_ddns']
        self.domain = pymongo.MongoClient(
            cfg.get('mongodb', 'host'),
            cfg.getint('mongodb', 'port'))[cfg.get('mongodb', 'db')]['test_domain']
        # 该collection存储每个ip相关联的domain信息
        self.ip2domain = pymongo.MongoClient(
            cfg.get('mongodb', 'host'),
            cfg.getint('mongodb', 'port'))[cfg.get('mongodb', 'db')]['test_ip2domain']

    def add_tags_ddns(self):
        """
        如果一个域名在周期内ip变化了10次以上，变化范围也达到5以上，则认为此域名为DDNS
        给该domain打上ddns的标签
        :return:
        """
        cursor = self.ddns.find({'changing_times': {'$gt': 10}, 'changing_range': {'$gt': 5}})
        for cur in cursor:
            domain = cur.get('original_domain')
            self.domain.update({'original_domain': domain}, {'$addToSet': {'tags': 'ddns'}}, multi=True)
        print 'add tags: ddns'

    def match_ip2domain(self):
        """
        从domain得到所有去重后的IP反向再去匹配domain
        最终，得到一个IP对应所有与之相关的domain的结果
        :return:
        """
        # 这里排除掉被sinkhole的IP
        pipeline = [
            {'$match': {'tags': {'$not': {'$in': ['sinkhole']}}}},
            {'$unwind': '$iplist'},
            {'$group': {'_id': '$iplist'}}
        ]

        ips = self.domain.aggregate(pipeline=pipeline, allowDiskUse=True)

        for i in ips:
            ip = i.get('_id')
            domains = self.domain.find({'iplist': ip})
            for domain in domains:
                self.ip2domain.update({'ip': ip}, {'$addToSet': {'domains': {'domain': domain.get('original_domain'),
                                                                             'family': domain.get('family')}}},
                                      upsert=True)
        print 'match ip2domain'

        # 匹配同一IP对应的domain中，每个family下的domain情况
        # 比如:
        #   family1:[domain1, domain2, ..., domainx]
        #   family2:[domain1, domain2, ..., domainx]
        ips = self.ip2domain.find()
        for data in ips:
            same_family = {}
            for d in data.get('domains'):
                if d.get('family') is not None:
                    for f in d.get('family'):
                        same_family[f] = []
            for d in data.get('domains'):
                if d.get('family') is not None:
                    for f in d.get('family'):
                        same_family[f].append(d.get('domain'))
                    
            self.ip2domain.update({'ip': data.get('ip')}, {'$set': {'same_family': same_family}})
        print 'match same family'

    def detect(self):
        self.add_tags_ddns()
        self.match_ip2domain()


if __name__ == '__main__':
    detector = Detector()
    detector.detect()
