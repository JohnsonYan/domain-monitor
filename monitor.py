# encoding=utf-8
import time
import datetime
import socket
import logging.config
import pymongo


class DomainMonitor(object):
    """
    域名监控
    1. 定时从数据库获取到domains，解析其ip，打上tag，存入数据库中
    2. 定时清理老化的域名文档
    每天定时执行
    """
    def __init__(self):
        # schedule config
        self.time_list = [17]
        # mongodb config
        self.host = '172.16.100.168'
        self.port = 27017
        self.client = pymongo.MongoClient(self.host, self.port)
        self.db = self.client['virustotal']
        self.hashmetadata = self.db['hashmetadata']
        self.domain = self.db['domain']
        # logging config
        logging.config.fileConfig('logging.conf')
        self.log = logging.getLogger('default')
        # 临时保存解析结果
        self.document = {}

    def domain2ip(self, domain):
        """
        将输入的domain转换为ip
        :param domain: domain name
        :return: ip = [domain, aliaslist, ipaddrlist]
        """
        ip = []
        try:
            ip = socket.gethostbyname_ex(domain)
        except socket.error as msg:
            # -2 Name or service not known
            if msg.errno == -2:
                self.document['tags'] = ['inactive']
                #print msg.errno, msg.strerror
            else:
                self.document['tags'] = [str(msg.errno)]

        return ip

    def set_tag(self):
        """
        为域名添加标记
        :return:
        """
        if 'sinkhole' in self.document['parsed_domain']:
            self.document['tags'].append('sinkhole')
        else:
            for _ip in self.document['iplist']:
                if '127.0.0.1' == _ip['ip']:
                    self.document['tags'].append('blocked')
                    break

    def monitor(self):
        """
        域名监控的主函数，包括数据库的存取，域名解析，打标签等功能
        :return:
        """
        self.log.info('Task Started.')
        count = 0

        data = self.hashmetadata.find({'waldomain': {'$not': {'$size': 0}}}).limit(1000)    # limit for test
        for d in data:
            domains = d['waldomain']
            for domain in domains:
                count += 1
                self.document.clear()
                #self.log.debug('[Parsed %d] Start parsing domain: %s' % (count, domain))

                ip = self.domain2ip(domain)
                if len(ip) > 0:
                    self.document['original_domain'] = domain
                    self.document['parsed_domain'] = ip[0]
                    self.document['aliaslist'] = ip[1]
                    self.document['iplist'] = []
                    for _ip in ip[2]:
                        self.document['iplist'].append({'ip': str(_ip), 'timestamp': str(datetime.datetime.now())})
                    self.document['tags'] = ['active']
                    self.set_tag()
                else:
                    self.document['original_domain'] = domain

                self.document['timestamp'] = str(datetime.datetime.now()).split()
                # 存入数据库-Collection: domain
                self.domain.insert(self.document)
        self.log.info('Task Completed.')

    def clean_outdated_domains(self):
        """
        删除60天前的域名文档
        :return:
        """
        _now = datetime.datetime.now()
        # 计算60天前的时间
        _outdate = str(_now - datetime.timedelta(days=60)).split()[0]
        deleted_count = self.domain.delete_many({'timestamp': {'$in': [_outdate]}}).deleted_count
        self.log.info('Clean outdated(60 days ago) domains [deleted_count: %d]' % deleted_count)

    def schedule(self):
        """
        定时任务，如果当前时刻在self.time_list中，则开始执行任务
        :return:
        """
        # _date = str(datetime.datetime.now()).split()[0]
        _time = str(datetime.datetime.now()).split()[1]

        if int(_time.split(':')[0]) in self.time_list:
            self.monitor()
            self.clean_outdated_domains()


if __name__ == '__main__':

    print '[Running...]'
    DomainMonitor = DomainMonitor()
    while True:
        try:
            # 每小时检查一次是否可以开始任务
            DomainMonitor.schedule()
            time.sleep(60*60)
        except Exception as msg:
            print msg

