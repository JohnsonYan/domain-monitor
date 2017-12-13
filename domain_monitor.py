# encoding=utf-8
import time
import datetime
import socket
import Queue
import threading
import logging.config
import pymongo
import configparser
import ipaddr

# config init
cfg = configparser.ConfigParser()
cfg.read('config.ini')
# logging config
logging.config.fileConfig(cfg.get('common', 'log_config'))
log = logging.getLogger(cfg.get('common', 'logger'))


class MultiThread(object):
    def __init__(self):
        # schedule config
        self.start_time = cfg.getint('common', 'start_time')
        # queue config
        self._queue = Queue.Queue()
        # threads config
        self.thread_count = cfg.getint('common', 'threads_num')
        self.count = 0
        # filename
        self.filename = cfg.get('common', 'filename')
        # domain resource
        self.domain = pymongo.MongoClient(cfg.get('common', 'host'),
                                          cfg.getint('common', 'port'))[cfg.get('common', 'db')][
            cfg.get('common', 'collection')]

    def in_queue_from_file(self):
        # read each line from file
        # translate each domain into ip
        with open(self.filename, 'r') as f:
            for line in f:
                self._queue.put([line.strip(), ''])
                # print '[Domain in Queue: %d] [Put %s into Queue]' % (self._queue.qsize(), line.strip())

    def in_queue(self):
        # batch_size，小一些防止cursor失效
        data = self.domain.find().batch_size(10)
        self.count = 0
        for d in data:
            domains = d['domains']
            self.count += 1
            # print 'put [%d]family: %s in queue' % (self.count, d['family'])
            for domain in domains:
                self._queue.put([domain['domain'], d['family']])

    def start_monitor(self):
        self.in_queue()
        # self.in_queue_from_file()
        threads = []
        for i in range(self.thread_count):
            threads.append(DomainMonitor(self._queue))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def schedule(self):
        """
        定时任务，如果当前时刻在self.time_list中，则开始执行任务
        :return:
        """
        # _date = str(datetime.datetime.now()).split()[0]
        _time = str(datetime.datetime.now()).split()[1]

        if datetime.datetime.now().hour == self.start_time:
            log.info('Task Started.')
            self.start_monitor()
            log.info('Task Completed.')
            DomainMonitor(self._queue).clean_outdated_domains()


class DomainMonitor(threading.Thread):
    """
    域名监控
    1. 定时从数据库获取到domains，解析其ip，打上tag，存入数据库中
    2. 定时清理老化的域名文档
    每天定时执行
    """

    def __init__(self, queue):
        threading.Thread.__init__(self)
        self._queue = queue
        # mongodb config
        self.host = cfg.get('mongodb', 'host')
        self.port = cfg.getint('mongodb', 'port')
        self.client = pymongo.MongoClient(self.host, self.port)
        self.db = self.client[cfg.get('mongodb', 'db')]
        self.domain = self.db[cfg.get('mongodb', 'collection')]
        self.domain_ip = self.db[cfg.get('mongodb', 'domain_ip')]
        # 临时保存解析结果
        self.document = {}
        self.simplify_doc = {}

    def run(self):
        while not self._queue.empty():
            domain = self._queue.get_nowait()
            # print 'domain: %s , family: %s' % (domain[0], domain[1])
            self.monitor(domain[0], domain[1])

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
                # print msg.errno, msg.strerror
            else:
                self.document['tags'] = ['%s: %s' % (str(msg.errno), msg.strerror)]
                # print msg.errno,msg.strerror
        except UnicodeEncodeError as msg:
            self.document['tags'] = ['DomainUnicodeEncodeError']

        return ip

    def set_tag(self, ips):
        """
        为域名添加标记
        :return:
        """
        flag = False
        for ip in ips:
            # 如果解析为下述六种之一，则认为该域名被沉洞
            check = ipaddr.IPv4Address(ip)
            if (check.is_link_local or check.is_loopback
                or check.is_private or check.is_unspecified):
                continue
            else:
                flag = True
        if flag is False:
            self.document['tags'].append('sinkhole')
        return flag

    def monitor(self, domain, family):
        """
        域名监控的主函数，包括数据库的存取，域名解析，打标签等功能
        :return:
        """
        self.document.clear()
        # log.debug('[Parsed %d] Start parsing domain: %s' % (count, domain))
        ip = self.domain2ip(domain)
        self.document['original_domain'] = domain
        self.document['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        self.document['family'] = family
        if len(ip) > 0:
            for _ip in ip[2]:
                self.simplify_doc.clear()
                check = ipaddr.IPv4Address(_ip)
                if check.is_link_local or check.is_loopback or check.is_private or check.is_unspecified:
                    continue
                self.simplify_doc['original_domain'] = domain
                self.simplify_doc['ip'] = str(_ip)
                self.simplify_doc['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                self.domain_ip.insert(self.simplify_doc)

            self.document['parsed_domain'] = ip[0]
            self.document['aliaslist'] = ip[1]
            ips = []
            for _ip in ip[2]:
                ips.append(str(_ip))
            self.document['tags'] = ['active']
            flag = self.set_tag(ips)
            # flag == false, domain被sinkhole
            # 下面这个段代码用于将sinkhole域名时间保持在第一次检测出来的时间
            if not flag:
                data = self.domain.find_one({'original_domain': domain})
                if data is not None:
                    self.document['timestamp'] = data['timestamp']

            # 根据是否能解析出ip地址，数据库操作有所不同 1
            # 存入数据库-Collection: domain
            self.domain.update({'original_domain': domain},
                               {'$set': self.document,
                                '$addToSet': {'iplist': {'ip': ips, 'timestamp': time.strftime('%Y-%m-%d %H:%M:%S',
                                                                                               time.localtime(
                                                                                                   time.time()))}}
                                },
                               upsert=True)
        else:
            # 根据是否能解析出ip地址，数据库操作有所不同 2
            # 存入数据库-Collection: domain
            self.domain.update({'original_domain': domain},
                               {'$set': self.document},
                               upsert=True)

    def clean_outdated_domains(self):
        """
        删除60天前的ip记录
        :return:
        """
        _now = datetime.datetime.now()
        # 计算60天前的时间
        _outdate = str(_now - datetime.timedelta(days=cfg.getint('common', 'days')))

        self.domain.update({}, {'$pull': {'iplist': {'timestamp': {'$lt': _outdate}}}}, multi=True)
        # print 'Clean outdated domains. Outdate time: %s' % _outdate
        log.info('Clean outdated domains. Outdate time: %s' % _outdate)


if __name__ == '__main__':

    print '[Running...]'
    mt = MultiThread()
    while True:
        try:
            # 每小时检查一次是否可以开始任务
            mt.schedule()
            time.sleep(60 * 60)
        except Exception as msg:
            print msg
