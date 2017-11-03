# encoding=utf-8
import time
import datetime
import socket
import Queue
import threading
import logging.config
import pymongo

# logging config
logging.config.fileConfig('logging.conf')
log = logging.getLogger('domain')


class MultiThread(object):
    def __init__(self):
        # schedule config
        self.time_list = [9]
        # mongodb config
        self.host = 'localhost'
        self.port = 27017
        self.client = pymongo.MongoClient(self.host, self.port)
        self.db = self.client['virustotal']
        self.hashmetadata = self.db['hashmetadata']
        self.domain = self.db['domain']
        # queue config
        self._queue = Queue.Queue()
        # threads config
        self.thread_count = 4
        self.count = 0
        # filename
        self.filename_list = 'malware-domains-list'


    def in_queue_from_file(self):
        filename_list = []
        with open(self.filename_list, 'r') as f:
            for line in f:
                filename_list.append(line.strip())
                # TODO:删了下面的break
                #break

        # read each file from filename list
        # translate each domain into ip
        for filename in filename_list:
            with open(filename, 'r') as f:
                for line in f:
                    self._queue.put(line.strip())
                    #print '[Domain in Queue: %d] [Put %s into Queue]' % (self._queue.qsize(), line.strip())

    def in_queue(self):
        data = self.hashmetadata.find({'waldomain': {'$not': {'$size': 0}}}).limit(100)  # limit for test
        self.count = 0
        for d in data:
            domains = d['waldomain']
            for domain in domains:
                self.count += 1
                self._queue.put(domain)

    def start_monitor(self):
        #self.in_queue()
        self.in_queue_from_file()
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

        if int(_time.split(':')[0]) in self.time_list:
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
        self.host = 'localhost'
        self.port = 27017
        self.client = pymongo.MongoClient(self.host, self.port)
        self.db = self.client['virustotal']
        self.domain = self.db['domain']
        # 临时保存解析结果
        self.document = {}

    def run(self):
        while not self._queue.empty():
            domain = self._queue.get_nowait()
            self.monitor(domain)

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
                self.document['tags'] = ['%s: %s' % (str(msg.errno), msg.strerror)]
                #print msg.errno,msg.strerror

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

    def monitor(self, domain):
        """
        域名监控的主函数，包括数据库的存取，域名解析，打标签等功能
        :return:
        """
        self.document.clear()
        # log.debug('[Parsed %d] Start parsing domain: %s' % (count, domain))
        ip = self.domain2ip(domain)
        if len(ip) > 0:
            self.document['original_domain'] = domain
            self.document['parsed_domain'] = ip[0]
            self.document['aliaslist'] = ip[1]
            self.document['iplist'] = []
            for _ip in ip[2]:
                self.document['iplist'].append({'ip': str(_ip), 'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))})
            self.document['tags'] = ['active']
            self.set_tag()
        else:
            self.document['original_domain'] = domain

        self.document['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        # 存入数据库-Collection: domain
        self.domain.insert(self.document)

    def clean_outdated_domains(self):
        """
        删除60天前的域名文档
        :return:
        """
        _now = datetime.datetime.now()
        # 计算60天前的时间
        _outdate = str(_now - datetime.timedelta(days=60))
        deleted_count = self.domain.delete_many({'timestamp': {'$lt': _outdate}}).deleted_count
        log.info('Clean outdated(60 days ago) domains [deleted_count: %d]' % deleted_count)


if __name__ == '__main__':

    print '[Running...]'
    mt = MultiThread()
    while True:
        try:
            # 每小时检查一次是否可以开始任务
            mt.schedule()
            time.sleep(60*60)
        except Exception as msg:
            print msg