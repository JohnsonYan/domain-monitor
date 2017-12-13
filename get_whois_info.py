# encoding=utf-8
import time
import datetime
import Queue
import threading
import pymongo
import configparser
import whois

# config init
cfg = configparser.ConfigParser()
cfg.read('config.ini')


class MultiThread(object):
    def __init__(self):
        # schedule config
        self.start_time = 14
        # queue config
        self._queue = Queue.Queue()
        # threads config
        self.thread_count = 50
        self.count = 0
        # domain resource
        self.domain = pymongo.MongoClient(cfg.get('common', 'host'),
                                          cfg.getint('common', 'port'))[cfg.get('common', 'db')][
            cfg.get('common', 'collection')]

    def in_queue(self):
        # batch_size，小一些防止cursor失效
        data = self.domain.find().batch_size(10)
        self.count = 0
        for d in data:
            domains = d['domains']
            self.count += 1
            for domain in domains:
                self._queue.put(domain['domain'])

    def start_monitor(self):
        self.in_queue()
        # self.in_queue_from_file()
        threads = []
        for i in range(self.thread_count):
            threads.append(WhoisMonitor(self._queue))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def schedule(self):
        """
        定时任务，如果当前时刻在self.time_list中，则开始执行任务
        :return:
        """
        if datetime.datetime.now().hour == self.start_time:
            self.start_monitor()
            print '[%s]task: get whois infomation done today.' % time.strftime('%Y-%m-%d %H:%M:%S',
                                                                               time.localtime(time.time()))


class WhoisMonitor(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self._queue = queue
        # mongodb config
        self.host = cfg.get('mongodb', 'host')
        self.port = cfg.getint('mongodb', 'port')
        self.client = pymongo.MongoClient(self.host, self.port)
        self.db = self.client[cfg.get('mongodb', 'db')]
        self.domain = self.db[cfg.get('mongodb', 'collection')]
        self.domain_whois = self.db['domain_whois']
        # 临时保存解析结果
        self.whois_doc = {}

    def run(self):
        while not self._queue.empty():
            domain = self._queue.get_nowait()
            self.monitor(domain)

    def monitor(self, domain):
        for i in range(3):
            try:
                self.whois_doc.clear()
                self.whois_doc = whois.whois(str(domain))
                if self.whois_doc is not None:
                    self.whois_doc['original_domain'] = domain
                    self.whois_doc['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                    self.domain_whois.update({'original_domain': domain}, {'$set': self.whois_doc}, upsert=True)
                    print 'upsert %s'%domain
                else:
                    print 'à'*50
            except Exception:
                if i >= 2:
                    print 'reach max retries,%s' % domain
                else:
                    time.sleep(3)
            else:
                time.sleep(0.1)
                break


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
