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
        self.start_time = 12
        # queue config
        self._queue = Queue.Queue()
        # threads config
        self.thread_count = 10
        self.count = 0
        # domain resource
        self.domain = pymongo.MongoClient(cfg.get('common', 'host'), cfg.getint('common', 'port'))['virustotal']['maldomain']
        self.local_domain = pymongo.MongoClient(cfg.get('common', 'local_avclass_host'), cfg.getint('common', 'local_avclass_port'))['vtfeed']['maldomain']

    def in_queue(self):
        pipeline = [
            {'$unwind': '$domains'},
            {'$group': {'_id': '$domains.domain'}}
        ]

        data = self.domain.aggregate(pipeline=pipeline, allowDiskUse=True)
        self.count = 0
        for d in data:
            domain = d.get('_id')
            self.count += 1
            self._queue.put(domain)
        print 'put %d domains from remote avclass to queue' % self.count
        # local avclass domain
        data = self.local_domain.aggregate(pipeline=pipeline, allowDiskUse=True)
        self.count = 0
        for d in data:
            domain = d.get('_id')
            self.count += 1
            # print 'put [%d]family: %s in queue' % (self.count, d['family'])
            self._queue.put(domain)
        print 'put %d domains from local avclass to queue' % self.count

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
            print '[info][%s]task: start.' % time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
            self.start_monitor()
            print '[info][%s]task: done.' % time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
            time.sleep(60*60*24)


class WhoisMonitor(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self._queue = queue
        # mongodb config
        self.domain_whois = pymongo.MongoClient(cfg.get('mongodb', 'host'), cfg.getint('mongodb', 'port'))['virustotal']['domain_whois']

        # 临时保存解析结果
        self.whois_doc = {}

    def run(self):
        while not self._queue.empty():
            domain = self._queue.get_nowait()
            try:
                domain = str(domain)
                self.monitor(domain)
            except UnicodeEncodeError as msg:
                # print '[debug:error]%s' % msg.message
                continue

    def monitor(self, domain):
        try:
            self.whois_doc.clear()
            self.whois_doc = whois.whois(domain)

            to_delete = []
            for key in self.whois_doc.keys():
                if self.whois_doc.get(key) is None:
                    to_delete.append(key)
            for key in to_delete:
                self.whois_doc.pop(key)

            self.whois_doc['original_domain'] = domain
            self.whois_doc['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
            self.domain_whois.update({'original_domain': domain}, {'$set': self.whois_doc}, upsert=True)
            # print '[debug]upsert %s' % domain
        except Exception as msg:
            pass
            # print msg


if __name__ == '__main__':

    print '[Running...]'
    mt = MultiThread()
    while True:
        try:
            # 每小时检查一次是否可以开始任务
            mt.schedule()
            time.sleep(60 * 60)
        except Exception as msg:
            pass
            # print msg
