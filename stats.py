# encoding=utf-8
import time
import datetime
import pymongo
import logging.config


class Stats(object):
    def __init__(self):
        # schedule config
        self.time_list = [11]
        # logging config
        logging.config.fileConfig('logging.conf')
        self.log = logging.getLogger('report')
        # mongodb config
        self.host = 'localhost'
        self.port = 27017
        self.client = pymongo.MongoClient(self.host, self.port)
        self.db = self.client['virustotal']
        self.domain = self.db['domain']
        self.report = self.db['report']
        # report document
        self.daily_report = {}

    def get_daily_stats(self):
        self.daily_report.clear()
        self.daily_report['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        self.daily_report['domain_number'] = self.domain.find({}).count()
        self.daily_report['tags_sinkhole_number'] = self.domain.find({'tags': {'$in': ['sinkhole']}}).count()
        self.daily_report['tags_blocked_number'] = self.domain.find({'tags': {'$in': ['blocked']}}).count()
        self.daily_report['tags_active_number'] = self.domain.find({'tags': {'$in': ['active']}}).count()
        self.daily_report['tags_inactive_number'] = self.domain.find({'tags': {'$in': ['inactive']}}).count()
        self.daily_report['distinct_domain_number'] = len(self.domain.distinct('original_domain'))

        # 日增量计算
        _now = datetime.datetime.now()
        _today = str(_now).split()[0]
        _tomorrow = str(_now + datetime.timedelta(days=1)).split()[0]

        self.daily_report['domain_daily_increment'] = self.domain.find(
            {'timestamp': {'$gt': _today, '$lt': _tomorrow}}
        ).count()
        self.daily_report['distinct_domain_daily_increment'] = len(self.domain.distinct(
            'original_domain',
            {'timestamp': {'$gt': _today, '$lt': _tomorrow}}
        ))

        # 窗口期增量计算
        _windowl_date = str(_now - datetime.timedelta(days=6)).split()[0]
        _windowr_date = str(_now + datetime.timedelta(days=1)).split()[0]

        self.daily_report['window_increment'] = self.domain.find(
            {'timestamp': {'$gt': _windowl_date, '$lt': _windowr_date}}
        ).count()
        self.daily_report['distinct_window_increment'] = len(self.domain.distinct(
            'original_domain',
            {'timestamp': {'$gt': _windowl_date, '$lt': _windowr_date}}
        ))

    def generate_report(self):
        self.get_daily_stats()
        self.report.insert(self.daily_report)

    def schedule(self):
        """
        定时任务，如果当前时刻在self.time_list中，则开始执行任务
        :return:
        """
        # _date = str(datetime.datetime.now()).split()[0]
        _time = str(datetime.datetime.now()).split()[1]

        if int(_time.split(':')[0]) in self.time_list:
            self.generate_report()
            self.log.info('Report generation.')
            for key, value in self.daily_report.items():
                self.log.info('\t\t%s [%s]' % (key, value))


if __name__ == '__main__':
    print '[Stats Running...]'
    s = Stats()
    while True:
        try:
            # 每小时检查一次是否可以开始任务
            s.schedule()
            time.sleep(60 * 60)
        except Exception as msg:
            print msg
