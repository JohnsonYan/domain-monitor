# encoding=utf-8
import time
import datetime
import hashlib
import pymongo
import logging.config
import xlwt

import detector


class Stats(object):
    def __init__(self):
        # schedule config
        self.time_list = 13
        # logging config
        logging.config.fileConfig('logging.conf')
        self.log = logging.getLogger('report')
        # mongodb config
        self.domain = pymongo.MongoClient('localhost', 27017)['virustotal']['domain']
        self.report = pymongo.MongoClient('localhost', 27017)['virustotal']['report']
        self.ddns = pymongo.MongoClient('localhost', 27017)['virustotal']['ddns']
        # 每次创建ddns都是对全部数据的聚合，可以在创建前删除已有的数据
        delete = self.ddns.delete_many({})
        print 'delete all ddns documents. count: %d' % delete.deleted_count
        # report document
        self.daily_report = {}

    def get_daily_stats(self):
        """
        获取各种统计信息
        :return:
        """
        self.daily_report.clear()
        self.daily_report['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        _now = datetime.datetime.now()
        _today = str(_now).split()[0]
        _tomorrow = str(_now + datetime.timedelta(days=1)).split()[0]
        _yestoday = str(_now - datetime.timedelta(days=1)).split()[0]
        # 域名数量计算
        self.daily_report['domain_number'] = self.domain.find({'timestamp': {'$gt': _today, '$lt': _tomorrow}}).count()

        # 标签统计
        self.daily_report['tags_sinkhole_number'] = self.domain.find({'timestamp': {'$gt': _today, '$lt': _tomorrow}, 'tags': 'sinkhole'}).count()
        self.daily_report['tags_active_number'] = self.domain.find({'timestamp': {'$gt': _today, '$lt': _tomorrow}, 'tags': 'active'}).count()
        self.daily_report['tags_inactive_number'] = self.domain.find({'timestamp': {'$gt': _today, '$lt': _tomorrow}, 'tags': 'inactive'}).count()
        self.daily_report['tags_ddns_number'] = self.domain.find({'timestamp': {'$gt': _today, '$lt': _tomorrow}, 'tags': 'ddns'}).count()

        # 日增量计算
        # 今天的domain数量 - 昨天domain数量 = 日增量
        yestoday_domain = self.domain.find({'timestamp': {'$gt': _yestoday, '$lt': _today}}).count()

        self.daily_report['domain_daily_increment'] = self.daily_report.get('domain_number', 0) - yestoday_domain

        # 窗口期增量计算
        _windowl_date = str(_now - datetime.timedelta(days=6)).split()[0]
        _windowr_date = str(_now - datetime.timedelta(days=5)).split()[0]
        window_count = self.domain.find({'timestamp': {'$gt': _windowl_date, '$lt': _windowr_date}}).count()

        self.daily_report['window_increment'] = self.daily_report.get('domain_number', 0) - window_count

    def generate_report(self):
        """
        生成report
        :return:
        """
        self.get_daily_stats()
        self.report.insert(self.daily_report)

    def changing_count(self, md5_list):
        """
        通过md5判断域名是否改变了绑定的ip
        :param md5_list: 每一天的 ip_list 的md5信息
        :return:
        """
        pre_value = ''
        changing_times = 0
        changing_range = 0
        # 获取变化的次数
        for md5 in md5_list:
            if md5 == pre_value:
                continue
            else:
                pre_value = md5
                changing_times += 1
        # 排序后，获取变化的范围
        md5_list.sort()
        pre_value = ''
        for md5 in md5_list:
            if md5 == pre_value:
                continue
            else:
                pre_value = md5
                changing_range += 1

        return [changing_times, changing_range]

    def ddns_detect(self):
        """
        记录每天的域名对应的ip信息，统计域名绑定的ip地址的变化情况
        :return:
        """
        pipeline = [
            {'$match': {'iplist': {'$exists': True}, 'tags': {'$not': {'$in': ['sinkhole']}}}},
            {'$group': {'_id': '$original_domain', 'ipstats': {'$push': '$iplist'}}}
        ]
        domains = self.domain.aggregate(pipeline=pipeline, allowDiskUse=True)

        # 检测domain绑定的ip变化的情况
        for d in domains:
            _domain = d.get('_id')
            md5_list = []

            # 下面循环中每次循环获取一天的iplist,得到每天ip的md5
            ipstats = d.get('ipstats')
            for iplist in ipstats:
                iplist.sort()
                md5 = hashlib.md5(','.join(iplist)).hexdigest()
                md5_list.append(md5)
            # 将ip变化的情况存入数据库
            count = self.changing_count(md5_list)
            d['changing_times'] = count[0]
            d['changing_range'] = count[1]
            d['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
            d['original_domain'] = d.get('_id')
            d.pop('_id')
            self.ddns.insert(d)

    def export2excel(self):
        try:
            keys = ['timestamp',
                    'domain_number',
                    'domain_daily_increment',
                    'window_increment',
                    'tags_active_number',
                    'tags_inactive_number',
                    'tags_sinkhole_number',
                    'tags_ddns_number']
            _now = datetime.datetime.now()
            # _today = str(_now).split()[0]
            _tomorrow = str(_now + datetime.timedelta(days=1)).split()[0]
            _before = str(_now - datetime.timedelta(days=6)).split()[0]

            workbook = xlwt.Workbook(encoding='utf-8')
            worksheet = workbook.add_sheet('domain', cell_overwrite_ok=True)

            data = self.report.find({'timestamp': {'$gt': _before, '$lt': _tomorrow}})
            row = 0
            col = 0
            for d in data:
                if row == 0:
                    for key in keys:
                        worksheet.write(row, col, key)
                        col += 1
                    col = 0
                    row += 1
                for key in keys:
                    worksheet.write(row, col, d.get(key, 'n/a'))
                    col += 1
                col = 0
                row += 1

            workbook.save('report.xls')
        except Exception as msg:
            print msg
            pass

    def schedule(self):
        """
        定时任务，如果当前时刻在self.time_list中，则开始执行任务
        :return:
        """
        # _date = str(datetime.datetime.now()).split()[0]
        _time = datetime.datetime.now()

        if _time.hour == self.time_list:
            self.ddns_detect()
            self.log.info('DDNS detect.')
            detector.Detector().detect()
            self.log.info('detector.py finish')
            self.generate_report()
            self.log.info('Report generation.')
            for key, value in self.daily_report.items():
                self.log.info('\t\t%s [%s]'%(key, value))
            self.export2excel()
            self.log.info('Export to Excel:"report.xls".')


if __name__ == '__main__':
    print '[Stats Running...]'
    s = Stats()
    while True:
        try:
            # 每小时检查一次是否可以开始任务
            s.schedule()
            time.sleep(60 * 60)
        except Exception as msg:
            print msg.message, msg.args
            time.sleep(60 * 60)