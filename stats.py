# encoding=utf-8
import time
import datetime
import hashlib
import pymongo
import logging.config
import xlwt


class Stats(object):
    def __init__(self):
        # schedule config
        self.time_list = [13]
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
        self.ddns = self.db['ddns']
        # report document
        self.daily_report = {}

    def get_daily_stats(self):
        """
        获取各种统计信息
        :return:
        """
        self.daily_report.clear()
        self.daily_report['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

        # 域名数量计算
        self.daily_report['domain_number'] = self.domain.find({}).count()
        self.daily_report['distinct_domain_number'] = len(self.domain.distinct('original_domain'))

        # 去重后标签统计
        self.daily_report['distinct_tags_sinkhole_number'] = len(self.domain.distinct(
            'original_domain', {'tags': {'$in': ['sinkhole']}}))
        self.daily_report['distinct_tags_blocked_number'] = len(self.domain.distinct(
            'original_domain', {'tags': {'$in': ['blocked']}}))
        self.daily_report['distinct_tags_active_number'] = len(self.domain.distinct(
            'original_domain', {'tags': {'$in': ['active']}}))
        self.daily_report['distinct_tags_inactive_number'] = len(self.domain.distinct(
            'original_domain', {'tags': {'$in': ['inactive']}}))

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
        )) - self.daily_report['distinct_domain_number']

        # 窗口期增量计算
        _windowl_date = str(_now - datetime.timedelta(days=6)).split()[0]
        _windowr_date = str(_now + datetime.timedelta(days=1)).split()[0]

        self.daily_report['window_increment'] = len(self.domain.distinct(
            'original_domain',
            {'timestamp': {'$gt': _windowl_date, '$lt': _windowr_date}}
        ))
        self.daily_report['distinct_window_increment'] = len(self.domain.distinct(
            'original_domain',
            {'timestamp': {'$gt': _windowl_date, '$lt': _windowr_date}}
        ))

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
        _now = datetime.datetime.now()
        _today = str(_now).split()[0]
        _tomorrow = str(_now + datetime.timedelta(days=1)).split()[0]
        # 获取到去重后的今天解析过的域名列表
        domains = self.domain.distinct('original_domain', {'timestamp': {'$gt': _today, '$lt': _tomorrow}})
        # 统计今天的结果，将今天的domain绑定的ip存入数据库
        for _domain in domains:
            data = self.domain.find_one({'original_domain': _domain, 'timestamp': {'$gt': _today, '$lt': _tomorrow}})
            # 这里我们只关注active的主机
            if dict(data).has_key('iplist'):
                iplist = []
                d = data['iplist']
                for ip in d:
                    iplist.append(ip['ip'])
                self.ddns.update({'original_domain': _domain},
                                 {'$addToSet': {'ipstats': {'timestamp': _today, 'iplist': iplist}},
                                  '$set': {'original_domain': _domain}},
                                 upsert=True)
        # 检测domain绑定的ip变化的情况
        for _domain in domains:
            md5_list = []
            data = self.ddns.find_one({'original_domain': _domain})
            #print _domain
            if data is not None:
                # 下面循环中每次循环获取一天的iplist,得到每天ip的md5
                for i in data['ipstats']:
                    iplist = i['iplist']
                    iplist.sort()
                    md5 = hashlib.md5(','.join(iplist)).hexdigest()
                    md5_list.append(md5)
                # 将ip变化的情况存入数据库
                count = self.changing_count(md5_list)
                self.ddns.update({'original_domain': _domain},
                                 {'$set': {'changing_times': count[0], 'changing_range': count[1]}},
                                 upsert=True)

    def export2excel(self):
        keys = ['timestamp',
                'domain_number',
                'distinct_domain_number',
                'domain_daily_increment',
                'distinct_domain_daily_increment',
                'window_increment',
                'distinct_window_increment',
                'distinct_tags_active_number',
                'distinct_tags_inactive_number',
                'distinct_tags_sinkhole_number',
                'distinct_tags_blocked_number']
        _now = datetime.datetime.now()
        #_today = str(_now).split()[0]
        _tomorrow = str(_now + datetime.timedelta(days=1)).split()[0]
        _before = str(_now - datetime.timedelta(days=6)).split()[0]

        workbook = xlwt.Workbook(encoding='utf-8')
        worksheet = workbook.add_sheet('domain', cell_overwrite_ok=True)

        data = self.report.find({'timestamp': {'$gt': _before, '$lt': _tomorrow}})

        row = 0
        col = 0
        for d in data:
            print str(d)
            print '*'*10
            print d['distinct_tags_active_number']
            if row == 0:
                for key in keys:
                    worksheet.write(row, col, key)
                    col += 1
                col = 0
                row += 1
            for key in keys:
                worksheet.write(row, col, d[key])
                col += 1
            col = 0
            row += 1

        workbook.save('report.xls')

    def schedule(self):
        """
        定时任务，如果当前时刻在self.time_list中，则开始执行任务
        :return:
        """
        # _date = str(datetime.datetime.now()).split()[0]
        _time = str(datetime.datetime.now()).split()[1]

        if int(_time.split(':')[0]) in self.time_list:
            self.ddns_detect()
            self.log.info('DDNS detect.')
            self.generate_report()
            self.log.info('Report generation.')
            for key, value in self.daily_report.items():
                self.log.info('\t\t%s [%s]' % (key, value))
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
            print msg
