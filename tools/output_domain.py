# encoding=utf-8
import time
import datetime
import os
import pymongo


def output():
    """
    每天输出去重后的domains供域名监控扫描
    :return:
    """
    try:
        ips = []
        domain = pymongo.MongoClient('172.16.100.38', 27017)['vtfeed']['avclass']
        pipeline = [{'$unwind': '$domains'}, {'$group': {'_id': {'domains': '$domains','family':'$family'}}}]
        # 获取到去重后的，由honeypot得来的IP
        cursor = domain.aggregate(pipeline=pipeline, allowDiskUse=True)

        filename = 'data/domains-%s.txt' % time.strftime('%Y-%m-%d', time.localtime(time.time()))
        if not os.path.exists(filename):
            with open(filename, 'w') as f:
                for c in cursor:
                    ips.append(str(c.get('_id').get('domains')))
                    f.write('%s\t%s\n' % (str(c.get('_id').get('domains')), c.get('_id').get('family')))
            print 'count:%d' % len(ips)
            print 'count:%d'%len(set(ips))
            print '[info]Output %s' % filename

    except Exception as msg:
        print '[error]%s' % msg

def schedule(starttime):
    _time = datetime.datetime.now()
    if _time.hour == starttime:
        output()


if __name__ == '__main__':
    print '[Output Running...]'
    while True:
        try:
            # 每小时检查一次是否可以开始任务
            schedule(10)
            time.sleep(60*60)
        except Exception as msg:
            print msg.message, msg.args
            time.sleep(60*60)