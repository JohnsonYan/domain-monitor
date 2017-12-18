# encoding=utf-8
import pymongo


def whois_gt3_doc_count():
    """
    计算domain_whois中，真正有whois信息的记录条数
    :return:
    """
    print 'counting...please wait'
    domain_whois = pymongo.MongoClient('localhost', 27017)['virustotal']['domain_whois']
    data = domain_whois.find({})
    count = 0
    for d in data:
        if len(d) > 3:
            count += 1
    print count


if __name__ == '__main__':
    whois_gt3_doc_count()