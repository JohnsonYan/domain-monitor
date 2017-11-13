# encoding=utf-8
import pymongo


def get_cisco_without_sinkhole():
    host = 'localhost'
    port = 27017
    client = pymongo.MongoClient(host, port)
    db = client['virustotal']
    cisco = db['cisco']

    data = cisco.find({'tags':{'$not':{'$in':['blocked','sinkhole']}}})

    with open('cisco_without_sinkhole.list', 'w') as f:
        for d in data:
            f.write('%s\n' % d['original_domain'])

            
if __name__ == '__main__':
    get_cisco_without_sinkhole()