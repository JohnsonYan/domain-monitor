# coding=utf-8
import pymongo

def aggs(src_host='52.36.192.225', src_port=27017, src_db='virustotal', src_clt='avclass'):
	src = pymongo.MongoClient(host=src_host, port=src_port)[src_db][src_clt]

	pipeline = [
		# 根据几个字段去判断键值对的唯一性，这里特别写明了{"$exists": True}，必须保证需要判断的字段完成，否则会影响到后面的group
		{"$match": {
				   "domains": {"$exists": True},
				"family": {'$exists':True},
			   }},
		# 将重复的键值对group起来，并用count计数
		{"$group": {
				   "_id": {
					   "domains": "$domains",
					   "family": "$family",
				   },
				   "count": {"$sum":1}
			   }},
		# 匹配count大于2的键值对，他们就是重复的
		{"$match": {
				   "count": {"$gt": 0}
			   }}
	]
	docs = src.aggregate(pipeline, allowDiskUse=True)
	L = []
	S = set()
	for doc in docs:
		match = doc['_id']
		for i in match['domains']:
			S.add(i)
			L.append(i)
	print len(S)
	print len(L)

aggs(src_host='52.36.192.225', src_port=27017, src_db='virustotal', src_clt='avclass')
