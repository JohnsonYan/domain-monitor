# encoding=utf-8
def merge_alex_cisco():
    """
    合并alex-top-1m.csv与cisco-top-1m.csv
    即求二者的对称差集
    结果写入文件alex-cisco-list中
    :return:
    """
    alex_domains = [line.split(',')[1].strip() for line in open('alex-top-1m.csv')]
    cisco_domains = [line.split(',')[1].strip() for line in open('cisco-top-1m.csv')]
    alex = set(alex_domains)
    cisco = set(cisco_domains)
    # 求alex cisco的对称差集
    alex_cisco = alex ^ cisco
    #print len(alex_cisco)
    with open('alex_cisco.list', 'w') as f:
        for domain in alex_cisco:
            f.write('%s\n' % domain)

    # 求cisco中不包含alex的域名
    cisco_without_alex = cisco - (alex & cisco)
    with open('cisco_without_alex.list', 'w') as f:
        for domain in cisco_without_alex:
            f.write('%s\n' % domain)


if __name__ == '__main__':
    merge_alex_cisco()