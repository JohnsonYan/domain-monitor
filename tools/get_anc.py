# encoding=utf-8


def get_whitelist():
    alex_domains = [line.split(',')[1].strip() for line in open('alex-top-1m.csv')]
    cisco_domains = [line.split(',')[1].strip() for line in open('cisco-top-1m.csv')]
    majestic_domains = [line.strip() for line in open('majestic-top-1m.csv')]
    alex = set(alex_domains)
    cisco = set(cisco_domains)
    majestic = set(majestic_domains)
    # 求并集
    domain_whitelist = list(alex|cisco|majestic)
    with open('domain_whitelist.list', 'w') as f:
        for domain in domain_whitelist:
            f.write('%s\n' % domain)


if __name__ == '__main__':
    get_whitelist()