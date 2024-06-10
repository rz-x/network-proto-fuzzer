# File: fuzzer/command_line.py

import sys
import os
import argparse
from scrapy.crawler import CrawlerProcess

# Ensure the fuzzer module is in the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from spiders.tcp_fuzzer import TcpFuzzerSpider

def main():
    parser = argparse.ArgumentParser(description="IPv4/IPv6 TCP Fuzzer")
    parser.add_argument('-c', '--config', type=str, default='config.yaml', help="Path to the configuration file")
    args = parser.parse_args()

    process = CrawlerProcess({
        'USER_AGENT': 'Mozilla/5.0',
    })
    process.crawl(TcpFuzzerSpider, config_file=args.config)
    process.start()

if __name__ == '__main__':
    main()
