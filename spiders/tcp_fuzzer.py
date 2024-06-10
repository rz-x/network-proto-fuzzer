# File: fuzzer/spiders/tcp_fuzzer.py

import scrapy
from scapy.all import *
import random
import logging
import time
import json
import yaml
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor
import string
import binascii

class TcpFuzzerSpider(scrapy.Spider):
    name = "tcp_fuzzer"
    
    # custom_settings = {
    #     'LOG_LEVEL': 'INFO'
    # }
    
    def __init__(self, config_file="config.yaml", *args, **kwargs):
        super(TcpFuzzerSpider, self).__init__(*args, **kwargs)
        
        with open(config_file, 'r') as file:
            self.config = yaml.safe_load(file)
        
        self.target_ip = self.config['target_ip']
        self.target_port = int(self.config['target_port'])
        self.ip_version = int(self.config['ip_version'])
        self.fuzz_fields = self.config['fuzz_fields']
        self.num_requests = int(self.config['num_requests'])
        self.interval = float(self.config['interval'])
        self.timeout = float(self.config['timeout'])
        self.payload_file = self.config['payload_file']
        self.log_file = self.config['log_file']
        self.log_level = self.config['log_level']
        self.health_check_interval = int(self.config['health_check_interval'])
        self.concurrency = int(self.config['concurrency'])
        self.hardcore_mode = self.config['hardcore_mode']
        self.stats_interval = int(self.config.get('stats_interval', 10))  # Default to 10 seconds if not provided

        self._logger = logging.getLogger(self.name)
        handler = RotatingFileHandler(self.log_file, maxBytes=10*1024*1024, backupCount=5)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        self._logger.addHandler(handler)
        self._logger.setLevel(getattr(logging, self.log_level.upper()))

        with open(self.payload_file, 'r') as file:
            self.payloads = json.load(file)
        
        self.packet_history = []
        self.stats = {
            'packets_sent': 0,
            'responses_received': 0,
            'timeouts': 0,
            'errors': 0
        }
        self.last_stats_time = time.time()

    def start_requests(self):
        # Perform initial health check
        if not self.health_check():
            self._logger.error("Target is not reachable. Exiting.")
            return  # Ensure that we exit gracefully if health check fails

        start_time = time.time()
        for i in range(self.num_requests):
            if self.health_check_interval == 0 or time.time() - start_time > self.health_check_interval:
                start_time = time.time()
                if not self.health_check():
                    self._logger.error("Target became unreachable during fuzzing. Exiting.")
                    return  # Exit gracefully if health check fails during fuzzing

            yield scrapy.Request(
                url=f"http://{self.target_ip}:{self.target_port}",  # Dummy URL to satisfy Scrapy's requirement
                callback=self.send_packet_callback,
                dont_filter=True
            )
            time.sleep(self.interval)
            
            # Check if it's time to print statistics
            if time.time() - self.last_stats_time >= self.stats_interval:
                self.print_statistics()
                self.last_stats_time = time.time()

    def craft_packet(self):
        if self.ip_version == 6:
            packet = IPv6(dst=self.target_ip) / TCP(dport=self.target_port)
        else:
            packet = IP(dst=self.target_ip) / TCP(dport=self.target_port)
        
        for field in self.fuzz_fields:
            if self.hardcore_mode:
                packet[TCP].setfieldval(field, random.randint(0, 65535))
            else:
                packet[TCP].setfieldval(field, random.randint(0, 65535))

        if self.hardcore_mode:
            payload = ''.join(random.choices(string.printable, k=random.randint(50, 150)))
        else:
            payload = random.choice(self.payloads)['pattern']
        
        packet = packet / Raw(load=payload)
        
        return packet
    
    def send_packet_callback(self, response):
        packet = self.craft_packet()
        packet_hex = binascii.hexlify(bytes(packet)).decode()
        self.packet_history.append(packet_hex)
        if len(self.packet_history) > 30:
            self.packet_history.pop(0)
        
        try:
            response = sr1(packet, timeout=self.timeout, verbose=False)
            self.stats['packets_sent'] += 1
            self._logger.info(f"Sent packet: {packet.summary()}")
            self._logger.info(f"Packet content: {packet_hex}")
            if response:
                self.stats['responses_received'] += 1
                response_hex = binascii.hexlify(bytes(response)).decode()
                self._logger.info(f"Received response: {response.summary()}")
                self._logger.info(f"Response content: {response_hex}")
            else:
                self.stats['timeouts'] += 1
                self._logger.warning("No response received")
            
            # Perform health check if interval is set to 0
            if self.health_check_interval == 0 and not self.health_check():
                self._logger.error("Target became unreachable after sending packet. Possible crash.")
                self.report_crash(packet_hex)
                return

        except Exception as e:
            self.stats['errors'] += 1
            self._logger.error(f"Error sending packet: {e}")
            self.report_crash(packet_hex)
    
    def health_check(self):
        self._logger.info(f"Performing health check on {self.target_ip}:{self.target_port}")
        if self.ip_version == 6:
            syn_packet = IPv6(dst=self.target_ip) / TCP(dport=self.target_port, flags='S')
        else:
            syn_packet = IP(dst=self.target_ip) / TCP(dport=self.target_port, flags='S')
        
        response = sr1(syn_packet, timeout=self.timeout, verbose=False)
        
        if response and response.haslayer(TCP) and response[TCP].flags == 'SA':
            self._logger.info("Target is reachable")
            return True
        else:
            self._logger.error("Target is not reachable")
            return False

    def report_crash(self, packet_hex):
        self._logger.critical("====================================")
        self._logger.critical("CRASH DETECTED!")
        self._logger.critical("====================================")
        if self.health_check_interval == 0:
            self._logger.critical(f"Exact packet causing crash: {packet_hex}")
        else:
            self._logger.critical("Recent 30 packets sent before crash:")
            for i, pkt in enumerate(self.packet_history):
                if pkt == packet_hex:
                    self._logger.critical(f"Packet {i+1} (Possible crash cause): {pkt}")
                else:
                    self._logger.critical(f"Packet {i+1}: {pkt}")
        self._logger.critical("====================================")
        self.print_statistics()

    def handle_timeout(self):
        self._logger.error(f"Timeout occurred after {self.timeout} seconds")
        self.stats['timeouts'] += 1

    def handle_crash(self, error):
        self._logger.error(f"Crash detected: {error}")
        self.stats['errors'] += 1

    def print_statistics(self):
        self._logger.info("====================================")
        self._logger.info("Fuzzing Statistics")
        self._logger.info("====================================")
        self._logger.info(f"Packets sent: {self.stats['packets_sent']}")
        self._logger.info(f"Responses received: {self.stats['responses_received']}")
        self._logger.info(f"Timeouts: {self.stats['timeouts']}")
        self._logger.info(f"Errors: {self.stats['errors']}")
        self._logger.info("====================================")
    
    def closed(self, reason):
        self.print_statistics()
