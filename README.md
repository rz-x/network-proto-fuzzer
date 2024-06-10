# IPv4/IPv6 TCP Fuzzer

This project is a TCP fuzzer designed to test servers by sending malformed packets and monitoring responses. The fuzzer supports both IPv4 and IPv6 and can be configured with various parameters to customize its behavior.

## Configuration

The fuzzer uses a YAML configuration file (`config.yaml`) to set its parameters. Below is an example of the configuration file and a description of each parameter.

### Example of the config.yaml for the Web server

```yaml 
target_ip: "2001:db8::1"        # Target IP address (IPv4 or IPv6)
target_port: 80                 # Target port
ip_version: 6                   # IP version (4 or 6)
fuzz_fields:                    # List of TCP fields to fuzz
  - sport
  - dport
  - seq
  - ack
  - dataofs
  - reserved
  - flags
  - window
  - chksum
  - urgptr
num_requests: 100000            # Number of requests to send
interval: 1.0                   # Interval between requests in seconds
timeout: 5.0                    # Timeout for each request in seconds
payload_file: "default_payloads.json"  # Path to the payload file
log_file: "fuzzer.log"          # Path to the log file
log_level: "INFO"               # Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
health_check_interval: 10       # Interval for periodic health checks in seconds
concurrency: 5                  # Number of concurrent connections
hardcore_mode: false            # Enable hardcore mode for intense fuzzing
```

### Example of the config.yaml for the MySQL server

```yaml 
target_ip: "192.168.1.2"
target_port: 3306
ip_version: 4
fuzz_fields:
  - sport
  - dport
  - seq
  - ack
  - dataofs
  - reserved
  - flags
  - window
  - chksum
  - urgptr
num_requests: 1500              # Moderate number of requests
interval: 1.0
timeout: 5.0
payload_file: "mysql_payloads.json"  # Custom payloads for MySQL fuzzing
log_file: "fuzzer_mysql.log"
log_level: "INFO"
health_check_interval: 10
concurrency: 5
hardcore_mode: false
```

### Example of the config.yaml for the FTP server

```yaml 
target_ip: "192.168.1.3"
target_port: 21
ip_version: 4
fuzz_fields:
  - sport
  - dport
  - seq
  - ack
  - dataofs
  - reserved
  - flags
  - window
  - chksum
  - urgptr
num_requests: 100000            # Standard number of requests
interval: 2.0                   # Longer interval to avoid overwhelming the server
timeout: 10.0                   # Longer timeout for FTP responses
payload_file: "ftp_payloads.json"  # Custom payloads for FTP fuzzing
log_file: "fuzzer_ftp.log"
log_level: "INFO"
health_check_interval: 15
concurrency: 5
hardcore_mode: false
```