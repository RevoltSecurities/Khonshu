class Settings:
    def __init__(self, args):
        self.host = args.host
        self.list = args.list
        self.exclude_hosts = args.exclude_hosts
        self.resume = args.resume

        self.port = args.port
        self.top_ports = args.top_ports
        self.port_file = args.port_file
        self.exclude_ports = args.exclude_ports
        self.port_state = args.port_state
        self.tcp_ports = args.tcp_ports

        self.output = args.output
        self.json = args.json

        self.concurrency = args.concurrency
        self.rate_limit = args.rate_limit

        self.update = args.update
        self.show_updates = args.show_updates

        self.host_discovery = args.host_discovery
        self.skip_discovery = args.skip_discovery
        self.enable_discovery = args.enable_discovery

        self.tcp_syn_ping = args.tcp_syn_ping
        self.tcp_ack_ping = args.tcp_ack_ping
        self.icmp_echo_ping = args.icmp_echo_ping
        self.icmp_timestamp_ping = args.icmp_timestamp_ping
        self.icmp_address_mask_ping = args.icmp_address_mask_ping
        self.arp_ping = args.arp_ping

        self.scan_type = args.scan_type
        self.scan_all_ips = args.scan_all_ips
        self.passive = args.passive
        self.interface_list = args.interface_list
        self.interface = args.interface
        self.resolver = args.resolver

        self.timeout = args.timeout
        self.retry = args.retry

        self.health_check = args.health_check
        self.debug = args.debug
        self.verbose = args.verbose
        self.version = args.version
        self.silent = args.silent
        self.no_color = args.no_color
        self.stats = args.stats
        self.ping = args.ping