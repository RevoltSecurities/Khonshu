import socket
import struct
import asyncio
import random
import platform
import os
import logging
import time
from typing import Optional, Set, Tuple
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor
from khonshu import Request, Response, Utils

logger = logging.getLogger(__name__)


class AsyncSynScanner:
    """
    High-performance asynchronous SYN scanner using raw sockets.

    This scanner implements true SYN scanning with proper TCP/IP packet crafting
    and response analysis. It is designed for concurrent operation at scale with
    minimal memory overhead and maximum performance.

    The scanner uses raw sockets to send TCP SYN packets and analyze responses
    according to RFC 793 (TCP) and RFC 791 (IP) specifications. Port states are
    interpreted following Nmap-style conventions:
    - 'open': SYN-ACK received
    - 'closed': RST or RST-ACK received
    - 'filtered': No response (timeout)

    Attributes:
        timeout (float): Response timeout in seconds
        retries (int): Number of retry attempts per scan
        interface (str): Network interface to use (optional)
        verbose (bool): Enable verbose debug logging
        max_workers (int): Thread pool size for blocking I/O operations

    Example:
        >>> scanner = AsyncSynScanner(timeout=3.0, retries=2, verbose=True)
        >>> request = Request(ip="192.168.1.1", port=80)
        >>> response = await scanner.scan(request)
        >>> print(response.status)
        'open'
    """

    def __init__(self, timeout: float = 3.0, retries: int = 2, interface=None,
                 verbose: bool = False, max_workers: int = 4):
        """
        Initialize the AsyncSynScanner with specified configuration.

        Args:
            timeout (float, optional): Response timeout in seconds. Defaults to 3.0.
            retries (int, optional): Number of retry attempts for each scan. Defaults to 2.
            interface (str, optional): Network interface to bind to. Defaults to None (auto-detect).
            verbose (bool, optional): Enable verbose debug logging. Defaults to False.
            max_workers (int, optional): Size of thread pool for blocking operations. Defaults to 4.

        Raises:
            PermissionError: If raw socket privileges are not available.

        Note:
            Raw socket privileges are required. On Unix systems, run with sudo.
            On Windows, run as Administrator.
        """
        self.timeout = timeout
        self.retries = retries
        self.interface = interface
        self.verbose = verbose
        self.max_workers = max_workers

        self._setup_logging()

        if self.verbose:
            self.logger.debug(
                f"Initializing AsyncSynScanner with timeout={timeout}, "
                f"retries={retries}, interface={interface}, max_workers={max_workers}"
            )

        self.os_type = platform.system().lower()
        if self.verbose:
            self.logger.debug(f"Detected OS: {self.os_type}")

        self._configure_os_specific()
        self._setup_network()

        self.source_port_base = random.randint(20000, 50000)
        self._port_lock = asyncio.Lock()
        self._port_counter = 0

        if self.verbose:
            self.logger.debug(f"Source port base: {self.source_port_base}")

        self.has_raw_socket_privilege = self._check_raw_socket_privilege()

        if not self.has_raw_socket_privilege:
            raise PermissionError(
                "Raw socket privileges required. Run with sudo/administrator privileges."
            )

        if self.verbose:
            self.logger.info(f"Raw socket privileges: {self.has_raw_socket_privilege}")

        self._executor = ThreadPoolExecutor(max_workers=self.max_workers)

        self._sender_sockets: asyncio.Queue = asyncio.Queue(maxsize=max_workers * 2)
        self._receiver_sockets: asyncio.Queue = asyncio.Queue(maxsize=max_workers * 2)
        self._socket_lock = asyncio.Lock()

        self._active_scans: Set[Tuple[str, int]] = set()
        self._scan_lock = asyncio.Lock()

        self._scan_count = 0
        self._success_count = 0
        self._failure_count = 0
        self._timeout_count = 0
        self._start_time = time.time()
        self._metrics_lock = asyncio.Lock()

        if self.verbose:
            self.logger.info("AsyncSynScanner initialization complete")

    def _setup_logging(self):
        """Configure logging handler and level based on verbose setting."""
        self.logger = logging.getLogger(f"{__name__}.{id(self)}")

        if self.verbose:
            if not self.logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.WARNING)

    def _configure_os_specific(self):
        """Configure operating system-specific socket options and parameters."""
        try:
            if self.os_type == "windows":
                self.ip_hdrincl = getattr(socket, 'IP_HDRINCL', 3)
                self.recv_buffer_size = 65535
                self.socket_timeout = 0.0
                if self.verbose:
                    self.logger.debug("Configured for Windows environment")

            elif self.os_type == "darwin":
                self.ip_hdrincl = socket.IP_HDRINCL
                self.recv_buffer_size = 65535
                self.socket_timeout = 0.0
                if self.verbose:
                    self.logger.debug("Configured for macOS environment")

            else:
                self.ip_hdrincl = socket.IP_HDRINCL
                self.recv_buffer_size = 65535
                self.socket_timeout = 0.0
                if self.verbose:
                    self.logger.debug(f"Configured for Linux/{self.os_type} environment")

        except Exception as e:
            self.logger.error(f"Error configuring OS-specific settings: {e}")
            self.ip_hdrincl = 3
            self.recv_buffer_size = 65535
            self.socket_timeout = 0.0

    def _check_raw_socket_privilege(self) -> bool:
        """
        Check if the process has raw socket privileges.

        Returns:
            bool: True if raw socket privileges are available, False otherwise.
        """
        try:
            if self.os_type == "windows":
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                test_sock.close()
                if self.verbose:
                    self.logger.debug("Windows raw socket privilege check passed")
                return True
            else:
                has_privilege = os.geteuid() == 0
                if self.verbose:
                    self.logger.debug(f"Unix privilege check: euid={os.geteuid()}, has_privilege={has_privilege}")
                return has_privilege
        except Exception as e:
            if self.verbose:
                self.logger.warning(f"Raw socket privilege check failed: {e}")
            return False

    def _setup_network(self):
        """Detect and configure source IP address for scanning."""
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_socket.connect(("8.8.8.8", 80))
            self.src_ip = temp_socket.getsockname()[0]
            temp_socket.close()
            if self.verbose:
                self.logger.info(f"Source IP detected: {self.src_ip}")
        except Exception as e:
            if self.verbose:
                self.logger.warning(f"Failed to detect source IP: {e}, using default")
            self.src_ip = "127.0.0.1"

    async def _get_source_port(self) -> int:
        """
        Generate a unique source port for scanning in a thread-safe manner.

        Returns:
            int: Source port number in the range [source_port_base, source_port_base + 30000).
        """
        async with self._port_lock:
            self._port_counter = (self._port_counter + 1) % 30000
            port = self.source_port_base + self._port_counter
            return port

    def _calculate_checksum(self, data: bytes) -> int:
        """
        Calculate RFC 1071 compliant Internet checksum.

        Args:
            data (bytes): Data to calculate checksum for.

        Returns:
            int: 16-bit checksum value.
        """
        if len(data) % 2:
            data += b'\0'

        checksum = sum(struct.unpack(f"!{len(data) // 2}H", data))
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += (checksum >> 16)
        return (~checksum) & 0xFFFF

    def _build_syn_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
        """
        Build a complete TCP SYN packet with IP and TCP headers.

        Implements proper packet structure according to RFC 793 (TCP) and RFC 791 (IP).
        The packet includes a 20-byte IP header and a 20-byte TCP header with the SYN flag set.

        Args:
            src_ip (str): Source IP address.
            dst_ip (str): Destination IP address.
            src_port (int): Source TCP port.
            dst_port (int): Destination TCP port.

        Returns:
            bytes: Complete IP+TCP packet ready for transmission.

        Raises:
            Exception: If packet construction fails.
        """
        try:
            version = 4
            ihl = 5
            tos = 0
            tot_len = 40
            ip_id = random.randint(1, 65535)
            frag_off = 0
            ttl = 64
            protocol = socket.IPPROTO_TCP
            check = 0

            saddr = socket.inet_aton(src_ip)
            daddr = socket.inet_aton(dst_ip)

            ihl_version = (version << 4) + ihl
            ip_header = struct.pack(
                '!BBHHHBBH4s4s',
                ihl_version, tos, tot_len, ip_id, frag_off,
                ttl, protocol, check, saddr, daddr
            )

            seq = random.randint(0, 4294967295)
            ack_seq = 0
            doff = 5

            fin = 0
            syn = 1
            rst = 0
            psh = 0
            ack = 0
            urg = 0

            flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
            window = socket.htons(65535)
            urg_ptr = 0

            tcp_header_partial = struct.pack(
                '!HHLLBBHHH',
                src_port, dst_port, seq, ack_seq,
                (doff << 4), flags, window, 0, urg_ptr
            )

            pseudo_header = struct.pack(
                '!4s4sBBH',
                saddr, daddr, 0, protocol, len(tcp_header_partial)
            )

            checksum = self._calculate_checksum(pseudo_header + tcp_header_partial)

            tcp_header = struct.pack(
                '!HHLLBBHHH',
                src_port, dst_port, seq, ack_seq,
                (doff << 4), flags, window, checksum, urg_ptr
            )

            packet = ip_header + tcp_header

            if self.verbose:
                self.logger.debug(
                    f"Built SYN packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                    f"(seq={seq}, size={len(packet)} bytes)"
                )

            return packet

        except Exception as e:
            if self.verbose:
                self.logger.error(f"Failed to build SYN packet: {e}", exc_info=True)
            raise

    def _create_sender_socket(self) -> socket.socket:
        """
        Create a raw socket for sending SYN packets.

        Returns:
            socket.socket: Configured raw socket for packet transmission.

        Raises:
            Exception: If socket creation or configuration fails.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, self.ip_hdrincl, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65535)
            sock.setblocking(True)

            if self.verbose:
                self.logger.debug("Created sender socket")

            return sock
        except Exception as e:
            if self.verbose:
                self.logger.error(f"Failed to create sender socket: {e}")
            raise

    def _create_receiver_socket(self) -> socket.socket:
        """
        Create a raw socket for receiving TCP responses.

        Returns:
            socket.socket: Configured non-blocking raw socket for packet reception.

        Raises:
            Exception: If socket creation or configuration fails.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setblocking(False)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.recv_buffer_size)

            if self.os_type != "windows":
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO,
                                struct.pack('LL', int(self.timeout), 0))

            try:
                if self.os_type == "windows":
                    sock.bind(('', 0))
                else:
                    sock.bind((self.src_ip, 0))
            except OSError as e:
                if self.verbose:
                    self.logger.warning(f"Bind failed, using any interface: {e}")
                sock.bind(('', 0))

            if self.verbose:
                self.logger.debug("Created receiver socket")

            return sock
        except Exception as e:
            if self.verbose:
                self.logger.error(f"Failed to create receiver socket: {e}")
            raise

    async def _get_sender_socket(self) -> socket.socket:
        """
        Get or create a sender socket from the socket pool.

        Returns:
            socket.socket: Sender socket ready for use.
        """
        try:
            sock = self._sender_sockets.get_nowait()
            return sock
        except asyncio.QueueEmpty:
            loop = asyncio.get_event_loop()
            sock = await loop.run_in_executor(self._executor, self._create_sender_socket)
            return sock

    async def _return_sender_socket(self, sock: socket.socket):
        """
        Return a sender socket to the pool or close it if pool is full.

        Args:
            sock (socket.socket): Socket to return to the pool.
        """
        try:
            self._sender_sockets.put_nowait(sock)
        except asyncio.QueueFull:
            try:
                sock.close()
            except:
                pass

    async def _get_receiver_socket(self) -> socket.socket:
        """
        Get or create a receiver socket from the socket pool.

        Returns:
            socket.socket: Receiver socket ready for use.
        """
        try:
            sock = self._receiver_sockets.get_nowait()
            return sock
        except asyncio.QueueEmpty:
            loop = asyncio.get_event_loop()
            sock = await loop.run_in_executor(self._executor, self._create_receiver_socket)
            return sock

    async def _return_receiver_socket(self, sock: socket.socket):
        """
        Return a receiver socket to the pool or close it if pool is full.

        Args:
            sock (socket.socket): Socket to return to the pool.
        """
        try:
            self._receiver_sockets.put_nowait(sock)
        except asyncio.QueueFull:
            try:
                sock.close()
            except:
                pass

    async def _send_syn_packet(self, sender_sock: socket.socket, packet: bytes,
                               target_ip: str, target_port: int) -> bool:
        """
        Send a SYN packet asynchronously using the thread pool executor.

        Args:
            sender_sock (socket.socket): Socket to send packet through.
            packet (bytes): Complete SYN packet to send.
            target_ip (str): Target IP address.
            target_port (int): Target port number.

        Returns:
            bool: True if packet was sent successfully, False otherwise.
        """
        try:
            loop = asyncio.get_event_loop()

            await loop.run_in_executor(
                self._executor,
                sender_sock.sendto,
                packet,
                (target_ip, 0)
            )

            if self.verbose:
                self.logger.debug(f"Sent SYN to {target_ip}:{target_port}")

            return True

        except Exception as e:
            if self.verbose:
                self.logger.error(f"Failed to send SYN packet to {target_ip}:{target_port}: {e}")
            return False

    def _parse_tcp_response(self, data: bytes, target_ip: str, src_port: int,
                            target_port: int) -> Optional[str]:
        """
        Parse TCP response packet and determine port state using Nmap-style interpretation.

        Args:
            data (bytes): Raw packet data received from socket.
            target_ip (str): Expected source IP of the response.
            src_port (int): Source port used in the original SYN packet.
            target_port (int): Target port being scanned.

        Returns:
            Optional[str]: Port state ('open', 'closed') or None if packet doesn't match.

        Note:
            - 'open': SYN-ACK received (flags 0x12)
            - 'closed': RST or RST-ACK received (flags 0x04 or 0x14)
        """
        try:
            if len(data) < 40:
                return None

            ip_header = data[:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            ip_header_length = ihl * 4

            src_addr = socket.inet_ntoa(iph[8])

            if src_addr != target_ip:
                return None

            if len(data) < ip_header_length + 20:
                return None

            tcp_header = data[ip_header_length:ip_header_length + 20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)

            resp_src_port = tcph[0]
            resp_dst_port = tcph[1]
            seq_num = tcph[2]
            ack_num = tcph[3]
            doff_reserved = tcph[4]
            flags = tcph[5]

            if resp_src_port != target_port or resp_dst_port != src_port:
                return None

            syn_ack = (flags & 0x12) == 0x12
            rst = (flags & 0x04) == 0x04
            rst_ack = (flags & 0x14) == 0x14

            if syn_ack:
                if self.verbose:
                    self.logger.debug(
                        f"Port {target_ip}:{target_port} OPEN "
                        f"(SYN-ACK received, seq={seq_num}, ack={ack_num})"
                    )
                return "open"

            elif rst or rst_ack:
                if self.verbose:
                    self.logger.debug(
                        f"Port {target_ip}:{target_port} CLOSED "
                        f"(RST received, flags=0x{flags:02x})"
                    )
                return "closed"

            else:
                if self.verbose:
                    self.logger.debug(
                        f"Port {target_ip}:{target_port} unexpected flags: 0x{flags:02x}"
                    )
                return None

        except struct.error as e:
            if self.verbose:
                self.logger.debug(f"Packet parsing error: {e}")
            return None
        except Exception as e:
            if self.verbose:
                self.logger.error(f"Error parsing TCP response: {e}")
            return None

    async def _receive_response(self, receiver_sock: socket.socket, target_ip: str,
                                src_port: int, target_port: int, timeout: float) -> Optional[str]:
        """
        Receive and analyze TCP responses asynchronously with timeout.

        Uses non-blocking socket operations integrated with asyncio to efficiently
        wait for and process incoming TCP responses.

        Args:
            receiver_sock (socket.socket): Socket to receive packets from.
            target_ip (str): Target IP address being scanned.
            src_port (int): Source port used in the scan.
            target_port (int): Target port being scanned.
            timeout (float): Maximum time to wait for response in seconds.

        Returns:
            Optional[str]: Port state ('open', 'closed') or None if timeout occurred.
        """
        loop = asyncio.get_event_loop()
        start_time = loop.time()
        end_time = start_time + timeout

        packets_checked = 0

        try:
            while loop.time() < end_time:
                remaining = end_time - loop.time()
                if remaining <= 0:
                    break

                try:
                    data = await asyncio.wait_for(
                        loop.sock_recv(receiver_sock, self.recv_buffer_size),
                        timeout=min(0.05, remaining)
                    )

                    packets_checked += 1

                    result = self._parse_tcp_response(data, target_ip, src_port, target_port)

                    if result:
                        if self.verbose:
                            self.logger.debug(
                                f"Response for {target_ip}:{target_port} after {packets_checked} packets"
                            )
                        return result

                except asyncio.TimeoutError:
                    continue

                except BlockingIOError:
                    await asyncio.sleep(0.001)
                    continue

                except Exception as e:
                    if self.verbose:
                        self.logger.debug(f"Receive error: {e}")
                    continue

            if self.verbose:
                self.logger.debug(
                    f"No response from {target_ip}:{target_port} "
                    f"(checked {packets_checked} packets, timeout={timeout}s)"
                )

            return None

        except Exception as e:
            if self.verbose:
                self.logger.error(f"Error in receive_response: {e}")
            return None

    async def _single_scan_attempt(self, request: Request) -> Tuple[Optional[str], Optional[float]]:
        """
        Perform a single SYN scan attempt on a target.

        Args:
            request (Request): Scan request containing target information.

        Returns:
            Tuple[Optional[str], Optional[float]]: Tuple of (status, rtt_ms) where status
                is the port state and rtt_ms is round-trip time in milliseconds.
        """
        sender_sock = None
        receiver_sock = None
        scan_start = time.time()

        try:
            src_port = await self._get_source_port()

            if self.verbose:
                self.logger.debug(
                    f"Scan attempt: {self.src_ip}:{src_port} -> {request.ip}:{request.port}"
                )

            sender_sock = await self._get_sender_socket()
            receiver_sock = await self._get_receiver_socket()

            packet = self._build_syn_packet(
                self.src_ip, request.ip, src_port, request.port
            )

            send_time = time.time()
            if not await self._send_syn_packet(sender_sock, packet, request.ip, request.port):
                return None, None

            result = await self._receive_response(
                receiver_sock, request.ip, src_port, request.port, self.timeout
            )

            rtt = None
            if result:
                rtt = (time.time() - send_time) * 1000

            return result, rtt

        except Exception as e:
            if self.verbose:
                self.logger.error(f"Scan attempt error for {request.ip}:{request.port}: {e}")
            return None, None

        finally:
            if sender_sock:
                await self._return_sender_socket(sender_sock)
            if receiver_sock:
                await self._return_receiver_socket(receiver_sock)

    async def scan(self, request: Request) -> Response:
        """
        Perform a SYN scan on a single target with automatic retry logic.

        This method implements multiple retry attempts for reliability and proper
        port state interpretation. The scan will attempt up to 'retries' times
        to get a definitive answer (open or closed) before returning 'filtered'.

        Args:
            request (Request): Scan request containing target IP, port, and metadata.

        Returns:
            Response: Scan response with status, timing, and metadata.

        Note:
            Port states returned:
            - 'open': Port is accepting connections (SYN-ACK received)
            - 'closed': Port is not accepting connections (RST received)
            - 'filtered': No response received (timeout or firewall)
            - 'error': Scan encountered an error
        """
        scan_id = (request.ip, request.port)
        scan_start_time = time.time()

        async with self._scan_lock:
            if scan_id in self._active_scans:
                if self.verbose:
                    self.logger.warning(f"Duplicate scan detected: {request.ip}:{request.port}")
            self._active_scans.add(scan_id)

        try:
            async with self._metrics_lock:
                self._scan_count += 1

            status = "filtered"
            best_rtt = None

            for attempt in range(self.retries):
                if self.verbose and attempt > 0:
                    self.logger.debug(
                        f"Retry attempt {attempt + 1}/{self.retries} "
                        f"for {request.ip}:{request.port}"
                    )

                result, rtt = await self._single_scan_attempt(request)

                if result:
                    status = result
                    best_rtt = rtt

                    if status in ("open", "closed"):
                        break

                if attempt < self.retries - 1 and status == "filtered":
                    await asyncio.sleep(0.1)

            async with self._metrics_lock:
                if status == "open":
                    self._success_count += 1
                elif status == "filtered":
                    self._timeout_count += 1
                else:
                    self._failure_count += 1

            scan_duration = time.time() - scan_start_time

            if self.verbose:
                self.logger.info(
                    f"Scan complete: {request.ip}:{request.port} -> {status.upper()} "
                    f"(duration={scan_duration:.3f}s, rtt={best_rtt:.2f}ms)"
                    if best_rtt else
                    f"Scan complete: {request.ip}:{request.port} -> {status.upper()} "
                    f"(duration={scan_duration:.3f}s)"
                )

            return Response(
                timestamp=Utils.timestamper(),
                ip=request.ip,
                port=request.port,
                status=status,
                domain=request.domain,
                interface=request.interface,
                type="syn",
            )

        except Exception as e:
            if self.verbose:
                self.logger.error(f"Scan failed for {request.ip}:{request.port}: {e}", exc_info=True)

            return Response(
                timestamp=Utils.timestamper(),
                ip=request.ip,
                port=request.port,
                status="error",
                domain=request.domain,
                interface=request.interface,
                type="syn",
            )

        finally:
            async with self._scan_lock:
                self._active_scans.discard(scan_id)

    async def scan_multiple(self, requests: list[Request],
                            concurrency: int = 100) -> list[Response]:
        """
        Scan multiple targets concurrently with controlled concurrency.

        This method efficiently scans multiple targets in parallel while respecting
        the specified concurrency limit to avoid overwhelming the network or system.

        Args:
            requests (list[Request]): List of scan requests to process.
            concurrency (int, optional): Maximum number of concurrent scans. Defaults to 100.

        Returns:
            list[Response]: List of scan responses in the same order as requests.

        Example:
            >>> requests = [Request(ip=f"192.168.1.{i}", port=80) for i in range(1, 255)]
            >>> responses = await scanner.scan_multiple(requests, concurrency=50)
            >>> open_ports = [r for r in responses if r.status == "open"]
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def bounded_scan(req: Request) -> Response:
            async with semaphore:
                return await self.scan(req)

        if self.verbose:
            self.logger.info(f"Starting batch scan: {len(requests)} targets, concurrency={concurrency}")

        start_time = time.time()
        results = await asyncio.gather(*[bounded_scan(req) for req in requests])
        duration = time.time() - start_time

        if self.verbose:
            self.logger.info(
                f"Batch scan complete: {len(requests)} targets in {duration:.2f}s "
                f"({len(requests) / duration:.1f} ports/sec)"
            )

        return results

    def get_scanner_info(self) -> dict:
        """
        Get comprehensive scanner information and performance statistics.

        Returns:
            dict: Dictionary containing scanner configuration, statistics, and system info.

        Example:
            >>> info = scanner.get_scanner_info()
            >>> print(f"Success rate: {info['statistics']['success_rate']}")
        """
        uptime = time.time() - self._start_time
        success_rate = (self._success_count / self._scan_count * 100) if self._scan_count > 0 else 0
        scan_rate = self._scan_count / uptime if uptime > 0 else 0

        info = {
            "scanner": {
                "type": "AsyncSynScanner",
                "version": "2.0",
                "method": "raw_socket_syn"
            },
            "configuration": {
                "os": self.os_type,
                "source_ip": self.src_ip,
                "timeout": self.timeout,
                "retries": self.retries,
                "max_workers": self.max_workers,
                "verbose": self.verbose
            },
            "privileges": {
                "has_raw_socket": self.has_raw_socket_privilege,
                "effective_uid": os.geteuid() if self.os_type != "windows" else "N/A"
            },
            "statistics": {
                "total_scans": self._scan_count,
                "successful_scans": self._success_count,
                "failed_scans": self._failure_count,
                "timeout_scans": self._timeout_count,
                "success_rate": f"{success_rate:.2f}%",
                "scan_rate": f"{scan_rate:.2f} scans/sec",
                "uptime_seconds": f"{uptime:.2f}",
                "active_scans": len(self._active_scans)
            },
            "socket_pools": {
                "sender_pool_size": self._sender_sockets.qsize(),
                "receiver_pool_size": self._receiver_sockets.qsize()
            }
        }
        return info

    @asynccontextmanager
    async def context(self):
        """
        Context manager for automatic resource management.

        Ensures proper initialization and cleanup of scanner resources.
        Recommended for use in production environments.

        Yields:
            AsyncSynScanner: The scanner instance.

        Example:
            >>> async with scanner.context():
            ...     response = await scanner.scan(request)
            ...     print(response.status)
        """
        try:
            if self.verbose:
                self.logger.info("Scanner context started")
            yield self
        finally:
            await self.cleanup()
            if self.verbose:
                self.logger.info("Scanner context closed")

    async def cleanup(self):
        """
        Cleanup all scanner resources and close open sockets.

        This method should be called when the scanner is no longer needed
        to ensure proper resource cleanup. It closes all pooled sockets
        and releases system resources.

        Note:
            Automatically called when using the context manager.
        """
        if self.verbose:
            self.logger.info("Starting cleanup...")

        while not self._sender_sockets.empty():
            try:
                sock = self._sender_sockets.get_nowait()
                sock.close()
            except:
                pass

        while not self._receiver_sockets.empty():
            try:
                sock = self._receiver_sockets.get_nowait()
                sock.close()
            except:
                pass

    def __str__(self) -> str:
        """
        Return a concise string representation of the scanner.

        Returns:
            str: String representation with key configuration parameters.
        """
        return (
            f"AsyncSynScanner(timeout={self.timeout}, retries={self.retries}, "
            f"os={self.os_type}, privileges={self.has_raw_socket_privilege})"
        )

    def __repr__(self) -> str:
        """
        Return a detailed string representation of the scanner.

        Returns:
            str: Detailed representation including all configuration parameters.
        """
        return (
            f"AsyncSynScanner(timeout={self.timeout}, retries={self.retries}, "
            f"interface={self.interface}, verbose={self.verbose}, "
            f"os={self.os_type}, privileges={self.has_raw_socket_privilege}, "
            f"source_ip={self.src_ip})"
        )