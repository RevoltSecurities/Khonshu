from khonshu import (
    Settings,
    Utils,
    Save,
    Request,
    Response,
    PINGAlive,
    ARPPing,
    InterfaceManager,
    PassiveScanner,
    NETStreamer,
    AioARP,
    AioICMP,
    AioTCP,
    AsyncConnectScanner,
    AsyncSynScanner,
)
from revoltlogger import Logger, LogLevel
from revoltutils import (
    ProgressBar,
    AsyncQueue,
    AsyncTempdir,
    AsyncTempfile,
    FileUtils,
    FolderUtils,
    AsyncDiskCache,
    IPUtils,
    DnsUtils,
    GenericUtils,
    RandomUtils,
    ResourceUtils
)
from khonshu.diskmanager.diskmanager import DiskManager
from khonshu.progresslogger.progresslogger import ProgressLogger
import asyncio
from aiolimiter import AsyncLimiter
import sys
import os
import signal
from typing import List
import json
import threading
import time

if sys.platform in ('win32', 'cygwin', 'cli'):
    import winloop

    asyncio.set_event_loop_policy(winloop.EventLoopPolicy())
else:
    import uvloop

    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


class Pyrunner:
    def __init__(self, args: Settings) -> None:
        self.args = args
        self.totalprocess = 0
        self.hostcount = 0
        self.logger = Logger(colored=False if self.args.no_color else True, level=LogLevel.DEBUG)
        self.utils = Utils()
        self.interfacers = InterfaceManager()
        self.probe_bar: ProgressBar = None
        self.db_bar: ProgressBar = None
        self.resume_bar: ProgressBar = None

        self.probe_logger: ProgressLogger = None
        self.db_logger: ProgressLogger = None
        self.resume_logger: ProgressLogger = None

        self.diskcache: AsyncDiskCache = None
        self.resume_manager: DiskManager = None
        self.tmpdir: AsyncTempdir = AsyncTempdir()
        self.tmpfile: AsyncTempfile = AsyncTempfile()
        self._dbevent = asyncio.Event()
        self._event = asyncio.Event()
        self._oevent = asyncio.Event()
        self._host_verification_event = asyncio.Event()
        self._task_generation_event = asyncio.Event()

        self.rate_limiter = AsyncLimiter(self.args.rate_limit, 1)

        self._lock = asyncio.Lock()
        self.dbsemaphore = asyncio.Semaphore(500)
        self.semaphore = asyncio.Semaphore(self.args.concurrency)
        self.task_started = False

        # Multi-stage queues for the new architecture of pyrunner
        self._raw_host_channel = AsyncQueue(maxsize=self.args.concurrency * 3)  # [A] -> [B]
        self._host_verification_channel = AsyncQueue(maxsize=self.args.concurrency * 2)  # [B] -> [C]
        self._task_channel = AsyncQueue(maxsize=self.args.concurrency * 4)  # [C] -> [D]
        self._output_channel = AsyncQueue(maxsize=self.args.concurrency * 2)  # [D] -> output

        # Legacy channels for compatibility
        self._pychannel = self._task_channel
        self._outchannel = self._output_channel
        self._dbchannel = AsyncQueue(maxsize=10000)

        self.fileutils = FileUtils()
        self.folderutils = FolderUtils()
        self.generics = GenericUtils()
        self.iputils = IPUtils()
        self.cidrstreamer = NETStreamer(max_size=1000)
        self.tmpdirpath = None
        self.tmpfilepath = None
        self.inputer = None
        self.dns: DnsUtils = None
        self.pas: PassiveScanner = None
        self.syn: AsyncSynScanner = None
        self.con: AsyncConnectScanner = None
        self.arp: AioARP = None
        self.icmp: AioICMP = None
        self.tcp: AioTCP = None
        self.save: Save = None
        self.resolvers = ["8.8.8.8", "1.1.1.1"]
        self.ports = None
        self.port_state = None
        self.thread_event = threading.Event()

        # Progress tracking - only counters, no growing data structures
        self.completed_tasks = 0
        self.alive_host_count = 0
        self.dead_host_count = 0
        self.cached_results = 0
        self.scanned_results = 0
        self.verified_hosts = 0
        self.generated_tasks = 0

    async def setup(self) -> None:
        self.tmpdirpath = await self.tmpdir.create()
        self.diskcache = AsyncDiskCache(directory=self.tmpdirpath)

        self.resume_manager = DiskManager(self.tmpdirpath)
        await self.resume_manager.start()

        if self.args.resolver:
            if await self.fileutils.file_exist(self.args.resolver):
                self.resolvers = await self.fileutils.readlines(self.args.resolver)
            else:
                self.resolvers = self.generics.string_to_string_list(self.args.resolver)

        ResourceUtils.extend_nofile_limit(new_limit=524288)
        await DnsUtils.init(nameservers=self.resolvers)

        if self.args.passive:
            self.pas = PassiveScanner()

        self.icmp = AioICMP(self.args.timeout, retries=self.args.retry, method="echo")

        if self.args.host_discovery and (self.args.tcp_ack_ping or self.args.tcp_syn_ping):
            method = "syn" if self.args.tcp_syn_ping else "ack"
            self.tcp = AioTCP(
                timeout=self.args.timeout,
                retries=self.args.retry,
                method=method,
                ports=self.generics.string_to_int_list(self.args.tcp_ports)
            )

        if self.args.host_discovery and (
                self.args.icmp_echo_ping or self.args.icmp_timestamp_ping or self.args.icmp_address_mask_ping
        ):
            if self.args.icmp_echo_ping:
                method = "echo"
            elif self.args.icmp_timestamp_ping:
                method = "timestamp"
            else:
                method = "mask"
            self.icmp = AioICMP(timeout=self.args.timeout, retries=self.args.retry, method=method)

        if self.args.host_discovery and self.args.arp_ping:
            self.arp = AioARP(
                timeout=self.args.timeout,
                retries=self.args.retry,
                interface=self.args.interface
            )

        if self.args.scan_type == "connect":
            total_ports = len(self.ports) if self.ports else 1000

            # OS-specific connection limits
            if sys.platform in ('win32', 'cygwin', 'cli'):
                base_max_connections = min(self.args.concurrency * 10, 1500)
                base_max_per_host = min(total_ports, 300)
            else:
                base_max_connections = min(self.args.concurrency * 15, 3000)
                base_max_per_host = min(total_ports, 800)

            self.con = AsyncConnectScanner(
                timeout=self.args.timeout,
                retries=self.args.retry,
                max_connections=base_max_connections,
                max_per_host=base_max_per_host,
                enable_circuit_breaker=False
            )
        elif self.args.scan_type == "syn":
            self.syn = AsyncSynScanner(timeout=self.args.timeout, retries=self.args.retry)
        self.save = Save(self.args.output, jsonize=self.args.json)

    async def cleanup(self) -> None:
        try:
            if self.resume_manager:
                await self.resume_manager.stop()
            if self.tmpdirpath and await self.folderutils.folder_exists(self.tmpdirpath):
                await self.tmpdir.close()
            if self.tmpfilepath and await self.fileutils.file_exist(self.tmpfilepath):
                await self.tmpfile.close()
        except RuntimeError:
            pass
        except Exception:
            pass

    async def _add_to_cache(self, host: str) -> None:
        async with self.dbsemaphore:
            if not self.args.resume:
                if self.iputils.is_ip(host):
                    request = {"ip": host}
                    if await self.diskcache.add(json.dumps(request), request):
                        self.hostcount += 1
                        if self.db_bar:
                            self.db_bar.update()
                        if self.db_logger:
                            await self.db_logger.update()
                elif self.iputils.is_cidr(host):
                    async for ip in self.cidrstreamer.stream(host):
                        request = {"ip": ip}
                        if await self.diskcache.add(json.dumps(request), request):
                            self.hostcount += 1
                            if self.db_bar:
                                self.db_bar.update()
                            if self.db_logger:
                                await self.db_logger.update()
                else:
                    ips = await DnsUtils.resolve(host, "A")
                    if len(ips) == 0:
                        if self.args.debug:
                            self.logger.warn(f"no ip address found for host {host}")
                        return

                    if self.args.scan_all_ips:
                        for ip in ips:
                            if self.args.debug:
                                self.logger.debug(f"using {ip} address for host {host}")
                            request = {"ip": ip, "domain": host}
                            if await self.diskcache.add(json.dumps(request), request):
                                self.hostcount += 1
                                if self.db_bar:
                                    self.db_bar.update()
                                if self.db_logger:
                                    await self.db_logger.update()
                    else:
                        ip = RandomUtils.random_choice(ips)
                        if self.args.debug:
                            self.logger.debug(f"using {ip} address for host {host}")
                        request = {"ip": ip, "domain": host}
                        if await self.diskcache.add(json.dumps(request), request):
                            self.hostcount += 1
                            if self.db_bar:
                                self.db_bar.update()
                            if self.db_logger:
                                await self.db_logger.update()
            else:
                if await self.diskcache.add(host, True):
                    self.hostcount += 1
                    if self.db_bar:
                        self.db_bar.update()
                    if self.db_logger:
                        await self.db_logger.update()

    async def dbproducer(self) -> None:
        async def producer():
            async for host in self.fileutils.stream(self.inputer):
                if not host:
                    continue
                await self._dbchannel.put(host)
            self._dbevent.set()

        async def processor(host: str):
            try:
                await self._add_to_cache(host)
            finally:
                self._dbchannel.task_done()

        async def consumer():
            while True:
                host = await self._dbchannel.get()
                asyncio.create_task(processor(host))

        # Initialize progress tracking based on stats argument
        if self.args.stats:
            self.db_logger = ProgressLogger(self.logger, None, "Loading")
        else:
            self.db_bar = ProgressBar(total=None, title="Loading...")
            self.db_bar.start()

        self._dbevent.clear()
        dbtasks = []
        dbtasks.append(asyncio.create_task(producer()))

        for _ in range(500):
            dbtasks.append(asyncio.create_task(consumer()))

        await self._dbevent.wait()
        await self._dbchannel.join()

        for task in dbtasks:
            task.cancel()

        if self.db_bar:
            self.db_bar.close()

        if self.args.debug:
            self.logger.debug(f"Total number of host loaded for the enumeration: {self.hostcount}")

    async def setupIO(self) -> None:
        if self.args.host:
            hosts = self.utils.host_filter(
                hosts=self.generics.string_to_string_list(self.args.host),
                exclude=self.generics.string_to_string_list(self.args.exclude_hosts)
            )
            self.tmpfilepath = await self.tmpfile.create()
            self.inputer = self.tmpfilepath
            for host in hosts:
                await self.tmpfile.write(host + "\n")
            return

        if self.args.list:
            if not await self.fileutils.file_exist(self.args.list):
                self.logger.warn(f"{self.args.list} no such file or directory exist")
                await self.cleanup()
                exit(1)
            else:
                self.inputer = self.args.list
            return

        if self.args.resume:
            if not await self.fileutils.file_exist(self.args.resume):
                self.logger.warn(f"{self.args.resume} no such file or directory exist")
                await self.cleanup()
                exit(1)
            else:
                self.inputer = self.args.resume
            return

        if not self.fileutils.is_stdin():
            self.logger.warn("no inputs provided for khonshu")
            await self.cleanup()
            exit(1)
        else:
            self.tmpfilepath = await self.tmpfile.create()
            self.inputer = self.tmpfilepath
            await self.fileutils.stdin_2_file(self.tmpfilepath)
            return

    async def setupPorts(self) -> None:
        self.port_state = self.generics.string_to_string_list(self.args.port_state)

        if self.args.host_discovery:
            self.ports = [80]
            return

        if self.args.passive:
            self.ports = [80]
            return

        if self.args.port:
            self.ports = self.utils.port_filter(
                ports=self.generics.string_to_int_list(self.args.port),
                exclude=self.generics.string_to_int_list(self.args.exclude_ports)
            )
            return

        if self.args.port_file:
            if not await self.fileutils.file_exist(self.args.port_file):
                self.logger.warn(f"{self.args.port_file} no such file or directory exist")
                exit(1)

            strport = await self.fileutils.readlines(self.args.port_file)
            self.ports = self.utils.port_filter(
                ports=self.utils.str_list_to_int_list(strport),
                exclude=self.generics.string_to_int_list(self.args.exclude_ports)
            )
            return

        if self.args.top_ports:
            self.ports = self.utils.port_filter(
                ports=self.utils.top_port(self.args.top_ports),
                exclude=self.generics.string_to_int_list(self.args.exclude_ports)
            )
            return

        if self.ports is None:
            self.ports = self.utils.port_filter(
                ports=self.utils.top_port("100"),
                exclude=self.generics.string_to_int_list(self.args.exclude_ports)
            )
        return

    # [A] Raw Host Producer - Streams hosts from cache
    async def raw_host_producer(self) -> None:
        try:
            if self.args.debug:
                self.logger.debug("Raw host producer started")

            async for host_task in self.diskcache.iterkeys():
                if self.thread_event.is_set():
                    break

                try:
                    data = json.loads(host_task)
                    host_data = {
                        "ip": data.get("ip"),
                        "domain": data.get("domain", None),
                        "cache_key": host_task
                    }

                    # Non-blocking put with backpressure handling for producing tasks to our consumers
                    while not self.thread_event.is_set():
                        try:
                            await asyncio.wait_for(self._raw_host_channel.put(host_data), timeout=0.1)
                            break
                        except asyncio.TimeoutError:
                            await asyncio.sleep(0.001)
                            continue

                except Exception as e:
                    if self.args.debug:
                        self.logger.error(f"Error in raw host producer for {host_task}: {e}")

        except Exception as e:
            if self.args.debug:
                self.logger.error(f"Raw host producer error: {e}")
        finally:
            self._event.set()
            if self.args.debug:
                self.logger.debug("Raw host producer finished")

    # [B] Host Verification Consumer - Verifies hosts are alive
    async def host_verification_consumer(self) -> None:
        """Host Consumer [B]: Verifies hosts are alive and forwards to task generator"""
        consumer_id = id(asyncio.current_task())

        if self.args.debug:
            self.logger.debug(f"Host verification consumer {consumer_id} started")

        while not self.thread_event.is_set():
            try:
                host_data = await asyncio.wait_for(
                    self._raw_host_channel.get(),
                    timeout=5.0
                )
            except asyncio.TimeoutError:
                if (self._event.is_set() and
                        self._raw_host_channel.qsize() == 0):
                    if self.args.debug:
                        self.logger.debug(f"Host verification consumer {consumer_id} finishing")
                    break
                continue
            except Exception as e:
                if self.args.debug:
                    self.logger.error(f"Host verification consumer {consumer_id} error: {e}")
                continue

            try:
                ip = host_data["ip"]
                domain = host_data.get("domain")
                cache_key = host_data["cache_key"]

                # Host-level ping verification with caching
                if (self.args.ping and
                        not self.args.skip_discovery and
                        not self.args.host_discovery):

                    if await self.resume_manager.is_host_alive(ip):
                        is_alive = True
                        if self.args.debug:
                            self.logger.debug(f"Host {ip} cached as alive")
                    elif await self.resume_manager.is_host_dead(ip):
                        is_alive = False
                        if self.args.debug:
                            self.logger.debug(f"Host {ip} cached as dead")
                    else:
                        # Perform actual ping verification
                        async with self.rate_limiter:
                            try:
                                response = await self.icmp.ping(host=ip)
                                if response and response.status == "alive":
                                    await self.resume_manager.mark_host_alive(ip)
                                    self.alive_host_count += 1
                                    is_alive = True
                                    if self.args.debug:
                                        self.logger.debug(f"Host {ip} verified as alive")
                                else:
                                    await self.resume_manager.mark_host_dead(ip)
                                    self.dead_host_count += 1
                                    is_alive = False
                                    if self.args.debug:
                                        self.logger.debug(f"Host {ip} is not responding to ping")
                            except Exception as e:
                                if self.args.debug:
                                    self.logger.debug(f"Ping verification failed for {ip}: {e}")
                                await self.resume_manager.mark_host_dead(ip)
                                self.dead_host_count += 1
                                is_alive = False

                    if not is_alive:
                        try:
                            if await self.diskcache.contains(cache_key):
                                await self.diskcache.delete(cache_key)
                        except Exception as e:
                            if self.args.debug:
                                self.logger.debug(f"Failed to cleanup dead host {ip}: {e}")
                        continue
                else:
                    is_alive = True

                if is_alive:
                    self.verified_hosts += 1
                    verified_host = {
                        "ip": ip,
                        "domain": domain,
                        "cache_key": cache_key
                    }

                    while not self.thread_event.is_set():
                        try:
                            await asyncio.wait_for(
                                self._host_verification_channel.put(verified_host),
                                timeout=0.1
                            )
                            break
                        except asyncio.TimeoutError:
                            await asyncio.sleep(0.001)
                            continue

            except Exception as e:
                if self.args.debug:
                    self.logger.error(f"Host verification consumer {consumer_id} error processing {host_data}: {e}")
            finally:
                self._raw_host_channel.task_done()

        if self.args.debug:
            self.logger.debug(f"Host verification consumer {consumer_id} finished")

    # [C] Task Generator Consumer - Generates port scanning tasks
    async def task_generator_consumer(self) -> None:
        """Task Generator [C]: Takes verified hosts and generates port scanning tasks"""
        consumer_id = id(asyncio.current_task())

        if self.args.debug:
            self.logger.debug(f"Task generator consumer {consumer_id} started")

        while not self.thread_event.is_set():
            try:
                # Non-blocking get with timeout
                verified_host = await asyncio.wait_for(
                    self._host_verification_channel.get(),
                    timeout=5.0
                )
            except asyncio.TimeoutError:
                if (self._event.is_set() and
                        self._raw_host_channel.qsize() == 0 and
                        self._host_verification_channel.qsize() == 0):
                    if self.args.debug:
                        self.logger.debug(f"Task generator consumer {consumer_id} finishing")
                    break
                continue
            except Exception as e:
                if self.args.debug:
                    self.logger.error(f"Task generator consumer {consumer_id} error: {e}")
                continue

            try:
                ip = verified_host["ip"]
                domain = verified_host.get("domain")
                cache_key = verified_host["cache_key"]

                # Generate tasks for all ports
                for port in self.ports:
                    if self.thread_event.is_set():
                        break

                    request = Request(
                        ip=ip,
                        port=port,
                        domain=domain,
                        type=self.args.scan_type,
                        interface=self.args.interface
                    )

                    # Add metadata for cleanup
                    request.cache_key = cache_key
                    request.is_last_port = (port == self.ports[-1])

                    self.generated_tasks += 1

                    # Non-blocking put with backpressure handling
                    while not self.thread_event.is_set():
                        try:
                            await asyncio.wait_for(self._task_channel.put(request), timeout=0.1)
                            break
                        except asyncio.TimeoutError:
                            await asyncio.sleep(0.001)
                            continue

            except Exception as e:
                if self.args.debug:
                    self.logger.error(f"Task generator consumer {consumer_id} error processing {verified_host}: {e}")
            finally:
                self._host_verification_channel.task_done()
        self._task_generation_event.set()

        if self.args.debug:
            self.logger.debug(f"Task generator consumer {consumer_id} finished")

    # [D] Task Consumer - Original consumer
    async def consumer(self) -> None:
        """Enhanced consumer with better resource management and cleanup"""
        consumer_id = id(asyncio.current_task())

        if self.args.debug:
            self.logger.debug(f"Task consumer {consumer_id} started")

        while not self.thread_event.is_set():
            try:
                request: Request = await asyncio.wait_for(
                    self._task_channel.get(),
                    timeout=5.0
                )
            except asyncio.TimeoutError:
                if (self._task_generation_event.is_set() and
                        self._task_channel.qsize() == 0):
                    if self.args.debug:
                        self.logger.debug(f"Task consumer {consumer_id} finishing - no more tasks")
                    break
                continue
            except Exception as e:
                if self.args.debug:
                    self.logger.error(f"Task consumer {consumer_id} error getting task: {e}")
                continue

            try:
                # Check for cached results first to reduce network operations
                if await self.resume_manager.is_port_open(request.ip, request.port):
                    if self.args.debug:
                        self.logger.debug(
                            f"Port {request.ip}:{request.port} already known to be open, using cached result")

                    self.cached_results += 1
                    cached_result = await self.resume_manager.get_open_port_info(request.ip, request.port)

                    if cached_result:
                        # Creating response for cached results
                        if self.args.json:
                            output_data = {
                                "ip": request.ip,
                                "port": request.port,
                                "type": self.args.scan_type,
                                "status": cached_result.get("status", "open"),
                                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                "domain": request.domain
                            }
                            output = json.dumps(output_data)
                        else:
                            if request.domain:
                                output = (
                                    f"found {cached_result.get('status', 'open')} on port {request.port} for host {request.domain} ({request.ip})"
                                    if self.args.verbose else f"{request.domain}:{request.port}"
                                )
                            else:
                                output = (
                                    f"found {cached_result.get('status', 'open')} on port {request.port} for host {request.ip}"
                                    if self.args.verbose else f"{request.ip}:{request.port}"
                                )

                        # Non-blocking output put
                        while not self.thread_event.is_set():
                            try:
                                await asyncio.wait_for(self._output_channel.put(output), timeout=0.1)
                                break
                            except asyncio.TimeoutError:
                                await asyncio.sleep(0.001)
                                continue
                else:
                    # Performing actual scan call here
                    await self.task(request)

                self.completed_tasks += 1

                # Cleanup completed host entries efficiently
                if (hasattr(request, 'is_last_port') and request.is_last_port and
                        hasattr(request, 'cache_key') and not self.thread_event.is_set()):
                    try:
                        if await self.diskcache.contains(request.cache_key):
                            await self.diskcache.delete(request.cache_key)
                            if self.args.debug:
                                self.logger.debug(f"Cleaned up completed host entry: {request.ip}")
                    except Exception as e:
                        if self.args.debug:
                            self.logger.debug(f"Failed to cleanup host {request.ip}: {e}")

            except Exception as e:
                if self.args.debug:
                    self.logger.error(f"Error processing task {request.ip}:{request.port}: {e}")
            finally:
                if not self.thread_event.is_set():
                    if self.probe_bar:
                        self.probe_bar.update()
                    if self.probe_logger:
                        await self.probe_logger.update()
                self._task_channel.task_done()

        if self.args.debug:
            self.logger.debug(f"Task consumer {consumer_id} finished")

    async def task(self, request: Request) -> None:
        try:
            async with self.rate_limiter:
                if self.args.host_discovery:
                    response: PINGAlive = None
                    if self.args.icmp_echo_ping or self.args.icmp_timestamp_ping or self.args.icmp_address_mask_ping:
                        response = await self.icmp.ping(host=request.ip)
                    elif self.args.tcp_ack_ping or self.args.tcp_syn_ping:
                        response = await self.tcp.ping(host=request.ip)

                    if response and response.status == "alive":
                        if self.args.json:
                            response.domain = request.domain
                            output = self.utils.jsonize(response)
                        elif request.domain:
                            output = f"found alive host for {request.domain} ({response.host})"
                        else:
                            output = f"found alive host {response.host}"
                        await self._output_channel.put(output)
                    return

                elif self.args.passive:
                    responses: List[Response] = await self.pas.scan(request=request)
                    if not responses:
                        return
                    for res in responses:
                        if res and res.status in self.port_state:

                            if res.status == "open":
                                await self.resume_manager.mark_port_open(res.ip, res.port, res.status, res.domain)

                            self.scanned_results += 1

                            if self.args.json:
                                output = self.utils.jsonize(res)
                            else:
                                if res.domain:
                                    output = (
                                        f"found {res.status} on port {res.port} for host {res.domain} ({res.ip})"
                                        if self.args.verbose else f"{res.domain}:{res.port}"
                                    )
                                else:
                                    output = (
                                        f"found {res.status} on port {res.port} for host {res.ip}"
                                        if self.args.verbose else f"{res.ip}:{res.port}"
                                    )
                            await self._output_channel.put(output)
                    return

                else:
                    res: Response = None
                    if self.args.scan_type == "connect" and self.con:
                        res = await self.con.scan(request)
                    elif self.args.scan_type == "syn" and self.syn:
                        res = await self.syn.scan(request)

                    if res and res.status in self.port_state:

                        # Cache open ports only for future runs to reduce network connections
                        if res.status == "open":
                            await self.resume_manager.mark_port_open(res.ip, res.port, res.status, res.domain)

                        self.scanned_results += 1

                        if self.args.json:
                            output = self.utils.jsonize(res)
                        else:
                            if res.domain:
                                output = (
                                    f"found {res.status} on port {res.port} for host {res.domain} ({res.ip})"
                                    if self.args.verbose else f"{res.domain}:{res.port}"
                                )
                            else:
                                output = (
                                    f"found {res.status} on port {res.port} for host {res.ip}"
                                    if self.args.verbose else f"{res.ip}:{res.port}"
                                )
                        await self._output_channel.put(output)
                    return
        except Exception as e:
            if self.args.debug:
                self.logger.warn(f"Error occurred in the task method for {request.ip}:{request.port} due to: {e}")


    async def outputconsumer(self) -> None:
        consumer_id = id(asyncio.current_task())

        if self.args.debug:
            self.logger.debug(f"Output consumer {consumer_id} started")

        while not self.thread_event.is_set():
            try:
                output = await asyncio.wait_for(
                    self._output_channel.get(),
                    timeout=10.0
                )
            except asyncio.TimeoutError:
                # Check if all processing is complete
                if (self._task_generation_event.is_set() and
                        self._task_channel.qsize() == 0 and
                        self._output_channel.qsize() == 0):
                    if self.args.debug:
                        self.logger.debug(f"Output consumer {consumer_id} finishing - no more output")
                    break
                continue
            except Exception as e:
                if self.args.debug:
                    self.logger.error(f"Output consumer {consumer_id} error getting output: {e}")
                continue

            try:
                if output:
                    # Output formatting and logging
                    if self.args.json:
                        self.logger.stdinlog(output)
                    else:
                        if self.args.verbose:
                            self.logger.output(output)
                        else:
                            self.logger.stdinlog(output)

                    # Parse JSON if needed
                    if self.args.json and isinstance(output, str):
                        try:
                            output = json.loads(output)
                        except json.JSONDecodeError:
                            pass

                    await self.save.save(output)
            except Exception as e:
                if self.args.debug:
                    self.logger.error(f"Output consumer {consumer_id} error processing output: {e}")
            finally:
                # Always mark output as done
                self._output_channel.task_done()

        if self.args.debug:
            self.logger.debug(f"Output consumer {consumer_id} finished gracefully")

    async def producer(self) -> None:
        """Legacy producer - now just starts the multi-stage pipeline"""
        if self.args.debug:
            self.logger.debug("Starting multi-stage producer pipeline...")
        await self.raw_host_producer()

    async def sprint(self) -> None:
        """sprint method with multi-producer/consumer orchestration"""
        try:
            response, good = self.utils.check_scan(self.args)
            if not good:
                self.logger.warn(response)
                exit(1)
            else:
                if not self.args.silent:
                    self.logger.info(response)

            response, good = self.utils.check_host_discovery(self.args)
            if not good:
                self.logger.warn(response)
                exit(1)
            else:
                if not self.args.silent:
                    self.logger.info(response)

            loop = asyncio.get_running_loop()
            try:
                loop.add_signal_handler(signal.SIGINT, self._signal_handler)
            except (NotImplementedError, RuntimeError):
                pass

            await self.setup()

            if self.args.arp_ping:
                responses: List[ARPPing] = await self.arp.scan()
                for response in responses:
                    if self.args.json:
                        output = self.utils.jsonize(response)
                        if not self.args.silent:
                            self.logger.stdinlog(output)
                    else:
                        output = f"found host {response.ip} with status {response.status} and mac address {response.mac}"
                        if not self.args.silent:
                            self.logger.output(output)
                    await self.save.save(output)
                return

            if self.args.interface_list:
                self.interfacers.display_interfaces()
                return

            # Setup input/output and ports
            await self.setupIO()
            await self.setupPorts()
            await self.dbproducer()

            self.totalprocess = self.hostcount * len(self.ports)

            if self.totalprocess == 0:
                if not self.args.silent:
                    self.logger.info("No hosts to process. Exiting.")
                await self.cleanup()
                exit(0)

            self.task_started = True

            if self.args.stats:
                self.probe_logger = ProgressLogger(self.logger, self.totalprocess, "Khonshu")
                if not self.args.silent:
                    self.logger.info(f"Starting multi-stage scan of {self.totalprocess} total tasks")
            else:
                self.probe_bar = ProgressBar(total=self.totalprocess, title="Khonshu")
                self.probe_bar.start()

            # Multi-stage task orchestration for our workers
            tasks = []

            # Clear all events
            self._event.clear()
            self._host_verification_event.clear()
            self._task_generation_event.clear()

            # Stage A: Raw Host Producer (single instance for coordinated streaming)
            producer_task = asyncio.create_task(self.raw_host_producer())
            tasks.append(producer_task)

            # Stage B: Host Verification Consumers (multiple for concurrent host verification)
            host_verification_tasks = []
            num_host_verifiers = min(self.args.concurrency, 20)  # Limit to prevent resource exhaustion
            for i in range(num_host_verifiers):
                task = asyncio.create_task(self.host_verification_consumer())
                host_verification_tasks.append(task)
                tasks.append(task)

            # Stage C: Task Generator Consumers (multiple for concurrent task generation)
            task_generator_tasks = []
            num_task_generators = min(self.args.concurrency // 2, 10)
            for i in range(max(1, num_task_generators)):
                task = asyncio.create_task(self.task_generator_consumer())
                task_generator_tasks.append(task)
                tasks.append(task)

            # Stage D: Task Consumers (multiple for concurrent port scanning)
            consumer_tasks = []
            for i in range(self.args.concurrency):
                task = asyncio.create_task(self.consumer())
                consumer_tasks.append(task)
                tasks.append(task)

            output_tasks = []
            for i in range(self.args.concurrency):
                task = asyncio.create_task(self.outputconsumer())
                output_tasks.append(task)
                tasks.append(task)

            if self.args.debug:
                self.logger.debug(f"Started {len(tasks)} total tasks: "
                                  f"1 producer, {len(host_verification_tasks)} host verifiers, "
                                  f"{len(task_generator_tasks)} task generators, "
                                  f"{len(consumer_tasks)} task consumers, "
                                  f"{len(output_tasks)} output consumers")

            if self.args.debug:
                self.logger.debug("Waiting for host production to complete...")
            await self._event.wait()

            if self.args.debug:
                self.logger.debug("Host production completed, waiting for host verification...")
            await self._raw_host_channel.join()

            if self.args.debug:
                self.logger.debug("Host verification completed, waiting for task generation...")
            await self._host_verification_channel.join()

            if self.args.debug:
                self.logger.debug("Task generation completed, waiting for task processing...")
            await self._task_channel.join()

            if self.args.debug:
                self.logger.debug("Task processing completed, waiting for output processing...")
            await self._output_channel.join()

            if self.args.debug:
                self.logger.debug("All processing completed, shutting down gracefully...")

            for task in tasks:
                if not task.done():
                    task.cancel()

            try:
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=10.0)
            except asyncio.TimeoutError:
                if self.args.debug:
                    self.logger.debug("Some tasks didn't finish within timeout, forcing exit")

            if self.probe_bar:
                self.probe_bar.close()

            if not self.args.silent:
                if self.cached_results > 0 or self.scanned_results > 0:
                    self.logger.info(f"Results: {self.cached_results} cached, {self.scanned_results} scanned")
                if self.args.ping and not self.args.skip_discovery:
                    self.logger.info(f"Host verification: {self.alive_host_count} alive, {self.dead_host_count} dead")

            await self.cleanup()

        except Exception as e:
            if self.args.debug:
                self.logger.error(f"Error in sprint method: {e}")
            self.logger.warn(f"Error occurred in the sprint method due to: {e}")
        finally:
            await self.cleanup()
            if not self.thread_event.is_set():
                exit(0)

    def _signal_handler(self):
        if not self.args.silent:
            self.logger.warn("CTRL+C pressed!.Saving resume file please wait")
        self.thread_event.set()
        asyncio.create_task(self._handle_interrupt())

    async def _handle_interrupt(self):
        if self.task_started:
            await self.save_resume_file()
        await self.cleanup()
        await asyncio.sleep(5)
        os._exit(1)

    async def save_resume_file(self):
        if self.probe_bar:
            self.probe_bar.close()
        filename = f"resume_{RandomUtils.random_string(5)}.cfg"
        await asyncio.sleep(5)
        cache_size = await self.diskcache.size()
        if self.args.stats:
            self.resume_logger = ProgressLogger(self.logger, cache_size, "Saving Resume")
        else:
            self.resume_bar = ProgressBar(total=cache_size, title="Saving Resume...")
            self.resume_bar.start()
        async for host in self.diskcache.iterkeys():
            await self.fileutils.write(filename, content=f"{host}\n", mode="a")
            if self.resume_bar:
                self.resume_bar.update()
            if self.resume_logger:
                await self.resume_logger.update()
        if self.resume_bar:
            self.resume_bar.close()
        if not self.args.silent:
            self.logger.info(f"saved the resume file successfully: {filename}")