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
    AsyncAckScanner,
    AioARP,
    AioICMP,
    AioTCP,
    AsyncConnectScanner,
    AsyncStealthFlagScanner,
    AsyncSynScanner,
    AsyncUdpScanner,
    AsyncWindowsScanner
)
from revoltlogger import Logger,LogLevel
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
import asyncio
from aiolimiter import AsyncLimiter
import sys
import os
import signal
from typing import List
import json
import threading
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
        self.logger = Logger(colored=False if self.args.no_color else True,level=LogLevel.DEBUG)
        self.utils = Utils()
        self.interfacers = InterfaceManager()
        self.probe_bar: ProgressBar = None
        self.db_bar: ProgressBar = None
        self.resume_bar: ProgressBar = None
        self.diskcache: AsyncDiskCache = None
        self.tmpdir : AsyncTempdir = AsyncTempdir()
        self.tmpfile : AsyncTempfile = AsyncTempfile()
        self._dbevent = asyncio.Event()
        self._event = asyncio.Event()
        self._oevent = asyncio.Event()
        self.rate_limiter = AsyncLimiter(self.args.rate_limit,1)
        self._lock = asyncio.Lock()
        self.dbsemaphore = asyncio.Semaphore(500)
        self.semaphore = asyncio.Semaphore(self.args.concurrency)
        self.task_started = False
        self._pychannel = AsyncQueue(maxsize=self.args.concurrency*2)
        self._outchannel = AsyncQueue(maxsize=self.args.concurrency*2)
        self._dbchannel = AsyncQueue(maxsize=10000)
        self.fileutils = FileUtils()
        self.folderutils = FolderUtils()
        self.generics = GenericUtils()
        self.iputils = IPUtils()
        self.cidrstreamer = NETStreamer(max_size=1000)
        self.tmpdirpath = None
        self.tmpfilepath = None
        self.inputer = None
        self.dns :DnsUtils = None
        self.pas :PassiveScanner = None
        self.ack :AsyncAckScanner = None
        self.syn :AsyncSynScanner = None
        self.con :AsyncConnectScanner = None
        self.fin :AsyncStealthFlagScanner = None
        self.null:AsyncStealthFlagScanner = None
        self.xmas:AsyncStealthFlagScanner = None
        self.udp :AsyncUdpScanner = None
        self.win :AsyncWindowsScanner = None
        self.arp :AioARP = None
        self.icmp:AioICMP = None
        self.tcp :AioTCP = None
        self.save:Save = None
        self.resolvers = ["8.8.8.8", "1.1.1.1"]
        self.ports = None
        self.port_state = None
        self.thread_event = threading.Event()

    async def setup(self) -> None:
        self.tmpdirpath = await self.tmpdir.create()
        self.diskcache = AsyncDiskCache(directory=self.tmpdirpath)
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
        if self.args.host_discovery and self.args.tcp_ack_ping or self.args.tcp_syn_ping:
            method = "syn" if self.args.tcp_syn_ping else "ack"
            self.tcp = AioTCP(timeout=self.args.timeout,retries=self.args.retry,method=method, ports=self.generics.string_to_int_list(self.args.tcp_ports))
        if self.args.host_discovery and self.args.icmp_echo_ping or self.args.icmp_timestamp_ping or self.args.icmp_address_mask_ping:
            if self.args.icmp_echo_ping:
                method = "echo"
            elif self.args.icmp_timestamp_ping:
                method = "timestamp"
            else:
                method = "mask"
            self.icmp = AioICMP(timeout=self.args.timeout,retries=self.args.retry,method=method)
        if self.args.host_discovery and self.args.arp_ping:
            self.arp = AioARP(timeout=self.args.timeout, retries=self.args.retry, interface=self.args.interface)
        if self.args.scan_type == "connect":
            self.con = AsyncConnectScanner(timeout=self.args.timeout, retries=self.args.retry)
        if self.args.scan_type == "syn":
            self.syn = AsyncSynScanner(timeout=self.args.timeout, retries=self.args.retry)
        if self.args.scan_type == "ack":
            self.ack = AsyncAckScanner(timeout=self.args.timeout, retries=self.args.retry)
        if self.args.scan_type == "udp":
            self.udp = AsyncUdpScanner(timeout=self.args.timeout, retries=self.args.retry)
        if self.args.scan_type == "windows":
            self.win = AsyncWindowsScanner(timeout=self.args.timeout, retries=self.args.retry)
        if self.args.scan_type == "null":
            self.null = AsyncStealthFlagScanner(scan_type="null", timeout=self.args.timeout, retries=self.args.retry)
        if self.args.scan_type == "fin":
            self.fin = AsyncStealthFlagScanner(scan_type="fin", timeout=self.args.timeout, retries=self.args.retry)
        if self.args.scan_type == "xmas":
            self.fin = AsyncStealthFlagScanner(scan_type="xmas", timeout=self.args.timeout, retries=self.args.retry)
        self.save = Save(self.args.output, jsonize=self.args.json)
        return
    async def cleanup(self) -> None:
        try:
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
                    if await self.diskcache.add(json.dumps(request),request):
                        self.hostcount+=1
                        self.db_bar.update()
                elif self.iputils.is_cidr(host):
                    async for ip in self.cidrstreamer.stream(host):
                        request =  {"ip": ip}
                        if await self.diskcache.add(json.dumps(request), request):
                            self.hostcount += 1
                            self.db_bar.update()
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
                            request = {"ip": ip,"domain": host}
                            if await self.diskcache.add(json.dumps(request), request):
                                self.hostcount += 1
                                self.db_bar.update()
                    else:
                        ip = RandomUtils.random_choice(ips)
                        if self.args.debug:
                            self.logger.debug(f"using {ip} address for host {host}")
                        request = {"ip": ip,"domain": host}
                        if await self.diskcache.add(json.dumps(request), request):
                            self.hostcount += 1
                            self.db_bar.update()
            else:
                if await self.diskcache.add(host,True):
                    self.hostcount += 1
                    self.db_bar.update()

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

        self.db_bar = ProgressBar(total=None, title="Loading...")
        self.db_bar.start()
        self._dbevent.clear()
        dbtasks = []
        dbtasks.append(
            asyncio.create_task(producer())
        )
        for _ in range(500):
            dbtasks.append(
                asyncio.create_task(consumer())
            )
        await self._dbevent.wait()
        await self._dbchannel.join()
        for task in dbtasks:
            task.cancel()
        self.db_bar.close()
        if self.args.debug:
            self.logger.debug(f"Total number of host loaded for the enumeration: {self.hostcount}")

    async def setupIO(self) -> None:

        if self.args.host:
            hosts = self.utils.host_filter(hosts=self.generics.string_to_string_list(self.args.host), exclude=self.generics.string_to_string_list(self.args.exclude_hosts))
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
            self.logger.warn(f"no inputs provided for khonshu")
            await self.cleanup()
            exit(1)
        else:
            self.tmpfilepath = await self.tmpfile.create()
            self.inputer = self.tmpfilepath
            await self.fileutils.stdin_2_file(self.tmpfilepath)
            return

    async def setupPorts(self)-> None:
        self.port_state = self.generics.string_to_string_list(self.args.port_state)

        if self.args.host_discovery:
            self.ports = [80]
            return

        if self.args.passive:
            self.ports = [80]
            return

        if self.args.port:
            self.ports = self.utils.port_filter(ports=self.generics.string_to_int_list(self.args.port),
                                                exclude=self.generics.string_to_int_list(self.args.exclude_hosts))
            return

        if self.args.port_file:
            if not await self.fileutils.file_exist(self.args.port_file):
                self.logger.warn(f"{self.args.port_file} no such file or directory exist")
                exit(1)

            strport = await self.fileutils.readlines(self.args.port_file)
            self.ports = self.utils.port_filter(ports=self.utils.str_list_to_int_list(strport),
                                                exclude=self.generics.string_to_int_list(self.args.exclude_hosts))
            return

        if self.args.top_ports:
            self.ports = self.utils.port_filter(ports=self.utils.top_port(self.args.top_ports),
                                                exclude=self.generics.string_to_int_list(self.args.exclude_hosts))
            return

        if self.ports is None:
            self.ports = self.utils.port_filter(ports=self.utils.top_port("100"),
                                                exclude=self.generics.string_to_int_list(self.args.exclude_hosts))
        return

    async def producer(self) -> None:
        async for host_task in self.diskcache.iterkeys():
            try:
                data = json.loads(host_task)
                for port in self.ports:
                    request = Request(ip=data.get("ip"), port=port, domain=data.get("domain", None), type=self.args.scan_type)
                    await self._pychannel.put(request)
            except Exception as e:
                self.logger.error(f"Error occured due to: {e}")
        self._event.set()

    async def consumer(self) -> None:
        while not self.thread_event.is_set():
            if self.thread_event.is_set():
                return
            request: Request = await self._pychannel.get()
            await self.task(request)
            if request.port == self.ports[-1] and not self.thread_event.is_set():
                await self.diskcache.delete(json.dumps({"ip": request.ip, "domain": request.domain}))
            self._pychannel.task_done()

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
                            await self._outchannel.put(output)
                        return

                    elif self.args.passive:
                        responses: List[Response] = await self.pas.scan(request=request)
                        if not responses:
                            return
                        for res in responses:
                            if res and res.status in self.port_state:
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
                                await self._outchannel.put(output)
                        return

                    else:
                        if not self.args.skip_discovery:
                            response = await self.icmp.ping(host=request.ip)
                            if response.status != "alive":
                                return

                        res: Response = None
                        if self.args.scan_type == "connect" and self.con:
                            res = await self.con.scan(request)
                        elif self.args.scan_type == "syn" and self.syn:
                            res = await self.syn.scan(request)
                        elif self.args.scan_type == "ack" and self.ack:
                            res = await self.ack.scan(request)
                        elif self.args.scan_type == "udp" and self.udp:
                            res = await self.udp.scan(request)
                        elif self.args.scan_type == "windows" and self.win:
                            res = await self.win.scan(request)
                        elif self.args.scan_type in ["null", "fin", "xmas"] and self.fin:
                            res = await self.fin.scan(request)

                        if res and res.status in self.port_state:
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
                            await self._outchannel.put(output)
                        return
        except Exception as e:
            self.logger.warn(f"Error occurred in the task method due to: {e}")
        finally:
            if not self.thread_event.is_set():
                self.probe_bar.update()

    async def outputconsumer(self) -> None:
        while not self.thread_event.is_set():
            output = await self._outchannel.get()
            if output:
                    if self.args.json:
                        self.logger.stdinlog(output)
                    else:
                        if self.args.verbose:
                            self.logger.output(output)
                        else:
                            self.logger.stdinlog(output)

                    if self.args.json and isinstance(output, str):
                        try:
                            output = json.loads(output)
                        except json.JSONDecodeError:
                            pass
                    await self.save.save(output)
                    self._outchannel.task_done()

    async def sprint(self) -> None:
        try:
            response,good = self.utils.check_scan(self.args)
            if not good:
                self.logger.warn(response)
                exit(1)
            else:
                self.logger.info(response)

            response,good = self.utils.check_host_discovery(self.args)
            if not good:
                self.logger.warn(response)
                exit(1)
            else:
                self.logger.info(response)
            loop = asyncio.get_running_loop()
            loop.add_signal_handler(signal.SIGINT, self._signal_handler)
            await self.setup()
            if self.args.arp_ping:
                responses : List[ARPPing] = await self.arp.scan()
                for response in responses:
                    if self.args.json:
                        output = self.utils.jsonize(response)
                        self.logger.stdinlog(output)
                    else:
                        output = f"found host {response.ip} with status {response.status} and mac address {response.mac}"
                        self.logger.output(output)
                    await self.save.save(output)
                return

            if self.args.interface_list:
                self.interfacers.display_interfaces()
                return

            await self.setupIO()
            await self.setupPorts()
            await self.dbproducer()
            self.totalprocess = self.hostcount * len(self.ports)
            if self.totalprocess == 0:
                self.logger.info("No URLs to process. Exiting.")
                await self.cleanup()
                exit(0)
            self.task_started = True
            self.probe_bar = ProgressBar(total=self.totalprocess, title="Khonshu")
            self.probe_bar.start()
            tasks = []
            self._event.clear()
            tasks.append(
                asyncio.create_task(self.producer())
            )

            """
            Spawns a fixed number of consumer tasks. Each consumer is responsible for 
            creating additional port producers and their corresponding workers based on 
            the defined concurrency level. These workers efficiently manage the scheduling 
            and execution of concurrent port scan coroutines.
            """

            for _ in range(self.args.concurrency):
                tasks.append(
                    asyncio.create_task(self.consumer())
                )

            for _ in range(self.args.concurrency):
                tasks.append(
                    asyncio.create_task(self.outputconsumer())
                )
            await self._event.wait()
            await self._pychannel.join()
            await self._outchannel.join()
            for task in tasks:
                task.cancel()
            self.probe_bar.close()
        except Exception as e:
            self.logger.warn(f"Error occured in the sprint method due to: {e}")
        finally:
            await self.cleanup()


    def _signal_handler(self):
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
        self.probe_bar.close()
        filename = f"resume_{RandomUtils.random_string(5)}.cfg"
        await asyncio.sleep(5) #wait for few seconds to stop the background threads and start calculating the progress bar for accurate view
        self.resume_bar = ProgressBar(total=await self.diskcache.size(), title="Saving Resume...")
        self.resume_bar.start()
        async for host in self.diskcache.iterkeys():
            await self.fileutils.write(filename, content=f"{host}\n",mode="a")
            self.resume_bar.update()
        self.resume_bar.close()
        self.logger.info(f"saved the resume file successfully: {filename}")