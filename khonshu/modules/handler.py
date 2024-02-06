import asyncio
from colorama import Fore,Back,Style
import os
import random


red =  Fore.RED

green = Fore.GREEN

magenta = Fore.MAGENTA

cyan = Fore.CYAN

mixed = Fore.RED + Fore.BLUE

blue = Fore.BLUE

yellow = Fore.YELLOW

white = Fore.WHITE

reset = Style.RESET_ALL

bold = Style.BRIGHT

colors = [ green, cyan, blue]

random_color = random.choice(colors)

try:
    from .help.help import all_help
    from .cli.cli import cli
    from .banner.banner import banner
    from .extender.extender import extender, get_root
    from .extract.extract import port_extractor, port_file_extractor, host_extractor
    from .version.version import check_version
    from .wordlist.wordlist import loader_host, loader_port
    from .core.hostip import ip_threader
    from .core.pingme import ping_threads
    from .core.lib import core_task
except ImportError as e:
    
    print(f"[{bold}{red}INFO{reset}]: {bold}{white}Import Error occured in Module imports due to: {e}{reset}")
    
    print(f"[{bold}{blue}INFO{reset}]: {bold}{white}If you are encountering this issue more than a time please report the issues in Khonshu Github page.. {reset}")
    
    quit()


red =  Fore.RED

green = Fore.GREEN

magenta = Fore.MAGENTA

cyan = Fore.CYAN

mixed = Fore.RED + Fore.BLUE

blue = Fore.BLUE

yellow = Fore.YELLOW

white = Fore.WHITE

reset = Style.RESET_ALL

bold = Style.BRIGHT

colors = [ green, cyan, blue]

def updateme():
    
    latest = check_version()
    
    version = "v1.0.1"
    
    if latest == version:
        
        print(f"[{blue}{bold}Update{reset}]:{bold}{white}Khonshu already in latest version{reset}")
        
        exit()
        
    else:
        
        print(f"[{blue}{bold}Update{reset}]: {bold}{white}Updating Khonshu new Version now.{reset}")
        
        os.system(f"pip install https://github.com/sanjai-AK47/Khonshu.git")
        
        print(f"[{blue}{bold}Update{reset}]: {bold}{white}Please check once manually for khonshu latest version{reset}")
        
        quit()
    
    

def version():
    
    latest = check_version()
    
    version = "v1.0.1"
    
    if latest == version:
        
        print(f"[{blue}{bold}Version{reset}]:{bold}{white}Khonshu current version {version} ({green}latest{reset}{bold}{white}){reset}")
        
    else:
        
        print(f"[{blue}{bold}Version{reset}]: {bold}{white}Khonshu current version {version} ({red}outdated{reset}{bold}{white}){reset}")


def help():
    
        
        all_help()
        
        quit()
        
def get_version():
    
    version()
    
    quit()


        
def root_access(args):
    
    get_root(args)
    
def port_analyser(args):
    
        if args.ports:
            
            ports = port_extractor(args.ports, args)
            
        if args.ports_file:
            
            ports = loader_port(args.ports_file)
            
            
            ports = port_file_extractor(ports, args)
            
        if args.exclude_cdn:
            
            ports = port_extractor('80, 443', args)
        
        if args.top_ports:
            
            ports = port_extractor("1-1024", args)
            
        if not args.ports and not args.ports_file and not args.exclude_cdn and not args.top_ports :
            
            ports = port_extractor("22,21,8080,8000,80,443", args)
            
        return ports
    
def ping_runner(domain, args):
    
    asyncio.run(ping_threads(domain, args))
    
    quit()
    
def ip_runner(domain, args):
    
    ips = asyncio.run(ip_threader(domain, args))
    
    return ips

def port_runner(domains, ports, args):
    
    asyncio.run(core_task(domains, ports, args))
    
    
def domain_manager(args):
    
    if args.domain:
        
        domain = [args.domain]
        
        ports = port_analyser(args)
        
        if args.ping:
            
            ping_runner(domain, args)
            
            quit()
            
        if not args.ping:
            
            ips = ip_runner(domain, args)
            
            port_runner(domain, ports, args)
            
            
def hosts_manager(args):
    
    if args.list:
        
        domains = loader_host(args.list)
        
        if args.exclude_host:
            
            domains = host_extractor(domains, args)
            
        ports = port_analyser(args)
        
        if args.ping:
            
            ping_runner(domains, args)
            
            quit()
            
        if not args.ping:
            
            ips = ip_runner(domains, args)
            
            port_runner(domains, ports, args)
            
            
        
        

def handler():
     
    global args
    
    args = cli()
    
    banners = banner()
    
    if not args.silent:
    
        print(f"{bold}{random_color}{banners}{reset}")
    
    if not args.version:
        
        if not args.silent:
        
            version()
    
    if args.help:
        
        help()
        
    if args.version:
        
        get_version()
        
    root_access(args)
    
    extender()
    
    if args.domain:
        
        domain_manager(args)
    
    if args.list:
        
        hosts_manager(args)
        
    if args.update:
        
        updateme()
    


    
    
    
    
        
    
    
    
    
    
    