#!/usr/bin/env python3
from colorama import Fore,Back,Style
import asyncio
import aioping as ping
import socket


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



async def pinger(domain, args):
    
    try:
        
        delay = await ping.ping(domain)
        
        if delay:
        
            if args.no_color:
            
                print(f"[INFO]: Ping Successfull for {domain} with {delay}")
            
            else:
        
            
                print(f"[{bold}{blue}INFO{reset}]: {bold}{white}Ping Successfull for {domain} with {delay}{reset}")
                
        else:
            
            if args.verbose:
            
                if args.no_color:
            
                    print(f"[INFO]: Ping Unsuccessfull for {domain}")
            
                else:
            
                    print(f"[{bold}{red}INFO{reset}]: {bold}{white}Ping Unsuccessfull for {domain}{reset}")
            
    except TimeoutError as e:
        
        if args.verbose:
            
                if args.no_color:
            
                    print(f"[INFO]: Ping Unsuccessfull for {domain}")
            
                else:
            
                    print(f"[{bold}{red}INFO{reset}]: {bold}{white}Ping Unsuccessfull for {domain}{reset}")
            
    except socket.gaierror as e:
        
        if args.verbose:
            
                if args.no_color:
            
                    print(f"[INFO]: Ping Unsuccessfull for {domain}")
            
                else:
            
                    print(f"[{bold}{red}INFO{reset}]: {bold}{white}Ping Unsuccessfull for {domain}{reset}")
        
            
    except asyncio.CancelledError as e:
        
        print(f"\n[{bold}{blue}INFO{reset}]: {bold}{white}Khonshu exits..{reset}")
        
        quit()
        
        
    except KeyboardInterrupt as e:
        
        print(f"\n[{bold}{blue}INFO{reset}]: {bold}{white}Khonshu exits..{reset}")
        
        quit()
        
    except Exception as e:
        
        pass


async def ping_threads(hostnames,  args):
    
    try:
        
        tasks = [pinger(domain, args)for domain in hostnames]
        
        await asyncio.gather(*tasks)
        
    except asyncio.CancelledError as e:
        
        print(f"\n[{bold}{blue}INFO{reset}]: {bold}{white}Khonshu exits..{reset}")
        
        quit()
        
        
    except KeyboardInterrupt as e:
        
        print(f"\n[{bold}{blue}INFO{reset}]: {bold}{white}Khonshu exits..{reset}")
        
        quit()
        
    except Exception as e:
        
        pass
        

    
    
    
    