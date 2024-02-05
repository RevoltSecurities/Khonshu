#!/usr/bin/env python3
from colorama import Fore,Back,Style
import asyncio
import aiodns


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



host_ips = []


async def get_ip(domain, args):
    try: 
        
        resolver = aiodns.DNSResolver()
        
        result = await resolver.query(domain, 'A')
        
        if result:
            
            ip = result[0].host
            
            if args.verbose:
                
                if args.no_color:
                    
                    print(f"[DBG]: Using {ip} for host: {domain}")
                    
                else:
                    
                    print(f"[{bold}{green}DBG{reset}]: {bold}{white}Using {ip} for host: {domain}{reset}")
                    
            
        else:
            
            if args.verbose:
                
                if args.no_color:
                    
                    print(f"[WRN]: No ip address found for host: {domain}")
                    
                else:
                    
                    print(f"[{bold}{red}WRN{reset}]: {bold}{white}No ip address found for: {domain}{reset}")
                    
        if result:   
                    
            host_ips.append(f"{domain}:{ip}")
                    
    except aiodns.error.DNSError:
        
        if args.verbose:
            
            if args.no_color:
                
                print(f"[WRN]: No ip address found for host: {domain}")
                
            else:
                
                print(f"[{bold}{red}WRN{reset}]: {bold}{white}No ip address found for: {domain}{reset}")
                
    except Exception as e:
        
        pass

async def ip_threader(hostnames, args):
    
    try:
        
        if args.no_color:
                
                print(f"[INFO]: Initiating IP scans ")
                
        else:
                
                print(f"[{bold}{green}INFO{reset}]: {bold}{white}Initiating IP scans{reset}")
        
        
        tasks = [get_ip(domain, args) for domain in hostnames]
        
        await asyncio.gather(*tasks)
        
        
        return host_ips
        
    except asyncio.CancelledError as e:
        
        print(f"\n[{bold}{blue}INFO{reset}]: {bold}{white}Khonshu exits..{reset}")
        
        quit()
        
    except KeyboardInterrupt as e:
        
        print(f"\n[{bold}{blue}INFO{reset}]: {bold}{white}Khonshu exits..{reset}")
        
        quit()
        
    except Exception as e:
        
        pass
