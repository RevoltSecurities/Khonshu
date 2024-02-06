import asyncio
import socket
import aiofiles
from colorama import Fore,Back,Style
import os
import idna


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


async def save(result, args):
    
    try:
        
        
            if args.output:
        
        
            
                if os.path.isfile(args.output):
                
                    filename = args.output
                
                elif os.path.isdir(args.output):
                
                    filename = os.path.join(args.output, f"Khonshu_results.txt")
                
                else:
                
                    filename = args.output
            
            
        
            async with aiofiles.open(filename, "a") as w:
                
                await w.write(result + '\n')

    except KeyboardInterrupt as e:
        
        
        print(f"\n[{bold}{blue}INFO{reset}]: {bold}{white}Khonshu exits..{reset}")
        
        quit()
        
    except asyncio.CancelledError as e:
        
        
        print(f"\n[{bold}{blue}INFO{reset}]: {bold}{white}Khonshu exits..{reset}\n")
        
        quit()
        
        
        
    except Exception as e:
        
        pass



async def port_scan(domains, port, sem, args):
    
    try:
        
        async with sem:
            
            
            if len(domains) == 0:
                
                return
            
            domains = idna.encode(domains).decode()
            
            
            streader, stwriter = await asyncio.wait_for(asyncio.open_connection(domains, port), timeout=args.timeout)
            
            
            
            if args.no_color:
                
                print(f"[INF]: Found open port on host {domains}\n{domains}:{port}")
                
            else:
                
                
                print(f"[{bold}{blue}INFO{reset}]: {bold}{white}Found open port on host {domains}\n{domains}:{port}{reset}")
                
                
            if args.output:
                
                await save(f"{domains}:{port}", args)
                
        await asyncio.sleep(args.rate_limit)
    
    except ( asyncio.TimeoutError, socket.gaierror, ConnectionRefusedError, TimeoutError, OSError) as e:
        
        pass
    
    except idna.IDNAError as e:
        
        pass
    
    except (KeyboardInterrupt, asyncio.CancelledError) as e:
        
        print(f"\n[{bold}{blue}INFO{reset}]: {bold}{white}Khonshu exits..{reset}\n")
        
        quit()
        
        
    except Exception as e:
        
        pass
        
async def core_task(hostnames, ports, args):
    
    try:
        if not args.silent:
            if args.no_color:
                
                print(f"[INFO]: Initiating Port scans ")
                
            else:
                
                print(f"[{bold}{green}INFO{reset}]: {bold}{white}Initiating Port scans{reset}")
    
        sem = asyncio.Semaphore(args.concurrency)

        tasks = [port_scan(host, port, sem, args)for host in hostnames for port in ports]
    
        await asyncio.gather(*tasks)
        
    except (KeyboardInterrupt, asyncio.CancelledError) as e:
        
        print(f"\n[{bold}{blue}INFO{reset}]: {bold}{white}Khonshu exits..{reset}\n")
        
        quit()
        
        
    except Exception as e:
        
        pass
