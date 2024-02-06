import os 
from colorama import Fore,Back,Style
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


def loader_host(filename):
    
    try:
        
        with open(filename, "r") as data :
            
            datas = data.read().splitlines()
            
        return datas 
    
    except FileNotFoundError as e:
        
        print(f"[{bold}{red}INFO{reset}]: {bold}{white}Pleach check the hosts file {filename} exists..{reset}")
        
        quit()
        
    except KeyboardInterrupt as e:
        
        print(f"\n[{bold}{blue}INFO{reset}]: {bold}{white}Khonshu exits..{reset}")
        
        quit()
        
    except Exception as e:
        
        pass
        
def loader_port(filename):
    
    try:
        
        with open(filename, "r") as data :
            
            datas = data.read().splitlines()
            
        return datas 
    
    except FileNotFoundError as e:
        
        print(f"[{bold}{red}INFO{reset}]: {bold}{white}Pleach check the port file {filename} exists..{reset}")
        
        quit()
        
    except KeyboardInterrupt as e:
        
        print(f"\n[{bold}{blue}INFO{reset}]: {bold}{white}Khonshu exits..{reset}")
        
        quit()
        
    except Exception as e:
        
        pass
    