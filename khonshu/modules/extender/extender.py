import platform
import os 
import resource
from colorama import Fore,Back,Style


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



def extender():  
    try:
        
        soft , hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        
        new = 1000000
        
        osname = platform.system()
        
        if osname == "Linux" or  osname == "Darwin":
            
            
            
            resource.setrlimit(resource.RLIMIT_NOFILE, (new, hard))
            
    except KeyboardInterrupt as e:
        
        quit()
        
    except Exception as e:
        
        pass
        
        

def get_username():
    
    try:
        
        username = os.getlogin()
        
    except OSError:
       
        username = os.getenv('USER') or os.getenv('LOGNAME') or os.getenv('USERNAME') or 'Unknown User'
        
    except Exception as e:
        
        username = "Unknown User"
        
    
    return username


def get_root(args):
    
    try:
        
        
        osname = platform.system()
        
        username = get_username()
        
        if osname == "Linux" or  osname == "Darwin":
            
            if os.geteuid() == 0:
                
                pass
            else:
                
                print(f"[{bold}{red}WRN{reset}]: {bold}{white}Permission denied for {username} please execute the Khonshu with root access.{reset}")
                
                quit()
        
        else:
            
            pass
            
            
    except KeyboardInterrupt as e:
        
        quit()
        
    except Exception as e:
        
        pass
    
    