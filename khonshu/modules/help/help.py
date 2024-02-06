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

def all_help():
    
    print(f"""
{bold}{white}[{reset}{bold}{blue}DESCRIPTION{reset}{bold}{white}]{reset}: {bold}{white}Khonsu is a powerful port scanning tool written in python that detect open ports with concurrent and accurately{reset}

{bold}{white}[{reset}{bold}{blue}Usage{reset}{bold}{white}]{reset}: 

    {bold}{white}khonshu [options]{reset}
    
{bold}{white}[{reset}{bold}{blue}OPTIONS{reset}{bold}{white}]{reset}: {bold}{white}

    {bold}{white}[{reset}{bold}{blue}INPUT{reset}{bold}{white}]{reset}:{bold}{white}
    
            -d   ,  --domain        string   : Domain name to scan and detect for Khonshu to discover Open Ports.
            
            -l   ,  --list          string   : File name that contains targets for Khonshu to discover Open Ports.
             
            -eh ,   --exclude-host  string   : Host to exclude from the scan , Enable it when -l or --list is given.
                        
    {bold}{white}[{reset}{bold}{blue}PORTS{reset}{bold}{white}]{reset}: {bold}{white}
    
            -p   ,  --ports         int      : Specify a port number to Khonshu for detecting and scanning open ports , [Ex: -p 80 (or) 80,443 (or) 1-1024].
            
            -tp  ,  --top-ports     command      : Enable it to scan only for top port that from 1-1024. 
            
            -pf  ,  --ports-file    string   : File name that contains port number for Khonshu to scan for that ports.
            
            -ep  ,  --exclude-ports int   : Port number to exclude from port scan.
            
            -ec  ,  --exclude-cdn   command  : Skip full scan for QAF/CDN and focus on for only 80,443 port scans. {reset}
             
    {bold}{white}[{reset}{bold}{blue}RATE-LIMIT{reset}{bold}{white}]{reset}: {bold}{white}
    
            -t   ,  --timeout       int      : Timeout value for sending packets in the port 
    
            -c   ,  --concurrency   int      : Concurrency value for scans.
            
            -rt  ,  --rate-limit    int      : Rate limit value for sending packets to port scans.
                        
    {bold}{white}[{reset}{bold}{blue}UPDATES{reset}{bold}{white}]{reset}: {bold}{white}
    
            -up  ,  --updates       command  : Updates the khonshu for larest version (required: pip to be installed) {reset}
            
    {bold}{white}[{reset}{bold}{blue}OUTPUT{reset}{bold}{white}]{reset}: {bold}{white}
    
            -o   ,  --output        string   : Filename to save the scans outputs. {reset}
            
    
    {bold}{white}[{reset}{bold}{blue}SCANS{reset}{bold}{white}]{reset}: {bold}{white}
    
            -pg  ,  --ping          command  : Only do ping scans for hosts and avoid scans. {reset}
    
    {bold}{white}[{reset}{bold}{blue}DEBUG{reset}{bold}{white}]{reset}: {bold}{white}
    
            -hc  ,  --health-check  command  : Health check process for khonshu.
            
            -vr  ,  --version       command  : Shows Version of the Khonshu and exits:
            
            -nc  ,  --no-color      command  : Disable the Khonshu's colorised CLI outputs and info.
            
            -s   ,  --silent        command  : Only shows outputs and avoid other info. {reset}
               
""")
    