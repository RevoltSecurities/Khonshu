# Khonshu
Khonsu is a powerful port scanning tool written in python that detect open ports with concurrent and accurately.
Khonshu is designed for open port scanning concurrently. It is a valuable asset for ethical hackers 
and penetration testers to discover open ports on targets.


### Features V1.0.1:

- Khonshu have ability of SYN Scan, Ping , Checks valid hosts
- Concurrently Scans for open ports
- Konshu is a Platform Independent Tool
- Khonshu automatically ensures that only authorized individuals can use the tool.
- Provide options to configure rate-limiting for scans to avoid detection or network disruptions.
- Scans for both IPv4/IPv6


### Installation:

#### Method 1:

```bash
git clone https://github.com/sanjai-AK47/Khonshu.git
cd Khonshu
pip install .
```

### Method 2:

```bash
pip install git+https://github.com/sanjai-AK47/Khonshu.git

```

### Usage:

```yaml
 khonshu -h
    __      __                             __          
   / /__   / /_   ____    ____    _____   / /_   __  __
  / //_/  / __ \ / __ \  / __ \  / ___/  / __ \ / / / /
 / ,<    / / / // /_/ / / / / / (__  )  / / / // /_/ / 
/_/|_|  /_/ /_/ \____/ /_/ /_/ /____/  /_/ /_/ \__,_/  
                                                       

    
                     Author : D.SanjaiKumar @CyberRevoltSecurities

[Version]: Khonshu current version v1.0.0 (latest)

[DESCRIPTION]: Khonsu is a powerful port scanning tool written in python that detect open ports with concurrent and accurately

[Usage]: 

    khonshu [options]
    
[OPTIONS]: 

    [INPUT]:
    
            -d   ,  --domain        string   : Domain name to scan and detect for Khonshu to discover Open Ports.
            
            -l   ,  --list          string   : File name that contains targets for Khonshu to discover Open Ports.
             
            -eh ,   --exclude-host  string   : Host to exclude from the scan , Enable it when -l or --list is given.
                        
    [PORTS]: 
    
            -p   ,  --ports         int      : Specify a port number to Khonshu for detecting and scanning open ports , [Ex: -p 80 (or) 80,443 (or) 1-1024].
            
            -tp  ,  --top-ports     command      : Enable it to scan only for top port that from 1-1024. 
            
            -pf  ,  --ports-file    string   : File name that contains port number for Khonshu to scan for that ports.
            
            -ep  ,  --exclude-ports int   : Port number to exclude from port scan.
            
            -ec  ,  --exclude-cdn   command  : Skip full scan for QAF/CDN and focus on for only 80,443 port scans. 
             
    [RATE-LIMIT]: 
    
            -c   ,  --concurrency   int      : Concurrency value for scans.
            
            -rt   , --rate-limit    int      : Rate limit value for sending packets to port scans.
                        
    [UPDATES]: 
    
            -up  ,  --updates       command  : Updates the khonshu for larest version (required: pip to be installed) 
            
    [OUTPUT]: 
    
            -o   ,  --output        string   : Filename to save the scans outputs. 
            
    
    [SCANS]: 
    
            -pg  ,  --ping          command  : Only do ping scans for hosts and avoid scans. 
    
    [DEBUG]: 
    
            
            -vr  ,  --version       command  : Shows Version of the Khonshu and exits:
            
            -nc  ,  --no-color      command  : Disable the Khonshu's colorised CLI outputs and info.
            
            -s   ,  --silent        command  : Only shows outputs and avoid other info. 
               

```

**INFO:** Khonshu is mainly uses root user previlege so for every scans it requires the root privilege to scan for open ports  and Khonshu have ability to handle high loads and also can give accurate results for the scan, far now
          Khonshu handle only domains and later on Khonshu features will be updated soon on upcoming version, So it can be used for many purpose when it comes to open port scanning and hope Khonshu will help you on your penetration testing , If you like Khonshu give ⭐ and show your ❤️ for it.If you want more feature to include or give feedbacks just create a issue in [Khonshu](https://github.com/sanjai-AK47/Khonshu) or connect with me with my [Linkedin](https://www.linkedin.com/in/d-sanjai-kumar-109a7227b)



