included_ports = []

included_host = []

def port_extractor(ports, args):
    
    ports_list = []
    
    
    if "," in ports:
        
        final = ports.split(",")
        
        ports_list.extend([int(port)for port in final])
        
    elif "-" in ports:
        low, high = ports.split("-")
        
        ports_list.extend(range(int(low), int(high)+1))
        
    else:
        
        
        ports_list.append(ports)
        
    for port in ports_list :
        
        if args.exclude_ports:
        
            if port in args.exclude_ports:
            
               pass
           
            else:
            
                included_ports.append(int(port))
        else:
            
            included_ports.append(int(port))
            
    return included_ports
            

def port_file_extractor(ports,args):
    
    for port in ports :
        
        if args.exclude_ports:
        
            if int(port) in args.exclude_ports:
            
               pass
           
            else:
            
                included_ports.append(int(port))
        else:
            
            included_ports.append(int(port))
            
    return included_ports
            

def host_extractor(hostnames, args):
    
    for host in hostnames:
        
        if args.exclude_host:
            
            if host in args.exclude_host:
                
                pass
            
            else:
                
                included_host.append(host)
                
        else:
            
            included_host.append(host)
            
    return included_host
    
    