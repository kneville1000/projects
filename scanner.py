import socket
import json
import argparse

#Details and skeleton of project: use argparse to determine single or multiple ips for scanning
#input one IP address or a list of IP addresses and scan ports, export info in JSON

STARTING_PORT = 1
ENDING_PORT = 1025
TIMEOUT = 0.2
RISKY_PORTS = [20, 21, 22, 23, 25, 137, 139, 445, 1433, 2375, 3306, 3389, 5432, 6379, 9200, 9300, 10250, 10255, 16379, 27017, 27018]

results = {
        'Findings': []
}


def scan(target):
    """This should scan ports and return a result if one is open"""
    open_ports = []
    for port in range(STARTING_PORT, ENDING_PORT):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((target, port))
        if result == 0:
                open_ports.append(port)
        sock.close()
    return open_ports


def format_result(target, open_port):
    """This should format the result into JSON"""       
    result = {
        "ip_address": target,
        "open_port": open_port,
        "risk_port": risk_check(open_port)
    }
    return result


def risk_check(open_port):
     """This should compare each open port against the list of known risky ports"""
     if open_port in RISKY_PORTS:
        return True
     if open_port not in RISKY_PORTS:
        return False
          
     


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", "--IP", type=str, dest= "target", help="Please enter the IP address you wish to scan.")
    parser.add_argument("--file", type=str, dest= "ip_list", help="please provide a text document containing a list of IP addresses")

    args = parser.parse_args()
    
    if args.target:
        open_ports = scan(args.target)
        print(f"Open ports on {args.target}: {open_ports}")
        for open_port in open_ports:
            results["Findings"].append(format_result(args.target, open_port))

    if args.ip_list:
        with open(args.ip_list, 'r') as ips:
            for line in ips:
                line = line.strip()
                open_ports = scan(line)
                print(f"Open ports on {line}: {open_ports}")
                for open_port in open_ports:
                    results["Findings"].append(format_result(line, open_port))

    with open('scanresults.txt', 'w') as file:
        file.write(json.dumps(results, indent=4))
    print("Results exported to text file")
    
    
main()