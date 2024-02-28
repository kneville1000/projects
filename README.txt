Hello! This simple port scanner can accept two arguments and perform a scan of ports in the range of 1 to 1024. (The port range can be modified by changing values of the STARTING_PORT and ENDING_PORT global variables at the top of the program.)

To scan a single ip address add the argument --ip XXX.XX.XX.XXX
To scan a list of ip addresses, this program can accept a file where there is one ip address per line,
add the arguement --file filename

When the scan is completed, the results will be added to the scanresults.txt file in this JSON format. Keep this text file in the same 
directory as the scanner. If an open port is on the list of known risky ports the risk_port line will return true.


{
    "Findings": [
        {
            "ip_address": "173.XX.XX.118",
            "open_port": 21,
            "risk_port": true
        }
    ]
}