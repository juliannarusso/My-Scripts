
#This checks the number of arugments, if not exactly one, it will print useage to stderr and exit non-zero
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 subnet" >&2
    exit 1
fi

#This define 2 variables used within nmap
#Only shows open ports
#-sn does a sing scan for host discovery
# -PS21 -23,25,53,80,443,3389 are TCP SYN 'ping' to listed ports trying to elicit a response by initating a SYN
# -PO IP protocol ping
#-PE ICMP echo request ping
#-PM ICMPtomestamp request
#-PP ICMP ping-type
opts="-T4 --open" 
pingopts="-sn -PS21-23,25,53,80,443,3389 -PO -PE -PM -PP" 

#This prints the status lines, then runs the nmap ping scan on the supplied subnet 
#Then writes output in grepable format to alive.gnmap
# -oG produces 'grepable' output that the script parses
echo "--------"
echo "Finding active hosts"
echo "--------"
echo "nmap $opts $pingopts -oG alive.gnmap $1"
nmap $opts $pingopts -oG alive.gnmap $1

#This parses alive.gnmap to extract IP addresses of hosts with Status: Up
grep "Status: Up" alive.gnmap | awk '{ print $2 }' > targets
count=$(wc -l targets | awk '{ print $1 }')
echo "[+] Found $count active hosts."

#Runs a full TCP port scan on each discovered host
echo ""
echo "--------"
echo "Finding open ports"
echo "--------"
echo "nmap $opts -iL targets -p 1-65535 -oG ports.gnmap"
nmap $opts -iL targets -p 1-65535 -oG ports.gnmap

#Parses the ports.gnmap file for open ports
grep -o -E "[0-9]+/open" ports.gnmap | cut -d "/" -f1 | sort -u > ports
count=$(wc -l ports | awk '{ print $1 }')
echo "[+] Found $count unique open ports"

# runs an aggressive nmap scan against the discovered hosts but only on the discovered ports.
echo ""
echo "--------"
echo "Running full nmap scan"
echo "--------"

portlist=$(paste -sd, ports)
echo "nmap $opts -iL targets -p $portlist -A -oA full_scan"
nmap $opts -iL targets -p $portlist -A -oA full_scan
echo "[+] Scan results available in full_scan.*"