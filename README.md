
#🔍 Java Port Scanner
A multithreaded Java port scanner that prioritizes scanning based on port likelihoods, detects basic service banners, and simulates a defender that blocks scans after repeated suspicious activity.

#🛠 Features
Scans all 65,535 TCP ports using a probability-weighted approach.

Outputs HTML scan report (scan_report.html) with open ports and banners.

Banner grabbing for open ports.

Simulated defender that blocks after scanning more than a threshold number of ports.

Multithreaded scanning for high performance.

#📄 Output
After the scan:
A file named scan_report.html is generated in the current directory.
Example output in terminal:

Enter IP address to scan: 192.168.1.1
Port 80 is open. Banner: HTTP/1.1 200 OK
Port 22 is open. Banner: SSH-2.0-OpenSSH_8.4
...
Scan complete. Report generated: scan_report.html

#🧠 How It Works
Probability Weights: Certain common ports (e.g., 22, 80, 443) are more likely to be scanned first.

Adaptive Learning: Each scan updates the probability of a port being open.

Simulated Defender: Blocks scanning if more than DEFENDER_THRESHOLD ports are scanned (default: 10).

Concurrency: Uses a thread pool of 100 threads for parallel scanning.
