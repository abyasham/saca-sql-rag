import os

inputFilePath = "/home/iot/Desktop/ICU_Usecase/Pcaps/mqtt2.pcap"  # mention path+Name of the pcap file
outputFilePath = inputFilePath + '_security.csv'

# Most relevant security features for attack detection (based on your example)

# Essential network flow features
essential_flow = "-e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport "

# Critical TCP connection state features  
tcp_connection_features = "-e tcp.ack -e tcp.connection.fin -e tcp.connection.rst -e tcp.connection.syn -e tcp.flags.ack -e tcp.flags.fin -e tcp.flags.push -e tcp.flags.reset -e tcp.flags.syn "

# TCP integrity and analysis features
tcp_analysis_features = "-e tcp.checksum -e tcp.analysis.retransmission -e tcp.analysis.duplicate_ack -e tcp.analysis.fast_retransmission -e tcp.analysis.out_of_order "

# MQTT security-critical features for IoT
mqtt_security_features = "-e mqtt.conflags -e mqtt.conflag.cleansess -e mqtt.conflag.willflag -e mqtt.conflag.passwd -e mqtt.msgtype -e mqtt.clientid "

# HTTP response analysis for web attacks
http_security_features = "-e http.response -e http.response.code -e http.request.method "

# ARP spoofing detection
arp_security_features = "-e arp.opcode -e arp.duplicate_address_detected "

# ICMP for reconnaissance detection  
icmp_security_features = "-e icmp.type -e icmp.code -e icmp.checksum "

# DNS for tunneling and exfiltration detection
dns_security_features = "-e dns.qry.name -e dns.qry.type -e dns.flags.response "

# Frame timing for traffic analysis
timing_features = "-e frame.time_relative -e frame.len "

# Output formatting
others = "-E header=y -E separator=, -E quote=d -E occurrence=f "

# Combine only the most security-critical features
allFeatures = (essential_flow + tcp_connection_features + tcp_analysis_features + 
               mqtt_security_features + http_security_features + arp_security_features + 
               icmp_security_features + dns_security_features + timing_features + others)

command = 'tshark -r ' + inputFilePath + ' -T fields ' + allFeatures + '> ' + outputFilePath

print(f"--- Input File: {inputFilePath} ---")
print('--Processing File for Security Analysis--')
print("=== Extracting Core Security Features for Attack Detection ===")
print("Features being extracted:")
print("• Network Flow: IP addresses, ports")
print("• TCP Connection States: SYN, FIN, RST, ACK flags") 
print("• TCP Analysis: Retransmissions, duplicates, out-of-order")
print("• MQTT IoT Security: Connection flags, message types")
print("• HTTP Response Analysis: Response codes, methods")
print("• ARP Spoofing Detection: ARP opcodes")
print("• ICMP Reconnaissance: ICMP types and codes")
print("• DNS Security: Query names and types")
print("• Traffic Timing: Frame timing and lengths")

os.system(command)

print("--- Security CSV Generated ---")
print(f"Output saved to: {outputFilePath}")

# Optional: Display column count and first few rows for verification
try:
    import pandas as pd
    df = pd.read_csv(outputFilePath)
    print(f"Total security columns extracted: {len(df.columns)}")
    print(f"Total packets analyzed: {len(df)}")
    print(f"\nExtracted columns: {list(df.columns)}")
    print("\nSample of extracted security features:")
    print(df.head(3))
except ImportError:
    print("Install pandas to see data preview: pip install pandas")
except Exception as e:
    print(f"Error reading CSV: {e}")