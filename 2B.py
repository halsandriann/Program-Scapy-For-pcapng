# Pada waktu kapan sajakah transmisi tertinggi yang terjadi ?
# Jawaban:
from collections import Counter
from scapy.all import *

# membuka file pcapng
pcapng = rdpcap("bahandata.pcapng")

# mengekstrak waktu transmisi dan alamat IP
time_list = []
ip_list = []
for pkt in pcapng:
    if pkt.haslayer(IP):
        time_list.append(float(pkt.time))
        ip_list.append(pkt[IP].src)
        ip_list.append(pkt[IP].dst)

# menghitung jumlah waktu transmisi
time_count = Counter(time_list)
ip_count = Counter(ip_list)

# mencari waktu transmisi tertinggi
max_time = time_count.most_common(1)[0]
# mencari alamat IP pada waktu transmisi tertinggi
max_ip = ip_count.most_common(1)[0]

# menampilkan waktu transmisi tertinggi dan alamat IP
print("Transmisi tertinggi terjadi pada: " + str(max_time[0]) + " (" + str(max_time[1]) + " kali)")
print("Timestamp waktu: " + datetime.fromtimestamp(max_time[0]).strftime("%d/%m/%Y %H:%M:%S") + " (" + str(max_time[1]) + " kali)")
print("Alamat IP pada transmisi tertinggi: " + max_ip[0])
