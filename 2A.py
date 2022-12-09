# Dari alamat IP dan mac-address mana sajakah yang berkontribusi terhadap penggunaan jaringan komputer paling besar
# Jawaban:
from collections import Counter
from scapy.all import *

# membuka file pcapng
pcapng = rdpcap("bahandata.pcapng")

# mengekstrak alamat IP dan MAC-address
ip_list = []
mac_list = []
for pkt in pcapng:
    if pkt.haslayer(IP):
        ip_list.append(pkt[IP].src)
        ip_list.append(pkt[IP].dst)
    if pkt.haslayer(Ether):
        mac_list.append(pkt[Ether].src)
        mac_list.append(pkt[Ether].dst)

# menghitung jumlah kontribusi alamat IP dan MAC-address
ip_count = Counter(ip_list)
mac_count = Counter(mac_list)

# mencari top 5 alamat IP dan MAC-address dengan kontribusi terbesar
max_ip = ip_count.most_common(5)
max_mac = mac_count.most_common(5)

# menampilkan top 5 alamat IP dan MAC-address dengan kontribusi terbesar
print("Top 5 alamat IP dengan kontribusi terbesar:")
for ip in max_ip:
    print(ip[0] + " (" + str(ip[1]) + " kali)")
print("Top 5 MAC-address dengan kontribusi terbesar:")
for mac in max_mac:
    print(mac[0] + " (" + str(mac[1]) + " kali)")
