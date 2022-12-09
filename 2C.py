# Protokol dan transmisi mana sajakah yang paling sering mengalami RESET pada Flag komunikasi TCP nya
# Jawaban:
from scapy.all import *

try:
    # membuka file pcapng
    pcapng = rdpcap("bahandata.pcapng")

    # menghitung jumlah reset pada setiap transmisi
    reset_count = {}
    for pkt in pcapng:
        if pkt.haslayer(TCP) and pkt[TCP].flags.R:
            if pkt.haslayer(IP):
                if pkt[IP].proto not in reset_count:
                    reset_count[pkt[IP].proto] = 1
                else:
                    reset_count[pkt[IP].proto] += 1                     

    # menampilkan protokol dan transmisi yang paling sering mengalami reset
    max_reset = max(reset_count, key=reset_count.get)
    print("Protokol yang paling sering mengalami reset:", max_reset)
    print("Jumlah reset:", reset_count[max_reset])
except:
    print("Terjadi error pada kode")

# menampilkan protokol dan jumlah reset
print("Protokol\tJumlah reset\tDeskripsi")
for proto, count in reset_count.items():
    print(proto, "\t\t", count, "\t\t", IP_PROTOS[proto])


