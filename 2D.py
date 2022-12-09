# Temukan 3 pola lain yang bisa Anda temukan yang berpotensi menjadi gangguan kualitas jaringan komputer tersebut.
# Jawaban:
from scapy.all import *

# membuka file pcapng
pcapng = rdpcap("bahandata.pcapng")

# mengekstrak informasi yang diperlukan
polak_list = []
for pkt in pcapng:
    polak = pkt.summary()
    # filter untuk pola transmisi yang memiliki TCP Flag R (RST)
    if pkt.haslayer(TCP) and pkt[TCP].flags == 0x4 and polak not in polak_list:
        polak_list.append(polak)

# menampilkan 3 pola yang berbeda pada Flag R (RST)
print("3 pola yang berbeda yang terdapat Flag R (RST):")
for polak in polak_list[:3]:
    print(polak)



