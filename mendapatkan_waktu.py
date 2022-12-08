# Import library Scapy
from scapy.all import *

# Baca file pcapng
pcapng = rdpcap("bahandata.pcapng")

# Inisialisasi waktu tertinggi
max_time = 0

# Loop melalui tiap packet dalam file
for packet in pcapng:
  # Ambil waktu pengiriman packet
  time = packet.time
  # Cek apakah waktu pengiriman lebih besar dari waktu tertinggi sebelumnya
  if time > max_time:
    # Jika ya, update waktu tertinggi
    max_time = time

# Cetak waktu tertinggi
print(max_time)
