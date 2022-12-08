# Import library Scapy
from scapy.all import *

# Baca file pcapng
pcapng = rdpcap("bahandata.pcapng")

# Buat dictionary untuk menyimpan IP dan panjang data yang dikirim oleh IP tersebut
ip_length = {}

# Loop melalui tiap packet dalam file
for packet in pcapng:
  # Cek apakah packet memiliki field IP
  if IP in packet:
    # Ambil alamat IP asal
    ip = packet[IP].src
    # Ambil panjang data dari packet IP
    length = packet[IP].len
    # Cek apakah IP sudah ada di dictionary
    if ip in ip_length:
      # Jika sudah, tambahkan panjang datanya
      ip_length[ip] += length
    else:
      # Jika belum, tambahkan ke dictionary dengan panjang data 1
      ip_length[ip] = length

# Urutkan dictionary berdasarkan panjang data IP
sorted_ip = sorted(ip_length, key=ip_length.get, reverse=True)

# Cetak top 5 IP
for i in range(5):
  print(sorted_ip[i])
