# Copyright 2022 I Wayan Widi Pradnyana


# %%
from scapy.all import *
import scapy.layers.inet as inet
import scapy.layers.dns as dns
import scapy.layers.l2 as l2
import scapy.layers.http as http


import scapy.layers.l2tp as l2tp

import scapy.utils as utils
import scapy.sendrecv as sendrecv
import scapy.packet as packet
import scapy.plist as plist
import scapy.interfaces as interfaces

# # %%

# a = inet.Ether()
# b = inet.IP()
# c = inet.TCP()

# a.show()
# b.show()
# c.show()

# # %%
# b.dst = "1.1.1.1"
# c.dport = 80
# b.show()
# c.show()
# # %%
# i = inet.IP(dst='127.0.0.1')/inet.ICMP()/"HelloWorld"

# # %%
# i

# # %%
# packet.ls(inet.ICMP)
# # %%
# sendrecv.sendp(i)

# # %%
# i.fieldtype
# i.fields_desc
# i[inet.IP].src = "192.168.43.12"
# i[inet.IP].dst = "192.168.43.1"
# i.fields

# # %%
# sendrecv.sendp(i)
# # %%
# x = sendrecv.sr1(i)

# # %%
# x

# # %%
# p = sendrecv.sr1(inet.IP(dst="8.8.8.8")/inet.UDP()/dns.DNS(rd=1,qd=dns.DNSQR(qname="www.citrix.com")))
# p

# # %%
# p=sendrecv.sr(inet.IP(dst="103.147.92.57")/inet.TCP(dport=[23,80,53,443]))
# p
# # %%
# pt = inet.traceroute (["www.google.com"], maxttl=20)

# # %%
# # Reading
# pkts = utils.rdpcap('Files/evidence02.pcap')
# print(type(pkts))
# pkts
# # %%
# pkts.summary()
# # %%
# pkts.nsummary()
# # %%
# pkts[48]


# # %%
# # Pull out DNS packets

# x = []
# for p in pkts:
#     if p.haslayer(inet.UDP) and p.haslayer(dns.DNS):
#         print(type(p))
#         x.append(p)
# print(type(x))
# x
# # %%
# # Writing
# utils.wrpcap('Files/test.pcap', x)
# utils.wireshark(x)
# # %%
# utils.wrpcap('Files/replay1.pcap',x[0])
# utils.wireshark(x[0])
# # %%
# # Replaying

# pkts = utils.rdpcap('pcap/replay1.pcap')
# # %%
# del pkts[0][l2.Ether].dst
# del pkts[0][l2.Ether].src
# pkts[0][inet.IP].src = '10.1.99.28'
# pkts[0][inet.IP].dst = '8.8.8.8'
# del pkts[0][inet.IP].chksum
# del pkts[0][inet.UDP].chksum

# # %%
# xreplay = sendrecv.srp1(pkts[0])
# xreplay.summary()

# sendrecv.srploop(pkts[0])
# utils.wrpcap("Files/replay2.pcap", pkts[0])

# # %%
# # Packet Sniffer
# interfaces.show_interfaces()
# # %%

# iface = "wlp2s0"
# pkts = sendrecv.sniff(iface=iface, prn=lambda x: x.summary())
# # %%
# filter = "tcp port 80"
# pkts = sendrecv.sniff(iface=iface, filter=filter, prn=lambda x: x.summary())
# utils.wrpcap("Files/hasilcoba.pcap",pkts)

# # %%
# sendrecv.sniff(offline="Files/hasilcoba.pcap")

# # %%
# packet.ls(http.HTTP)

# %%

def analisis_bahan_data(pkts : PacketList):
    get_requests = []
    http_get = 'GET /'
    for p in pkts:
        # p.show()
        # print("Layers size ",len(p.layers()))
        for layer in p.layers():
            print("Layer :",type(layer))
        # if p.haslayer(inet.TCP) and p.haslayer(packet.Raw):
        if p.haslayer(inet.TCP) and p.haslayer(http.HTTP):
            print(" check ",p.haslayer(inet.TCP),p.haslayer(http.HTTP))
            # rawbyte = p.getlayer(packet.Raw).load



# %%
pcapemail = "bahandata.pcapng"

pkts : PacketList =  utils.rdpcap(pcapemail)
print(type(pkts))

# %%
# analisis_bahan_data(pkts)

# %%
import pandas as pd
import scapy.layers.l2 as l2
import plotly
import plotly.io as pio
from datetime import datetime
import panel as pn
from scapy.utils import EDecimal
import socket

pn.extension()
pio.renderers.default = "notebook"
pktBytes=[]
pktTimes=[]
pktSources=[]
pktDest=[]
pktProtocols=[]
pktFlags=[]
df1 = pd.DataFrame
encoding = 'utf-8'
pkt : Packet
for pkt in pkts:
    # print("layers",pkt.layers)
    if (pkt.haslayer(l2.Ether)):
        try:
            if(pkt.haslayer(inet.IP)):
                inetpkt : inet.IP = pkt[inet.IP]
                pktBytes.append(inetpkt.len)
                if(pkt.haslayer(inet.TCP)):
                    tcpkt : inet.TCP = pkt[inet.TCP]
                    try:
                        proto = socket.getservbyport(tcpkt.sport)
                        pktProtocols.append(proto)
                    except Exception as e:
                        pktProtocols.append("zz-unknown")
                    flag : FlagValue = tcpkt.flags
                    pktFlags.append(flag.value)
            ethpkt : l2.Ether = pkt.getlayer(l2.Ether)
            pktSources.append(ethpkt.src)
            pktDest.append(ethpkt.dst)
            pktTime=datetime.fromtimestamp(float(pkt.time))
            pktTimes.append(pktTime.strftime("%Y-%m-%d %H:%M:%S.%f"))
        except Exception as e:
            print(e)
            pass
print("pktBytes",len(pktBytes))
print("pktTimes",len(pktTimes))
print("pktSources",len(pktSources))
print("pktDest",len(pktDest))
print("pktProtocols",len(pktProtocols))
print("pktFlags",len(pktFlags))
bytes = pd.Series(pktBytes).astype(int)
sources = pd.Series(pktSources).astype(str)
dest = pd.Series(pktDest).astype(str)
protocols = pd.Series(pktProtocols).astype(str)
flags = pd.Series(pktFlags).astype(str)
times = pd.to_datetime(pd.Series(pktTimes).astype(str),  errors='coerce')
df : pd.DataFrame = pd.DataFrame({"Bytes": bytes, "Sources":sources,"Dest":dest,"Protocols":protocols,"Flags":flags})
df = df.set_index('Sources')
# print(type(df))
df.describe()
dfprotocols = df.groupby(["Protocols","Flags"]).count().sort_values("Protocols",ascending=True)
print(dfprotocols)
dfflags = df.groupby(["Flags"]).count().sort_values("Flags",ascending=False)
print(dfflags)
# %%

# %%

# %%
