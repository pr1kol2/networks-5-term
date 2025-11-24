from netfilterqueue import NetfilterQueue
from scapy.all import IP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, send

class Handler:
  def __init__(self, trigger_domain, base_port, hop_ips, hop_names):
    self.trigger_domain = trigger_domain
    self.base_port = base_port
    self.hop_ips = hop_ips
    self.hop_names = hop_names
    self.dest_ip = hop_ips[-1]

  def handle_packet(self, queued_packet):
    try:
      pkt = IP(queued_packet.get_payload())
    except Exception:
      queued_packet.accept()
      return

    if self.handle_dns(pkt, queued_packet):
      return
    if self.handle_icmp(pkt, queued_packet):
      return
    if self.handle_udp(pkt, queued_packet):
      return
    queued_packet.accept()

  def handle_dns(self, pkt, queued_packet):
    if not pkt.haslayer(UDP) or not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
      return False
    udp = pkt[UDP]
    if udp.dport != 53 and udp.sport != 53:
      return False
    dns = pkt[DNS]
    if dns.qr != 0:
      return False
    q = dns.qd
    qname = q.qname.decode(errors="ignore").rstrip(".")
    qtype = q.qtype

    if qtype == 1 and qname == self.trigger_domain:
      ans = DNSRR(rrname=q.qname, type="A", rclass="IN", rdata=self.dest_ip, ttl=60)
      resp = IP(src=pkt.dst, dst=pkt.src) / UDP(sport=udp.dport, dport=udp.sport) / DNS(id=dns.id, qr=1, aa=1, qd=q, an=ans)
      send(resp, verbose=False)
      queued_packet.drop()
      return True

    if qtype == 12 and qname.endswith(".in-addr.arpa"):
      ip_text = ".".join(reversed(qname.replace(".in-addr.arpa", "").split(".")))
      if ip_text in self.hop_names:
        name = self.hop_names[ip_text]
        ans = DNSRR(rrname=q.qname, type="PTR", rclass="IN", rdata=f"{name}.", ttl=60)
        resp = IP(src=pkt.dst, dst=pkt.src) / UDP(sport=udp.dport, dport=udp.sport) / DNS(id=dns.id, qr=1, aa=1, qd=q, an=ans)
        send(resp, verbose=False)
        queued_packet.drop()
        return True

    return False

  def handle_icmp(self, pkt, queued_packet):
    if not pkt.haslayer(ICMP):
      return False
    icmp = pkt[ICMP]
    if icmp.type != 8:
      return False
    if pkt.dst != self.dest_ip:
      return False
    ttl = pkt.ttl
    hop_idx = ttl - 1 if ttl > 0 else 0
    if hop_idx < len(self.hop_ips):
      src_ip = self.hop_ips[hop_idx]
      reply = IP(src=src_ip, dst=pkt.src) / ICMP(type=11, code=0) / Raw(bytes(pkt))
    else:
      reply = IP(src=self.dest_ip, dst=pkt.src) / ICMP(type=0, id=icmp.id, seq=icmp.seq) / icmp.payload
    send(reply, verbose=False)
    queued_packet.drop()
    return True

  def handle_udp(self, pkt, queued_packet):
    if not pkt.haslayer(UDP):
      return False
    udp = pkt[UDP]
    if udp.dport < self.base_port:
      return False
    if pkt.dst != self.dest_ip:
      return False
    ttl = pkt.ttl
    hop_idx = ttl - 1 if ttl > 0 else 0
    src_ip = self.hop_ips[hop_idx] if hop_idx < len(self.hop_ips) else self.dest_ip
    if hop_idx < len(self.hop_ips):
      icmp_layer = ICMP(type=11, code=0)
    else:
      icmp_layer = ICMP(type=3, code=3)
    payload = Raw(bytes(pkt)[:28])
    reply = IP(src=src_ip, dst=pkt.src) / icmp_layer / payload
    send(reply, verbose=False)
    queued_packet.drop()
    return True

def build_hops(song_lines, base_ip):
  hops = []
  names = {}
  for idx, line in enumerate(song_lines):
    ip = f"{base_ip}{idx + 1}"
    host = ".".join(line.lower().split())
    hops.append((host, ip))
    names[ip] = host
  hop_ips = [ip for _, ip in hops]
  return hop_ips, names

def main():
  queue_num = 1
  trigger_domain = "rerand0m.ru"
  base_ip_prefix = "10.0.0."
  udp_base_port = 33434
  song_lines = [
    "london bridge",
    "is falling down",
    "falling down",
    "falling down",
    "london bridge",
    "is falling down",
    "my fair lady",
  ]

  hop_ips, hop_names = build_hops(song_lines, base_ip_prefix)
  handler = Handler(trigger_domain, udp_base_port, hop_ips, hop_names)
  nfqueue = NetfilterQueue()
  nfqueue.bind(queue_num, handler.handle_packet)
  try:
    nfqueue.run()
  except KeyboardInterrupt:
    pass
  finally:
    nfqueue.unbind()

if __name__ == "__main__":
  main()
