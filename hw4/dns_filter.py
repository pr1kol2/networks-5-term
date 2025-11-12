import argparse
import re
import ast
from netfilterqueue import NetfilterQueue
from scapy.all import IP, UDP, DNS, DNSQR
from scapy.layers.dns import dnsqtypes, DNSRROPT

def parse_rules_file(path):
  config = {}
  with open(path, 'r') as f:
    for raw in f:
      line = raw.strip()
      if not line or line.startswith('#'):
        continue
      if ':' not in line:
        continue
      key, value = line.split(':', 1)
      key = key.strip()
      value = value.strip()

      low = value.lower()
      if low == 'true':
        config[key] = True
        continue
      if low == 'false':
        config[key] = False
        continue

      if value.startswith(('[', '"', "'")):
        try:
          config[key] = ast.literal_eval(value)
          continue
        except Exception:
          pass

      try:
        config[key] = int(value)
        continue
      except ValueError:
        pass

      config[key] = value
  return config

class DnsRules:
  def __init__(self, data):
    pattern = data.get('blocked_name_regex', r'$^')
    if not isinstance(pattern, str):
      pattern = str(pattern)
    self.blocked_name_regex = re.compile(pattern)

    self.name_to_num = {
      str(name).upper(): int(num)
      for name, num in dnsqtypes.items()
      if isinstance(name, str) and isinstance(num, int)
    }
    self.num_to_name = {
      int(num): str(name).upper()
      for num, name in dnsqtypes.items()
      if isinstance(num, int) and isinstance(name, str)
    }

    raw_qtypes = data.get('drop_qtypes', [])
    if not isinstance(raw_qtypes, list):
      raw_qtypes = []

    self.drop_qtypes_names = set()
    self.drop_qtypes_nums = set()
    for item in raw_qtypes:
      if isinstance(item, int):
        self.drop_qtypes_nums.add(int(item))
      else:
        s = str(item).upper()
        self.drop_qtypes_names.add(s)
        if s in self.name_to_num:
          self.drop_qtypes_nums.add(self.name_to_num[s])

    self.drop_if_rd_zero = bool(data.get('drop_if_rd_zero', False))
    self.drop_if_edns_present = bool(data.get('drop_if_edns_present', False))

    try:
      self.max_qname_length = int(data.get('max_qname_length', 1 << 30))
    except Exception:
      self.max_qname_length = 1 << 30

  def qtype_name(self, qtype_num):
    qn = int(qtype_num)
    return self.num_to_name.get(qn, str(qn))

class DnsFilter:
  def __init__(self, rules: DnsRules):
    self.rules = rules

  def handle_packet(self, queued_packet):
    payload = queued_packet.get_payload()
    try:
      pkt = IP(payload)
    except Exception:
      queued_packet.accept()
      return

    if not pkt.haslayer(UDP) or (pkt[UDP].dport != 53 and pkt[UDP].sport != 53):
      queued_packet.accept()
      return

    if not pkt.haslayer(DNS):
      queued_packet.accept()
      return

    dns = pkt[DNS]
    if dns.qr != 0:
      queued_packet.accept()
      return

    if not pkt.haslayer(DNSQR):
      queued_packet.accept()
      return

    qname_bytes = pkt[DNSQR].qname or b""
    try:
      qname_text = qname_bytes.decode('utf-8', errors='ignore').rstrip('.')
    except Exception:
      qname_text = str(qname_bytes)

    qtype_num = int(pkt[DNSQR].qtype)
    qtype_name = self.rules.qtype_name(qtype_num)
    qtype_name_upper = qtype_name.upper()
    rd_flag = int(getattr(dns, 'rd', 0))
    edns_present = pkt.haslayer(DNSRROPT)

    reasons = []
    if self.rules.blocked_name_regex.search(qname_text):
      reasons.append(f'name={qname_text}')
    if (qtype_num in self.rules.drop_qtypes_nums) or (qtype_name_upper in self.rules.drop_qtypes_names):
      reasons.append(f'qtype={qtype_name_upper}')
    if self.rules.drop_if_rd_zero and rd_flag == 0:
      reasons.append('rd=0')
    if self.rules.drop_if_edns_present and edns_present:
      reasons.append('edns=1')
    if len(qname_text) > self.rules.max_qname_length:
      reasons.append(f'name_len>{self.rules.max_qname_length}')

    if reasons:
      print(f"[drop] {qname_text} {qtype_name_upper} rd={rd_flag} edns={int(edns_present)} reasons={','.join(reasons)}")
      queued_packet.drop()
    else:
      print(f"[accept] {qname_text} {qtype_name_upper} rd={rd_flag} edns={int(edns_present)}")
      queued_packet.accept()

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--queue', type=int, default=5)
  parser.add_argument('--rules', type=str, required=True)
  args = parser.parse_args()

  config = parse_rules_file(args.rules)
  rules = DnsRules(config)
  filt = DnsFilter(rules)

  nfqueue = NetfilterQueue()
  nfqueue.bind(args.queue, filt.handle_packet)
  print(f"[nfqueue] listening on queue {args.queue}")
  try:
    nfqueue.run()
  except KeyboardInterrupt:
    pass
  finally:
    nfqueue.unbind()

if __name__ == '__main__':
  main()
