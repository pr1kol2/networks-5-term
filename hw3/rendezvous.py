import socket

kRooms = {}

def parse_register(payload: str):
  parts = payload.strip().split()
  if len(parts) < 3 or parts[0] != "REGISTER":
    return None
  try:
    room_id = parts[1].split("=", 1)[1]
    ip_port = parts[2].split("=", 1)[1]
    ip_str, port_str = ip_port.split(":")
    return room_id, (ip_str, int(port_str))
  except Exception:
    return None

def main():
  host = "0.0.0.0"
  port = 40000

  udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udp_socket.bind((host, port))
  print(f"[rv] listening on {host}:{port}")

  while True:
    data, sender_address = udp_socket.recvfrom(2048)
    text = data.decode("utf-8", "ignore")

    p = parse_register(text)
    if not p:
      udp_socket.sendto(b"ERR", sender_address)
      continue

    room_id, private_addr = p
    public_addr = sender_address

    lst = kRooms.setdefault(room_id, [])
    if not any(pa == public_addr for pa, _ in lst):
      lst.append((public_addr, private_addr))

    print(f"[rv] room={room_id} now {len(lst)} peer(s)")

    if len(lst) >= 2:
      (pub1, priv1), (pub2, priv2) = lst[0], lst[1]
      msg1 = f"PEER {pub2[0]} {pub2[1]} {priv2[0]} {priv2[1]}".encode()
      msg2 = f"PEER {pub1[0]} {pub1[1]} {priv1[0]} {priv1[1]}".encode()
      udp_socket.sendto(msg1, pub1)
      udp_socket.sendto(msg2, pub2)

if __name__ == "__main__":
  main()
