import argparse
import fcntl
import os
import select
import socket
import struct
import sys
import time

def send_line(any_socket, data: bytes, udp_peer=None):
  if not data.endswith(b"\n"):
    data += b"\n"
  if udp_peer is None:
    any_socket.sendall(data)
  else:
    any_socket.sendto(data, udp_peer)

def print_message(prefix, data: bytes):
  try:
    text = data.decode("utf-8", errors="replace")
  except Exception:
    text = repr(data)
  print(f"{prefix}{text}")

def get_interface_ip(interface_name: str) -> str:
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  return socket.inet_ntoa(fcntl.ioctl(
      s.fileno(), 0x8915,  # SIOCGIFADDR
      struct.pack('256s', interface_name.encode()[:15])
  )[20:24])

def register_with_rendezvous(udp_socket, rendezvous_address, room_id, private_ip, local_port):
  message = f"REGISTER room={room_id} private={private_ip}:{local_port}".encode()
  deadline = time.time() + 15.0
  udp_socket.settimeout(1.0)

  while time.time() < deadline:
    udp_socket.sendto(message, rendezvous_address)
    try:
      data, _ = udp_socket.recvfrom(1024)
    except socket.timeout:
      continue
    text = data.decode("utf-8", "ignore")
    if text.startswith("PEER"):
      _, pub_ip, pub_port, priv_ip, priv_port = text.split()
      peer_public = (pub_ip, int(pub_port))
      peer_private = (priv_ip, int(priv_port))
      return peer_public, peer_private
  raise RuntimeError("rendezvous: no PEER within timeout")

def same_lan_hint(ip_a: str, ip_b: str) -> bool:
  return ip_a.split(".")[:2] == ip_b.split(".")[:2]

def punch_hole(udp_socket, targets, established_flag, active_peer_holder, timeout_sec=15.0):
  udp_socket.setblocking(False)
  deadline = time.time() + timeout_sec

  while time.time() < deadline and not established_flag[0]:
    for target in targets:
      try:
        udp_socket.sendto(b"ping", target)
      except OSError:
        pass

    r, _, _ = select.select([udp_socket], [], [], 0.2)
    if r:
      data, sender_address = udp_socket.recvfrom(65535)
      active_peer_holder["peer"] = sender_address
      established_flag[0] = True
      print(f"[p2p] established with {sender_address}")
      return

def udp_chat_direct(udp_socket, peer):
  udp_socket.setblocking(False)
  print(f"[chat] Peer={peer}; type here to send...")

  while True:
    r, _, _ = select.select([udp_socket, sys.stdin], [], [])
    if udp_socket in r:
      try:
        data, _ = udp_socket.recvfrom(65535)
      except BlockingIOError:
        pass
      else:
        line = data.rstrip(b"\r\n")
        print_message("[peer] ", line)

    if sys.stdin in r:
      line = sys.stdin.buffer.readline()
      if line == b"":  # Ctrl-D
        print("[local] EOF -> exit")
        return
      send_line(udp_socket, line.rstrip(b"\n"), udp_peer=peer)

def main():
  args_parser = argparse.ArgumentParser()
  args_parser.add_argument("--rv-host", default="172.16.10.10")
  args_parser.add_argument("--rv-port", type=int, default=40000)
  args_parser.add_argument("--room", required=True)
  args_parser.add_argument("--ifname", default="eth0")
  args_parser.add_argument("--local-port", type=int, default=50000)
  args = args_parser.parse_args()

  rendezvous_address = (args.rv_host, args.rv_port)

  udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udp_socket.bind(("0.0.0.0", args.local_port))
  local_address = udp_socket.getsockname()

  private_ip = get_interface_ip(args.ifname)
  print(f"[init] local={local_address}, priv_ip={private_ip}, rv={rendezvous_address}, room={args.room}")

  peer_public, peer_private = register_with_rendezvous(
      udp_socket, rendezvous_address, args.room, private_ip, args.local_port
  )
  print(f"[rv] peer_public={peer_public} peer_private={peer_private}")

  targets = []
  if same_lan_hint(private_ip, peer_private[0]):
    targets.append(peer_private)
  targets.append(peer_public)

  established_flag = [False]
  active_peer_holder = {"peer": None}

  deadline = time.time() + 15.0
  udp_socket.settimeout(0.5)

  while (time.time() < deadline) and (not established_flag[0]):
    for target in targets:
      try:
        udp_socket.sendto(b"ping", target)
      except OSError:
        pass

    try:
      data, sender_address = udp_socket.recvfrom(65535)
      active_peer_holder["peer"] = sender_address
      established_flag[0] = True
      print(f"[p2p] established (rx-first) with {sender_address}")
      break
    except socket.timeout:
      continue

  if not established_flag[0]:
    print("[err] could not establish direct UDP in time")
    return

  udp_chat_direct(udp_socket, active_peer_holder["peer"])

if __name__ == "__main__":
  main()
