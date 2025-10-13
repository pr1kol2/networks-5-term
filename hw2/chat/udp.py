import errno
import selectors
import socket
import sys
import time

from .utils import print_message, send_line

def udp_chat(udp_socket, bind_address, is_server):
  if is_server:
    udp_socket.bind(bind_address)

  udp_socket.setblocking(False)
  selector = selectors.DefaultSelector()
  selector.register(udp_socket, selectors.EVENT_READ)
  selector.register(sys.stdin, selectors.EVENT_READ)

  peer = None if is_server else udp_socket.getpeername()
  last_seen = 0 if is_server else time.time()
  idle_timeout = 120

  local_address = udp_socket.getsockname()
  print(f"[UDP] bound on {local_address[0]}:{local_address[1]}; type here to send...")

  try:
    try:
      while True:
        events = selector.select(1.0)
        now = time.time()

        if is_server and peer and ((now - last_seen) > idle_timeout):
          print("[UDP] peer timeout -> released")
          peer = None

        for event, _ in events:
          if event.fileobj is udp_socket:
            try:
              if is_server:
                data, sender_address = udp_socket.recvfrom(65535)
              else:
                data = udp_socket.recv(65535)
                sender_address = peer
            except (BlockingIOError, InterruptedError):
              continue
            except OSError as error:
              if error.errno in (errno.ECONNREFUSED, errno.ENETUNREACH, errno.EHOSTUNREACH):
                print(f"[UDP] recv error ({error.errno}): {error} —> keep waiting")
                continue
              raise

            if is_server:
              if peer is None:
                peer = sender_address
                print(f"[UDP] peer set to {peer}")
              if sender_address != peer:
                continue

            last_seen = now
            line = data.rstrip(b"\r\n")
            print_message("[peer] ", line)
            if line == b"bye":
              print("[UDP] peer said bye -> released")
              peer = None

          else:
            line = sys.stdin.buffer.readline()
            if line == b"":
              print("[local] EOF -> exit")
              return
            if peer is None:
              print("[UDP] no peer yet -> waiting inbound...")
              continue
            try:
              if is_server:
                send_line(udp_socket, line.rstrip(b"\n"), udp_peer=peer)
              else:
                send_line(udp_socket, line.rstrip(b"\n"))
            except OSError as error:
              if error.errno in (errno.ECONNREFUSED, errno.ENETUNREACH, errno.EHOSTUNREACH):
                print(f"[UDP] send error ({error.errno}): {error}")
                peer = None
                continue
              raise
    except KeyboardInterrupt:
      print("\n[UDP] interrupted -> closing")
      return
  finally:
    try:
      selector.unregister(udp_socket); selector.unregister(sys.stdin)
    except Exception:
      pass
    udp_socket.close()

def udp_server(host, port):
  udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udp_chat(udp_socket, (host, port), True)

def udp_client(host, port):
  udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udp_socket.connect((host, port))
  try:
    udp_socket.send(b"hi\n")
  except OSError:
    pass
  udp_chat(udp_socket, udp_socket.getsockname(), False)
