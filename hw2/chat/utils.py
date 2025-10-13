def send_line(any_socket, data: bytes, udp_peer=None):
  if not data.endswith(b"\n"):
    data += b"\n"
  if udp_peer is None:
    any_socket.sendall(data)
  else:
    any_socket.sendto(data, udp_peer)

def read_tcp_lines(tcp_socket, received_buffer: bytes):
    try:
      chunk = tcp_socket.recv(4096)
    except (BlockingIOError, InterruptedError):
      return [], received_buffer
    except (ConnectionResetError, BrokenPipeError, OSError):
      return None, received_buffer
    if chunk == b"":
      return None, received_buffer

    received_buffer += chunk
    lines = []
    while True:
      i = received_buffer.find(b"\n")
      if i < 0:
        break
      lines.append(received_buffer[:i])
      received_buffer = received_buffer[i + 1:]
    return lines, received_buffer

def print_message(prefix, data: bytes):
  try:
    text = data.decode("utf-8", errors="replace")
  except Exception:
    text = repr(data)
  print(f"{prefix}{text}")
