import selectors
import socket
import sys

from .utils import print_message, send_line, read_tcp_lines

def tcp_chat(connection, sender_address):
  print(f"[TCP] connected: {sender_address}")

  connection.setblocking(False)

  selector = selectors.DefaultSelector()
  selector.register(connection, selectors.EVENT_READ)
  selector.register(sys.stdin, selectors.EVENT_READ)

  received_buffer = b""

  try:
    try:
      while True:
        for event, _ in selector.select():
          if event.fileobj is connection:
            reveived_lines, received_buffer = read_tcp_lines(connection, received_buffer)
            if reveived_lines is None:
              print("[TCP] peer closed")
              return
            for line in reveived_lines:
              print_message("[peer] ", line)
          else:
            line = sys.stdin.buffer.readline()
            if line == b"":
              print("[TCP] local EOF -> closing")
              return
            try:
              send_line(connection, line.rstrip(b"\n"))
            except (BrokenPipeError, ConnectionResetError, OSError):
              print("[TCP] peer closed during write")
              return
    except KeyboardInterrupt:
      print("\n[TCP] interrupted -> closing")
      return
  finally:
    try:
      connection.shutdown(socket.SHUT_RDWR)
    except:
      pass
    connection.close()

def tcp_server(host, port):
  with socket.create_server((host, port), reuse_port=True) as server_socket:
    print(f"[TCP] server listening on {host}:{port}")
    while True:
      try:
        connection, client_address = server_socket.accept()
      except KeyboardInterrupt:
        print("[TCP] shutting down")
        return

      with connection:
        try:
          tcp_chat(connection, client_address)
        except (ConnectionResetError, BrokenPipeError, OSError) as error:
          print(f"[TCP] session aborted: {error}")
        except Exception as error:
          print(f"[TCP] session error: {error}")

      print("[TCP] session ended -> waiting next client...")

def tcp_client(host, port):
  with socket.create_connection((host, port)) as client_socket:
    tcp_chat(client_socket, (host, port))
