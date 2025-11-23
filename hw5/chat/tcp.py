import selectors
import socket
import sys
import os
import ssl

from .utils import print_message, send_line, read_tcp_lines

def tcp_chat(connection, sender_address, is_tls):
  prefix = "[TCP/TLS]" if is_tls else "[TCP]"
  print(f"{prefix} connected: {sender_address}")

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
              print(f"{prefix} peer closed")
              return
            for line in reveived_lines:
              print_message("[peer] ", line)
          else:
            line = sys.stdin.buffer.readline()
            if line == b"":
              print(f"{prefix} local EOF -> closing")
              return
            try:
              send_line(connection, line.rstrip(b"\n"))
            except (BrokenPipeError, ConnectionResetError, OSError):
              print(f"{prefix} peer closed during write")
              return
    except KeyboardInterrupt:
      print(f"\n{prefix} interrupted -> closing")
      return
  finally:
    try:
      connection.shutdown(socket.SHUT_RDWR)
    except:
      pass
    connection.close()

def create_tls_context(is_server, cert_path=None, key_path=None):
  context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if is_server else ssl.PROTOCOL_TLS_CLIENT)
  if is_server:
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
  else:
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
  keylog_file = os.getenv("SSLKEYLOGFILE")
  if keylog_file:
    context.keylog_filename = keylog_file
  return context

def tcp_server(host, port, tls_enabled=False, cert_path=None, key_path=None):
  tls_context = None
  if tls_enabled:
    if not cert_path or not key_path:
      print("[TCP] tls enabled but cert/key not provided")
      return
    tls_context = create_tls_context(True, cert_path, key_path)

  with socket.create_server((host, port), reuse_port=True) as server_socket:
    print(f"[TCP{'/TLS' if tls_enabled else ''}] server listening on {host}:{port}")
    while True:
      try:
        connection, client_address = server_socket.accept()
      except KeyboardInterrupt:
        print("[TCP] shutting down")
        return

      if tls_enabled:
        try:
          connection = tls_context.wrap_socket(connection, server_side=True)
        except ssl.SSLError as error:
          print(f"[TCP] tls handshake failed: {error}")
          connection.close()
          continue

      with connection:
        try:
          tcp_chat(connection, client_address, tls_enabled)
        except (ConnectionResetError, BrokenPipeError, OSError) as error:
          print(f"[TCP] session aborted: {error}")
        except Exception as error:
          print(f"[TCP] session error: {error}")

      print("[TCP] session ended -> waiting next client...")

def tcp_client(host, port, tls_enabled=False, cert_path=None, key_path=None):
  with socket.create_connection((host, port)) as raw_socket:
    if tls_enabled:
      tls_context = create_tls_context(False)
      try:
        client_socket = tls_context.wrap_socket(raw_socket, server_hostname=host)
      except ssl.SSLError as error:
        print(f"[TCP] tls handshake failed: {error}")
        return
    else:
      client_socket = raw_socket
    with client_socket:
      tcp_chat(client_socket, (host, port), tls_enabled)
