import argparse

from chat.tcp import tcp_server, tcp_client
from chat.udp import udp_server, udp_client

def main():
  args_parser = argparse.ArgumentParser()

  args_parser.add_argument("--mode", choices=["tcp", "udp"], required=True)
  args_parser.add_argument("--role", choices=["server", "client"], required=True)
  args_parser.add_argument("--host", default="127.0.0.1")
  args_parser.add_argument("--port", type=int, default=9000)
  args_parser.add_argument("--tls", action="store_true", help="Enable TLS for TCP mode")
  args_parser.add_argument("--cert", help="Path to TLS certificate (server side)")
  args_parser.add_argument("--key", help="Path to TLS private key (server side)")

  args = args_parser.parse_args()

  dispatch = {
    ("tcp","server"): tcp_server,
    ("tcp","client"): tcp_client,
    ("udp","server"): udp_server,
    ("udp","client"): udp_client,
  }

  if args.mode == "tcp":
    dispatch[(args.mode, args.role)](args.host, args.port, args.tls, args.cert, args.key)
  else:
    dispatch[(args.mode, args.role)](args.host, args.port)

if __name__ == "__main__":
  main()
