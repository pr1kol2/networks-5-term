# HW 6

## Запуск

- alpine-2 (перехватчик):

  ```sh
  udhcpc -i eth0
  sysctl -w net.ipv4.ip_forward=1
  ip addr add 10.10.0.1/24 dev eth1
  ip link set eth1 up
  iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
  iptables -I FORWARD -j NFQUEUE --queue-num 1
  iptables -I INPUT -p udp --dport 53 -j NFQUEUE --queue-num 1
  python3 interceptor.py
  ```

- alpine-1 (клиент):

  ```sh
  ip addr add 10.10.0.2/24 dev eth0
  ip link set eth0 up
  ip route add default via 10.10.0.1
  echo "nameserver 8.8.8.8" > /etc/resolv.conf
  traceroute rerand0m.ru
  ```
