import argparse

from task.traceroute import Traceroute

parser = argparse.ArgumentParser(prog="traceroute",
                                 usage='%(prog)s [OPTIONS] IP_ADDRESS {tcp|udp|icmp}',
                                 description="Выводит маршрут до указанного IP-адреса с использованием протоколов TCP, UDP или ICMP.", )
parser.add_argument("-t", "--timeout", type=int, default=2, help="Время ожидания ответа в секундах (по умолчанию: 2).")
parser.add_argument("-p", "--port", type=int, default=33434, help="Порт для TCP/UDP (по умолчанию: 33434).")
parser.add_argument("-n", "--max_hops", type=int, default=30,
                    help="Максимальное количество запросов (по умолчанию: 30).")
parser.add_argument("-v", "--verbose", action="store_true", help="Вывод номера автономной системы.")
parser.add_argument("ip_address", help="IP-адрес назначения для трассировки маршрута.")
parser.add_argument("protocol", choices=["tcp", "udp", "icmp"], help="Протокол для использования (tcp, udp или icmp).")
args = parser.parse_args()
print(Traceroute.trace(args.ip_address, args.protocol, args.timeout, args.max_hops, args.port, args.verbose))
