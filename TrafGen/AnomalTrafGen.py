from scapy.all import *
import random
from datetime import datetime, timedelta
import time
from tqdm import tqdm

# Вспомогательная функция для генерации случайного IP адреса из указанного диапазона
def generate_random_ip():
    return "192.168.10." + str(random.randint(2, 10))

# Создание ARP запроса
def create_arp_request(source_ip, target_ip):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        hwtype=1,
        ptype=0x0800,
        hwlen=6,
        plen=4,
        op=1,
        hwsrc=mac_addresses[source_ip],
        psrc=source_ip,
        hwdst="00:00:00:00:00:00",
        pdst=target_ip
    )
    return arp_request

# Создание ARP ответа
def create_arp_reply(request):
    arp_reply = Ether(dst=request[Ether].src) / ARP(
        hwtype=1,
        ptype=0x0800,
        hwlen=6,
        plen=4,
        op=2,
        hwsrc=mac_addresses[request[ARP].pdst],
        psrc=request[ARP].pdst,
        hwdst=request[ARP].hwsrc,
        pdst=request[ARP].psrc
    )
    return arp_reply

# Создание SMTP пакета
def create_smtp_packet(source_ip, target_ip):
    smtp_packet = Ether() / IP(src=source_ip, dst=target_ip) / TCP(dport=25) / ("HELO\r\n")
    smtp_packet /= Ether() / IP(src=source_ip, dst=target_ip) / TCP(dport=25) / ("MAIL FROM: sender@example.com\r\n")
    smtp_packet /= Ether() / IP(src=source_ip, dst=target_ip) / TCP(dport=25) / ("RCPT TO: recipient@example.com\r\n")
    smtp_packet /= Ether() / IP(src=source_ip, dst=target_ip) / TCP(dport=25) / ("DATA\r\n")
    smtp_packet /= Ether() / IP(src=source_ip, dst=target_ip) / TCP(dport=25) / ("Message body\r\n.\r\n")
    smtp_packet /= Ether() / IP(src=source_ip, dst=target_ip) / TCP(dport=25) / ("QUIT\r\n")
    return smtp_packet

# Создание TCP пакета
def create_tcp_packet(source_ip, target_ip, seq, ack, data_len):
    tcp_packet = Ether() / IP(src=source_ip, dst=target_ip) / TCP(
        sport=random.randint(1024, 65535),
        dport=random.randint(1024, 65535),
        seq=seq,
        ack=ack,
        flags="",
        window=random.randint(100, 1000),
        chksum=0,
        urgptr=0
    ) / ("X" * data_len)
    return tcp_packet

# Задаем MAC адреса для каждого IP адреса
mac_addresses = {
    "192.168.10.2": "00:11:22:33:44:AA",
    "192.168.10.3": "00:11:22:33:44:BB",
    "192.168.10.4": "00:11:22:33:44:CC",
    "192.168.10.5": "00:11:22:33:44:DD",
    "192.168.10.6": "00:11:22:33:44:EE",
    "192.168.10.7": "00:11:22:33:44:FF",
    "192.168.10.8": "00:11:22:33:44:11",
    "192.168.10.9": "00:11:22:33:44:22",
    "192.168.10.10": "00:11:22:33:44:33"
}

# Определяем время начала и окончания рабочего дня
start_time = datetime(year=2023, month=4, day=13, hour=10, minute=0, second=0)
end_time = datetime(year=2023, month=4, day=13, hour=18, minute=0, second=0)

# Список для хранения сгенерированных пакетов
generated_packets = []

# Генерация ARP пакетов
for _ in range(10):
    source_ip = generate_random_ip()
    target_ip = generate_random_ip()

    # Генерация ARP запроса и добавление в список
    arp_request = create_arp_request(source_ip, target_ip)
    generated_packets.append(arp_request)

    # Генерация ARP ответа и добавление в список
    arp_reply = create_arp_reply(arp_request)
    generated_packets.append(arp_reply)

print("Генерация ARP пакетов завершена")

# Генерация SMTP пакетов
for _ in range(40):
    source_ip = generate_random_ip()
    target_ip = generate_random_ip()

    # Генерация SMTP пакета и добавление в список
    smtp_packet = create_smtp_packet(source_ip, target_ip)
    generated_packets.append(smtp_packet)

print("Генерация SMTP завершена")

TCP_Packet = 30

for i in tqdm(range(TCP_Packet)):

    for _ in range(3, 21):
        source_ip = generate_random_ip()
        target_ip = generate_random_ip()

        seq = random.randint(1000, 5000)
        ack = 0
        data_len = random.randint(10, 100)

        # Установка соединения (SYN)
        tcp_syn_packet = create_tcp_packet(source_ip, target_ip, seq, ack, 0)
        tcp_syn_packet[TCP].flags = "S"
        generated_packets.append(tcp_syn_packet)

        # Передача данных и подтверждение
        for _ in range(_):
            # Отправка TCP пакета с данными
            tcp_packet = create_tcp_packet(source_ip, target_ip, seq, ack, data_len)
            generated_packets.append(tcp_packet)

            # Ожидание подтверждения доставки
            ack_packet = create_tcp_packet(target_ip, source_ip, ack, seq + data_len, 0)
            generated_packets.append(ack_packet)

            ack = ack_packet[TCP].seq + len(ack_packet[TCP].payload)

        # Разрыв соединения (FIN)
        tcp_fin_packet = create_tcp_packet(source_ip, target_ip, seq + data_len, ack, 0)
        tcp_fin_packet[TCP].flags = "F"
        generated_packets.append(tcp_fin_packet)

        # Подтверждение разрыва (ACK)
        tcp_ack_packet = create_tcp_packet(source_ip, target_ip, seq + data_len + 1, ack + 1, 0)
        generated_packets.append(tcp_ack_packet)
     
    # HTTP request
    if i == 4:
        source_ip = "192.168.10.5"  # IP адрес источника (отправителя)
        destination_ip = "216.58.209.238"  # IP адрес назначения (например, google.com)
        destination_port = 80  # Порт HTTP сервера 

        # Создание фальшивого HTTP GET запроса
        http_request = (
        b"GET / HTTP/1.1\r\n"
        b"Host: google.com\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36\r\n"
        b"Connection: keep-alive\r\n"
        b"\r\n"
        )

        packet =Ether() /  IP(src=source_ip, dst=destination_ip) / TCP(sport=RandShort(), dport=destination_port, flags="PA") / http_request
    
        HTTP = []  # Список для хранения пакетов
    
        for _ in range(2):  # Отправляем запроса с интервалом в 20 секунд
            HTTP.append(packet)  # Добавляем пакет в список
            time.sleep(20)  # Пауза в 20 секунд между запросами
        generated_packets.extend(HTTP)
        print("HTTP отправлен")

    if i == 10:
        source_ip = "192.168.10.5"  # IP адрес источника (отправителя)
        destination_ip = "216.58.209.238"  # IP адрес назначения (например, google.com)
        destination_port = 80  # Порт HTTP сервера 

        # Создание фальшивого HTTP GET запроса
        http_request = (
        b"GET / HTTP/1.1\r\n"
        b"Host: google.com\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36\r\n"
        b"Connection: keep-alive\r\n"
        b"\r\n"
        )

        packet =Ether() /  IP(src=source_ip, dst=destination_ip) / TCP(sport=RandShort(), dport=destination_port, flags="PA") / http_request
    
        HTTP = []  # Список для хранения пакетов
    
        for _ in range(2):  # Отправляем запроса с интервалом в 20 секунд
            HTTP.append(packet)  # Добавляем пакет в список
            time.sleep(20)  # Пауза в 20 секунд между запросами
        generated_packets.extend(HTTP)
        print("HTTP отправлен")
    
    if i == 14:
        targe_ip = "198.162.10.4"
        attack_duration = random.randint(90, 120)  # Длительность атаки
        request_rate = 10  # Средняя частота запросов: 10 запросов в секунду 
    
        end_time = time.time() + attack_duration
        ddos_pac = []

        while time.time() < end_time:
            # Генерация пакетов в цикле с установленной частотой
            for _ in range(request_rate):
                # Создание фальшивого TCP пакета с использованием случайного источника IP
                src_ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
                ip_pkt = IP(src=src_ip, dst=target_ip)
                tcp_pkt = TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
                packet = Ether() / ip_pkt / tcp_pkt
                ddos_pac.append(packet)
            time.sleep(1)  # Пауза в 1 секунду между пакетами
        generated_packets.extend(ddos_pac)
        print("атака завершена")
    
    if i == 19:
        source_ip = "192.168.10.5"  # IP адрес источника (отправителя)

        # Список целевых IP адресов для отправки пингов
        target_ips = [
            "192.168.10.2",
            "192.168.10.3",
            "192.168.10.4",
            "192.168.10.8",
            "192.168.10.6",
            "192.168.10.9"
        ]

        interval = 10  # Интервал между отправкой пакетов (в секундах)
        ICMP_packets = []  # Список для хранения отправленных пакетов
        count = 0
        for target_ip in target_ips:
            for _ in range(6):  # Отправляем 6 пингов к каждому целевому IP адресу
                packet = Ether() / IP(src=source_ip, dst=target_ip) / ICMP()
                ICMP_packets.append(packet)  # Добавляем пакет в список
                time.sleep(interval)  # Пауза между отправкой пакетов
            count +=1
            print("произошел пинг", count)
        generated_packets.extend(ICMP_packets)

    time.sleep(0.1)
     
    if i == 29:
        src_ip = "192.168.10.8"  # IP адрес источника (отправителя)
        dst_ip = "56.110.14.82"  # IP адрес назначения в глобальной сети
        
        # Создание большого пакета информации (10000 байт)
        payload = b"A" * 10000
        mine = []
        # Создание IP пакета с большим пакетом информации
        packet = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(dport=12345) / payload
        mine.append(packet)
        generated_packets.extend(mine)
        print("UDP отправлен")

# Запись сгенерированных пакетов в файл .pcap
wrpcap("9.pcap", generated_packets)

print("Генерация трафика завершена.")
