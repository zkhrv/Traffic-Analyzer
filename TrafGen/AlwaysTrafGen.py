from scapy.all import *
import random
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
    tcp_packet = Ether() / IP(src=source_ip, dst=target_ip) / TCP( # Формирование TCP пакета с использованием scapy
        sport=random.randint(1024, 65535), # Установка случайного значения порта источника
        dport=random.randint(1024, 65535), # Установка случайного значения порта назначения
        seq=seq, # Установка значения последовательности TCP
        ack=ack, # Установка значения подтверждения TCP
        flags="", # Установка флагов TCP (в данном случае пусто)
        window=random.randint(100, 1000), # Установка размера окна TCP
        chksum=0, # Установка контрольной суммы TCP (в данном случае 0, будет вычислена автоматически)
        urgptr=0 # Установка указателя срочности TCP
    ) / ("X" * data_len) # Добавление данных в пакет (символ "X" повторяется data_len раз)
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
for _ in range(1):
    source_ip = generate_random_ip()
    target_ip = generate_random_ip()

    # Генерация SMTP пакета и добавление в список
    smtp_packet = create_smtp_packet(source_ip, target_ip)
    generated_packets.append(smtp_packet)

print("Генерация SMTP завершена")

Packet = 41

for i in tqdm(range(Packet)):

    for _ in range(3, 21):
        # Вложенный цикл для отправки нескольких пакетов с данными для каждого TCP пакета
        # Генерация случайных IP адресов и установка случайных значений для последовательности, подтверждения и размера данных
        source_ip = generate_random_ip()
        target_ip = generate_random_ip()
        seq = random.randint(1000, 5000)
        ack = 0
        data_len = random.randint(10, 100)

        # Установка соединения (SYN)
        tcp_syn_packet = create_tcp_packet(source_ip, target_ip, seq, ack, 0)
        tcp_syn_packet[TCP].flags = "S"
        # Создание TCP пакета с флагом SYN (установка соединения)
        generated_packets.append(tcp_syn_packet)
        # Передача данных и подтверждение
        for _ in range(_):
            # Цикл для отправки нескольких пакетов с данными и их подтверждения
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
        # Создание TCP пакета с флагом FIN (разрыв соединения)
        generated_packets.append(tcp_fin_packet)

        # Подтверждение разрыва (ACK)
        tcp_ack_packet = create_tcp_packet(source_ip, target_ip, seq + data_len + 1, ack + 1, 0)
        # Создание TCP пакета с флагом ACK (подтверждение разрыва)
        generated_packets.append(tcp_ack_packet)


    time.sleep(0.1)

    if i ==4:
        for _ in range(10):
            source_ip = generate_random_ip()
            target_ip = generate_random_ip()

            # Генерация SMTP пакета и добавление в список
            smtp_packet = create_smtp_packet(source_ip, target_ip)
            generated_packets.append(smtp_packet)

    # остальной код
    
    elif i == 11:
        for _ in range(5):
            source_ip = generate_random_ip()
            target_ip = generate_random_ip()

            # Генерация SMTP пакета и добавление в список
            smtp_packet = create_smtp_packet(source_ip, target_ip)
            generated_packets.append(smtp_packet)
    elif i == 27:
        for _ in range(4):
            source_ip = generate_random_ip()
            target_ip = generate_random_ip()

            # Генерация SMTP пакета и добавление в список
            smtp_packet = create_smtp_packet(source_ip, target_ip)
            generated_packets.append(smtp_packet)

# Запись сгенерированных пакетов в файл .pcap
wrpcap("6.pcap", generated_packets)

print("Генерация трафика завершена.")
