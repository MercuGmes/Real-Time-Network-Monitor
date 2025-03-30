import scapy.all as scapy
import tkinter as tk
from tkinter import ttk
import threading
import matplotlib.pyplot as plt # type: ignore
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg # type: ignore
import time
import socket

# Lista para almacenar el tamaño de paquetes capturados
packet_sizes = []
time_stamps = []
start_time = time.time()

def get_host_info(ip):
    """ Intenta obtener el nombre del host a partir de la IP """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Desconocido"

def is_potentially_malicious(ip):
    """ Simulación de detección de IPs sospechosas """
    malicious_ips = ["192.168.1.100", "203.0.113.5", "198.51.100.42"]  # Lista de ejemplo
    return ip in malicious_ips

def capture_packets():
    """ Captura paquetes en tiempo real y los muestra en la GUI """
    def process_packet(packet):
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            proto = packet[scapy.IP].proto
            size = len(packet)

            # Obtener información del host
            src_host = get_host_info(src_ip)
            dst_host = get_host_info(dst_ip)

            # Detectar posibles amenazas
            threat = "Sí" if is_potentially_malicious(src_ip) else "No"

            # Guardar datos para el gráfico
            elapsed_time = time.time() - start_time
            time_stamps.append(elapsed_time)
            packet_sizes.append(size)

            # Actualizar tabla en la GUI
            tree.insert("", 0, values=(src_ip, src_host, dst_ip, dst_host, proto, size, threat))

    scapy.sniff(prn=process_packet, store=False)

def update_graph():
    """ Actualiza el gráfico en tiempo real """
    ax.clear()
    ax.plot(time_stamps, packet_sizes, label="Tamaño de Paquetes")
    ax.set_xlabel("Tiempo (s)")
    ax.set_ylabel("Tamaño (bytes)")
    ax.legend()
    canvas.draw()
    root.after(1000, update_graph)  # Actualiza cada 1 segundo

# Configurar la GUI
root = tk.Tk()
root.title("Real-Time Network Monitor")
root.geometry("900x500")

# Tabla para mostrar paquetes
columns = ("IP Origen", "Host Origen", "IP Destino", "Host Destino", "Protocolo", "Tamaño (bytes)", "Posible Amenaza")
tree = ttk.Treeview(root, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=120)
tree.pack(pady=10, fill=tk.BOTH, expand=True)

# Gráfico en tiempo real
fig, ax = plt.subplots()
canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack()

# Iniciar captura de paquetes en un hilo separado
threading.Thread(target=capture_packets, daemon=True).start()
update_graph()

root.mainloop()
