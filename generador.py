# Importamos las librerías necesarias
import socket  # Biblioteca nativa para interactuar directamente con la pila de protocolos TCP/IP del SO
import time    # Gestión de intervalos de tiempo y delays entre ráfagas de paquetes

def ejecutar_generador():
    """
    Función orquestadora que interactúa con el usuario mediante CLI para configurar 
    y ejecutar la inyección de tráfico sintético hacia la LAN.
    """
    print("="*50)
    print("      SDN TRAFFIC INJECTOR (TCP/UDP) - U. ROSARIO")
    print("="*50)
    
    # --- CAPTURA DE DATOS DE DIRECCIONAMIENTO Y PAYLOAD ---
    # IP del agente remoto que será evaluado. Si se deja en blanco, asume el localhost.
    ip = input("IP del agente destino (ej: 127.0.0.1): ") or "127.0.0.1"
    
    # Puerto de Capa 4 donde el agente está escuchando (debe coincidir con el puerto del cliente).
    puerto = int(input("Puerto del agente destino (ej: 5000): ") or 5000)
    
    # Selección de protocolo de transporte (TCP orientado a conexión o UDP sin conexión).
    proto = input("Protocolo a usar (TCP/UDP): ").upper() or "UDP"
    
    # Mensaje o cadena de texto cruda que viajará en la sección de datos (Payload) del segmento/datagrama.
    msg = input("Mensaje a transmitir: ") or "Mensaje seguro de auditoría"
    
    # Número de transmisiones repetitivas para simular una ráfaga de tráfico real.
    cantidad = int(input("Número de ráfagas: ") or 3)

    print(f"\n[*] Disparando ráfaga hacia {ip}:{puerto} [{proto}]...")
    
    # --- BUCLE DE INYECCIÓN DE DATOS (Plano de Datos Sintético) ---
    for i in range(cantidad):
        # Codificación del mensaje de texto a bytes de forma explícita en UTF-8 para su correcto viaje por la red
        payload = f"[Paquete {i+1}] {msg}".encode('utf-8')
        try:
            # --- RAMA UDP: TRANSMISIÓN SIN CONEXIÓN ---
            if proto == "UDP":
                # Inicializa un socket para Internet (AF_INET) de tipo Datagrama (SOCK_DGRAM)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                
                # Envía los bytes inmediatamente al destino. Al ser UDP, no valida si el host está activo
                s.sendto(payload, (ip, puerto))
                s.close()  # Libera el descriptor del socket inmediatamente
                
            # --- RAMA TCP: TRANSMISIÓN ORIENTADA A CONEXIÓN ---
            elif proto == "TCP":
                # Inicializa un socket para Internet (AF_INET) de tipo Flujo de Bytes (SOCK_STREAM)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
                # Configura un tiempo de espera de 2 segundos. Evita que el script se congele si la regla
                # en el agente es un "DROP" (el cual descarta el paquete y no responde con banderas RST o ACK)
                s.settimeout(2.0)
                
                # Inicia el proceso de saludo de tres vías (Three-way Handshake)
                s.connect((ip, puerto))
                
                # Transmite la totalidad del buffer de datos a través del canal establecido de forma segura
                s.sendall(payload)
                s.close()  # Cierra la conexión de forma ordenada enviando la bandera FIN
                
            print(f"[+] Transmisión {i+1}/{cantidad} completada de forma exitosa.")
            
        except socket.timeout:
            # Excepción específica para el bloqueo TCP: si el agente aplica un DROP silencioso, 
            # el socket de este script expirará, evidenciando físicamente el éxito de la mitigación.
            print(f"[-] Falla en ráfaga {i+1}: Tiempo de espera agotado (Timeout). ¡Posible mitigación por DROP!")
            
        except Exception as e:
            # Captura de cualquier otra anomalía física de la red (ej. Host inalcanzable, puerto cerrado, etc.)
            print(f"[-] Falla en ráfaga {i+1}: {e}")
            
        # Intervalo de suspensión de 1 segundo entre transmisiones para simular un flujo constante 
        # y permitir que la telemetría del dashboard se actualice de forma escalonada
        time.sleep(1.0)

if __name__ == "__main__":
    ejecutar_generador()