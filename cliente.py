# Importamos las librerías de utilidades necesarias

import sys          # Permite interactuar con variables del sistema (captura de argumentos por consola)
import time         # Gestión de temporizadores y suspensiones de hilos (sleep)
import socket       # Núcleo de bajo nivel para la manipulación de Sockets de red de Berkeley (Capa 4)
import threading    # Hilos de ejecución paralela para evitar bloqueos en la escucha mutiprocolo
import requests     # Cliente HTTP para el canal de control (comunicación descendente hacia el servidor)

# --- CAPTURA DE PARÁMETROS DE ARRANQUE E INTERFAZ CLI ---
# Inicialización de variables globales para la identidad de red del host agente
NOMBRE = ""
PUERTO = 0

# Bucle de validación interactiva para asignar un identificador unívoco al nodo
while True: 
    NOMBRE = input("Ingresar un nombre para el nodo (e.g. NodoAlpha): ")
    if NOMBRE.strip() != "":
        break

# Bucle de validación para el puerto local de escucha del switch/firewall virtual
while True: 
    try:
        PUERTO = int(input("Ingresar puerto de escucha local (e.g. 5000): "))
        if 65536 > PUERTO > 0:  # Restricción técnica del rango de puertos TCP/UDP
            break
        print("[-] Puerto inválido. Debe estar entre 1 y 65535.")
    except ValueError:
        print("[-] Por favor ingrese un número entero.")

# Estructura de configuración local del agente
CONFIG = {
    "NOMBRE_NODO": NOMBRE,
    "CONTROLADOR_URL": "http://127.0.0.1:8000", # Cambiar por la IP privada LAN del servidor controlador
    "PUERTO_ESCUCHA": PUERTO,
    "SYNC_INTERVAL": 4  # Frecuencia de refresco (en segundos) para la Flow Table (Pull-based architecture)
}

class AgenteSDN:
    """
    Abstracción del Plano de Datos. Modela el comportamiento de un conmutador programable
    con capacidades de filtrado de paquetes de estado simple (Stateless Firewall).
    """
    def __init__(self):
        self.reglas = []       # Flow Table local (Caché sincronizada desde el controlador)
        self.running = True    # Bandera de control para los hilos de ejecución

    def registrar_agente(self):
        """
        Fase de Descubrimiento de Topología: Envía una notificación HTTP POST al 
        controlador para dar de alta al nodo en el inventario central.
        """
        print(f"[*] Sincronizando '{CONFIG['NOMBRE_NODO']}' con el plano de control...")
        try:
            r = requests.post(
                f"{CONFIG['CONTROLADOR_URL']}/api/nodes/register", 
                json={"nombre": CONFIG['NOMBRE_NODO']}, 
                timeout=4
            )
            if r.status_code == 200:
                print("[+] Registro exitoso ante el Controlador.")
        except Exception as e:
            print(f"[-] Error de conexión inicial con el controlador: {e}")

    def hilo_pull_reglas(self):
        """
        Canal de Control Descendente: Descarga de forma iterativa y periódica las 
        políticas vigentes en la Flow Table centralizada.
        """
        while self.running:
            try:
                r = requests.get(f"{CONFIG['CONTROLADOR_URL']}/api/rules", timeout=3)
                if r.status_code == 200:
                    self.reglas = r.json()  # Actualiza la Flow Table local en caliente
                    print(f"[SDN] Sincronizadas {len(self.reglas)} reglas de flujo desde el controlador.")
            except Exception as e:
                print(f"[-] Canal de control inaccesible (reintentando...): {e}")
            time.sleep(CONFIG["SYNC_INTERVAL"])

    def motor_firewall(self, raw_data, addr, proto):
        """
        Motor de Inspección de Flujos (Core SDN): Evalúa cada paquete interceptado en la 
        interfaz contra la Flow Table local utilizando algoritmos de coincidencia de primer orden.
        """
        ip_src = addr[0]  # Extrae la dirección IP de origen del host remoto atacante/generador
        msg = raw_data.decode('utf-8', errors='ignore') # Decodifica el payload (Deep Packet Inspection conceptual)
        print(f"\n[EVALUANDO FLUJO] {proto} desde {ip_src}:{addr[1]} hacia Puerto Local {CONFIG['PUERTO_ESCUCHA']}")

        regla_ganadora = None
        
        # EVALUACIÓN DE REGLAS POR PRIORIDAD:
        # Al venir pre-ordenadas de Alta a Baja por el servidor, la primera coincidencia estructural toma el control.
        for regla in self.reglas:
            # 1. Coincidencia de Capa 4 (Protocolo de Transporte)
            match_proto = (regla["ipProto"] == "*" or regla["ipProto"].upper() == proto.upper())
            # 2. Coincidencia de Capa 4 (Puerto de Destino del servicio local)
            match_port = (regla["tpDst"] == "*" or int(regla["tpDst"]) == CONFIG['PUERTO_ESCUCHA'])
            # 3. Coincidencia de Capa 3 (Dirección IP de Origen - Agregado para cumplir la guía)
            match_ip_src = (regla["ipSrc"] == "*" or regla["ipSrc"] == ip_src)
            
            # Si el paquete cumple con todos los campos de coincidencia (Match Fields) de OpenFlow
            if match_proto and match_port and match_ip_src:
                regla_ganadora = regla
                break

        # Valores restrictivos por defecto en caso de no coincidir con ninguna política explícita
        accion_final = "DROP" 
        note_regla = "Política restrictiva por defecto de la arquitectura"
        rule_id = None

        if regla_ganadora:
            rule_id = regla_ganadora["id"]
            note_regla = regla_ganadora["note"]
            if regla_ganadora["action"] == "forward":
                accion_final = "ALLOW"
            elif regla_ganadora["action"] == "drop":
                accion_final = "DROP"
            elif regla_ganadora["action"] == "controller":
                accion_final = "ALERT"

        # REPORTAR HIT DE REGLA: Incrementa de forma discreta el contador de telemetría de la política afectada
        if rule_id:
            try: requests.post(f"{CONFIG['CONTROLADOR_URL']}/api/rules/match/{rule_id}", timeout=1)
            except: pass

        # EJECUCIÓN DE LA ACCIÓN A NIVEL DE DATOS:
        if accion_final in ["ALLOW", "ALERT"]:
            print(f"[+] [{accion_final}] Flujo PROCESADO exitosamente por regla: '{note_regla}'")
            print(f"    Payload útil del paquete: '{msg}'")
        else:
            print(f"[-] [DROP] Tráfico MITIGADO (Purgado silenciosamente) por regla: '{note_regla}'")

        # ENVIAR EVENTO AL ANALIZADOR DE TRÁFICO CENTRALIZADO (Telemetría global para el Dashboard)
        # Convertimos ALERT a ALLOW a nivel de flujo para no romper los contadores del frontend, manteniendo el log intacto.
        self.reportar_al_analizador(proto, ip_src, "ALLOW" if accion_final == "ALERT" else accion_final, msg)

    def reportar_al_analizador(self, proto, ip_src, accion, msg):
        """
        Canal de Control Ascendente: Reporta de forma asíncrona un informe detallado
        del paquete al analizador de telemetría del controlador.
        """
        try:
            payload = {
                "nodo": CONFIG["NOMBRE_NODO"],
                "protocolo": proto,
                "puerto": CONFIG["PUERTO_ESCUCHA"],
                "origen": ip_src,
                "accion_tomada": accion,
                "payload": msg
            }
            requests.post(f"{CONFIG['CONTROLADOR_URL']}/api/analyzer/report", json=payload, timeout=2)
        except Exception as e:
            # Falla silenciosa en consola para evitar que problemas de red HTTP bloqueen el plano de datos
            pass

    # --- ENTRADAS MULTI-HILO (Interfaces de Escucha del Plano de Datos) ---

    def socket_udp_listener(self):
        """Abre un canal de escucha de datagramas UDP sin conexión en el puerto asignado."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", CONFIG["PUERTO_ESCUCHA"])) # Escucha en todas las interfaces físicas
        while self.running:
            try:
                data, addr = s.recvfrom(4096)  # Intercepta el buffer de datos entrante
                # Delega la evaluación de forma asíncrona a un hilo nuevo para no encolar el socket
                threading.Thread(target=self.motor_firewall, args=(data, addr, "UDP"), daemon=True).start()
            except: pass

    def socket_tcp_listener(self):
        """Abre un socket de escucha orientado a conexión TCP en modo pasivo."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Permite la reutilización inmediata del puerto local evitando bloqueos de TIME_WAIT del sistema operativo
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", CONFIG["PUERTO_ESCUCHA"]))
        s.listen(5)  # Define una cola de hasta 5 conexiones concurrentes pendientes
        while self.running:
            try:
                conn, addr = s.accept() # Captura el saludo de tres vías (Three-way handshake)
                data = conn.recv(4096)
                if data:
                    # Deriva la carga útil del segmento TCP al motor de políticas en un hilo independiente
                    threading.Thread(target=self.motor_firewall, args=(data, addr, "TCP"), daemon=True).start()
                conn.close() # Cierra el socket de la sesión para liberar recursos
            except: pass

    def arrancar(self):
        """Orquestador Principal: Inicializa de manera concurrente todos los servicios del nodo."""
        self.registrar_agente()
        
        # Despliegue de los hilos demonio (Daemon Threads) de fondo
        threading.Thread(target=self.hilo_pull_reglas, daemon=True).start()
        threading.Thread(target=self.socket_udp_listener, daemon=True).start()
        threading.Thread(target=self.socket_tcp_listener, daemon=True).start()
        
        # Mantiene el hilo principal vivo respondiendo a interrupciones del teclado
        try:
            while self.running: 
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[-] Apagando interfaces y saliendo del Agente SDN...")
            self.running = False

# --- PUNTO DE ENTRADA AL MÓDULO POR CONSOLA (Desacoplamiento de Configuración) ---
if __name__ == "__main__":
    # Permite sobrescribir la configuración interactiva si el script se arranca pasándole argumentos:
    # Ejemplo: 'python cliente.py NodoAlpha 5001'
    if len(sys.argv) > 1: 
        CONFIG["NOMBRE_NODO"] = sys.argv[1]
    if len(sys.argv) > 2: 
        CONFIG["PUERTO_ESCUCHA"] = int(sys.argv[2])
    
    # Instanciación e inicio del servicio
    agente = AgenteSDN()
    agente.arrancar()