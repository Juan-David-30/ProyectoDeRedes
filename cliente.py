# Importamos las librerías de utilidades necesarias
import sys
import time
import socket
import threading
import requests

# --- CAPTURA DE PARÁMETROS DE ARRANQUE ---
NOMBRE = ""
PUERTO = 0

while True:
    NOMBRE = input("Ingresar un nombre para el nodo (e.g. NodoAlpha): ")
    if NOMBRE.strip():
        break

while True:
    try:
        PUERTO = int(input("Ingresar puerto de escucha local (e.g. 5000): "))
        if 0 < PUERTO < 65536:
            break
        print("[-] Puerto inválido. Debe estar entre 1 y 65535.")
    except ValueError:
        print("[-] Por favor ingrese un número entero.")

CONFIG = {
    "NOMBRE_NODO": NOMBRE,
    "CONTROLADOR_URL": "http://127.0.0.1:8000",  # Cambiar por IP privada LAN del servidor
    "PUERTO_ESCUCHA": PUERTO,
    "SYNC_INTERVAL": 4,   # Segundos entre sincronizaciones de la Flow Table
}


class AgenteSDN:
    """
    Abstracción del Plano de Datos.
    Modela un conmutador programable con firewall stateless y motor de reglas SDN.
    Admite prioridades en el rango [0, 100] y campos de coincidencia extendidos
    (ipSrc, ipDst, ipProto, tpSrc, tpDst).
    """

    def __init__(self):
        self.reglas = []
        self.running = True

    # ------------------------------------------------------------------
    # REGISTRO Y SINCRONIZACIÓN CON EL CONTROLADOR
    # ------------------------------------------------------------------

    def registrar_agente(self):
        """Fase de descubrimiento: da de alta el nodo ante el controlador."""
        print(f"[*] Registrando '{CONFIG['NOMBRE_NODO']}' en el plano de control...")
        try:
            r = requests.post(
                f"{CONFIG['CONTROLADOR_URL']}/api/nodes/register",
                json={"nombre": CONFIG["NOMBRE_NODO"]},
                timeout=4,
            )
            if r.status_code == 200:
                print("[+] Registro exitoso ante el Controlador.")
        except Exception as e:
            print(f"[-] Error de conexión inicial: {e}")

    def hilo_pull_reglas(self):
        """
        Canal de control descendente (Pull-based).
        Descarga periódicamente las políticas vigentes desde el controlador.
        Las reglas ya vienen ordenadas de mayor a menor prioridad.
        """
        while self.running:
            try:
                r = requests.get(
                    f"{CONFIG['CONTROLADOR_URL']}/api/rules", timeout=3
                )
                if r.status_code == 200:
                    self.reglas = r.json()
                    print(
                        f"[SDN] Sincronizadas {len(self.reglas)} reglas "
                        f"(mayor prioridad: "
                        f"{self.reglas[0]['priority'] if self.reglas else 'N/A'})."
                    )
            except Exception as e:
                print(f"[-] Canal de control inaccesible: {e}")
            time.sleep(CONFIG["SYNC_INTERVAL"])

    # ------------------------------------------------------------------
    # MOTOR DE FIREWALL / COINCIDENCIA DE REGLAS
    # ------------------------------------------------------------------

    def motor_firewall(self, raw_data, addr, proto):
        """
        Motor de inspección de flujos (core SDN).

        Evalúa cada paquete contra la Flow Table local usando coincidencia de
        primer orden sobre reglas pre-ordenadas de mayor a menor prioridad [0-100].

        Campos evaluados:
          - ipSrc  : IP de origen del paquete
          - ipDst  : IP de destino (la interfaz local del agente)
          - ipProto: Protocolo de transporte (TCP / UDP)
          - tpSrc  : Puerto de origen del emisor
          - tpDst  : Puerto de destino (el puerto de escucha del agente)
        """
        ip_src = addr[0]
        port_src = str(addr[1])
        ip_dst_local = self._get_local_ip()      # IP local del agente (destino del flujo)
        msg = raw_data.decode("utf-8", errors="ignore")

        print(
            f"\n[FLUJO] {proto} | {ip_src}:{port_src} → "
            f"{ip_dst_local}:{CONFIG['PUERTO_ESCUCHA']}"
        )

        regla_ganadora = None

        for regla in self.reglas:
            # 1. Coincidencia de protocolo (Capa 4)
            match_proto = (
                regla["ipProto"] == "*"
                or regla["ipProto"].upper() == proto.upper()
            )
            # 2. Coincidencia de IP de origen (Capa 3)
            match_ip_src = (
                regla["ipSrc"] == "*" or regla["ipSrc"] == ip_src
            )
            # 3. Coincidencia de IP de destino (Capa 3)
            match_ip_dst = (
                regla["ipDst"] == "*" or regla["ipDst"] == ip_dst_local
            )
            # 4. Coincidencia de puerto de origen (Capa 4)
            match_tp_src = (
                regla.get("tpSrc", "*") == "*"
                or regla.get("tpSrc", "*") == port_src
            )
            # 5. Coincidencia de puerto de destino (Capa 4)
            match_tp_dst = (
                regla["tpDst"] == "*"
                or int(regla["tpDst"]) == CONFIG["PUERTO_ESCUCHA"]
            )

            if match_proto and match_ip_src and match_ip_dst and match_tp_src and match_tp_dst:
                regla_ganadora = regla
                break   # Primera coincidencia gana (reglas ya ordenadas por prioridad desc.)

        # Política restrictiva por defecto (Default-Deny)
        accion_final = "DROP"
        note_regla = "Política por defecto (ninguna regla coincidió)"
        rule_id = None

        if regla_ganadora:
            rule_id = regla_ganadora["id"]
            note_regla = regla_ganadora["note"]
            accion_map = {
                "forward":    "ALLOW",
                "drop":       "DROP",
                "controller": "ALERT",
            }
            accion_final = accion_map.get(regla_ganadora["action"], "DROP")

        # Reportar hit de regla al controlador (telemetría por regla)
        if rule_id:
            try:
                requests.post(
                    f"{CONFIG['CONTROLADOR_URL']}/api/rules/match/{rule_id}",
                    timeout=1,
                )
            except:
                pass

        # Ejecutar acción
        if accion_final in ("ALLOW", "ALERT"):
            print(f"[+] [{accion_final}] Regla: '{note_regla}'")
            print(f"    Payload: '{msg[:80]}'")
        else:
            print(f"[-] [DROP] Regla: '{note_regla}' — paquete descartado silenciosamente.")

        # Reportar evento al analizador de tráfico (telemetría global)
        # ALERT se reporta como ALERT para que el servidor incremente alertas_criticas
        self.reportar_al_analizador(proto, ip_src, accion_final, msg)

    def _get_local_ip(self) -> str:
        """Obtiene la IP local principal del agente para la coincidencia de ipDst."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def reportar_al_analizador(self, proto, ip_src, accion, msg):
        """Canal de control ascendente: envía telemetría al controlador."""
        try:
            payload = {
                "nodo": CONFIG["NOMBRE_NODO"],
                "protocolo": proto,
                "puerto": CONFIG["PUERTO_ESCUCHA"],
                "origen": ip_src,
                "accion_tomada": accion,
                "payload": msg[:200],
            }
            requests.post(
                f"{CONFIG['CONTROLADOR_URL']}/api/analyzer/report",
                json=payload,
                timeout=2,
            )
        except:
            pass

    # ------------------------------------------------------------------
    # INTERFACES DE ESCUCHA (PLANO DE DATOS)
    # ------------------------------------------------------------------

    def socket_udp_listener(self):
        """Canal UDP sin conexión."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", CONFIG["PUERTO_ESCUCHA"]))
        print(f"[UDP] Escuchando en 0.0.0.0:{CONFIG['PUERTO_ESCUCHA']}")
        while self.running:
            try:
                data, addr = s.recvfrom(4096)
                threading.Thread(
                    target=self.motor_firewall,
                    args=(data, addr, "UDP"),
                    daemon=True,
                ).start()
            except:
                pass

    def socket_tcp_listener(self):
        """Canal TCP orientado a conexión."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", CONFIG["PUERTO_ESCUCHA"]))
        s.listen(5)
        print(f"[TCP] Escuchando en 0.0.0.0:{CONFIG['PUERTO_ESCUCHA']}")
        while self.running:
            try:
                conn, addr = s.accept()
                data = conn.recv(4096)
                if data:
                    threading.Thread(
                        target=self.motor_firewall,
                        args=(data, addr, "TCP"),
                        daemon=True,
                    ).start()
                conn.close()
            except:
                pass

    # ------------------------------------------------------------------
    # ORQUESTADOR PRINCIPAL
    # ------------------------------------------------------------------

    def arrancar(self):
        self.registrar_agente()
        threading.Thread(target=self.hilo_pull_reglas, daemon=True).start()
        threading.Thread(target=self.socket_udp_listener, daemon=True).start()
        threading.Thread(target=self.socket_tcp_listener, daemon=True).start()
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[-] Apagando el Agente SDN...")
            self.running = False


# --- PUNTO DE ENTRADA ---
if __name__ == "__main__":
    # Sobrescritura opcional por argumentos de línea de comandos:
    #   python cliente.py NodoAlpha 5001 http://192.168.1.10:8000
    if len(sys.argv) > 1:
        CONFIG["NOMBRE_NODO"] = sys.argv[1]
    if len(sys.argv) > 2:
        CONFIG["PUERTO_ESCUCHA"] = int(sys.argv[2])
    if len(sys.argv) > 3:
        CONFIG["CONTROLADOR_URL"] = sys.argv[3]

    agente = AgenteSDN()
    agente.arrancar()
