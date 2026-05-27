# Generador de Tráfico Sintético SDN
# Universidad del Rosario — Redes de Computadores
import socket
import time

def ejecutar_generador():
    print("=" * 55)
    print("   SDN TRAFFIC INJECTOR (TCP/UDP) — U. ROSARIO")
    print("=" * 55)

    # --- CONFIGURACIÓN DEL FLUJO ---
    ip      = input("IP del agente destino  (default: 127.0.0.1): ").strip() or "127.0.0.1"
    puerto  = int(input("Puerto destino          (default: 5000): ").strip() or 5000)
    proto   = input("Protocolo (TCP/UDP)     (default: UDP): ").strip().upper() or "UDP"
    msg     = input("Mensaje / payload       (default: Paquete de prueba SDN): ").strip() or "Paquete de prueba SDN"
    cantidad = int(input("Número de ráfagas      (default: 3): ").strip() or 3)
    intervalo = float(input("Intervalo entre ráfagas en segundos (default: 1.0): ").strip() or 1.0)

    print(f"\n[*] Iniciando inyección → {ip}:{puerto} [{proto}] × {cantidad} ráfaga(s)\n")

    for i in range(cantidad):
        payload = f"[Ráfaga {i+1}/{cantidad}] {msg}".encode("utf-8")
        try:
            if proto == "UDP":
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(payload, (ip, puerto))
                s.close()
                print(f"[+] UDP ráfaga {i+1}/{cantidad} enviada → {ip}:{puerto}")

            elif proto == "TCP":
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((ip, puerto))
                s.sendall(payload)
                s.close()
                print(f"[+] TCP ráfaga {i+1}/{cantidad} enviada → {ip}:{puerto}")

            else:
                print(f"[-] Protocolo '{proto}' no reconocido. Usa TCP o UDP.")
                break

        except socket.timeout:
            print(
                f"[-] Ráfaga {i+1}: TIMEOUT — el agente descartó el paquete (DROP efectivo)."
            )
        except ConnectionRefusedError:
            print(
                f"[-] Ráfaga {i+1}: Conexión rechazada — el agente no está escuchando en {ip}:{puerto}."
            )
        except Exception as e:
            print(f"[-] Ráfaga {i+1}: Error inesperado — {e}")

        if i < cantidad - 1:
            time.sleep(intervalo)

    print("\n[*] Inyección completada.")


if __name__ == "__main__":
    ejecutar_generador()
