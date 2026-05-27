# Importamos las librerías necesarias

# FastAPI: Framework ASGI de alto rendimiento para construir la API del controlador de forma asíncrona
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
# Jinja2Templates: Motor para renderizar y servir la interfaz gráfica de usuario de forma desacoplada
from fastapi.templating import Jinja2Templates

# Pydantic y Tipado: Garantizan el tipado estricto y la validación estructural de los datos entrantes (JSON)
from pydantic import BaseModel
from typing import List, Dict, Any

# Servidores y Utilidades
import uvicorn  # Servidor web ASGI rápido que expone y ejecuta la aplicación FastAPI
import uuid     # Generador de identificadores únicos para indexar las reglas de flujo de forma inequívoca

# Inicializamos la aplicación principal del controlador SDN
app = FastAPI(title="Controlador SDN - Proyecto de Redes")

# Configuración del motor de plantillas de Jinja2, apuntando al directorio físico donde reside el HTML
templates = Jinja2Templates(directory="templates") 

# --- MODELOS DE DATOS (Abstracciones de Pydantic para Validación Estricta) ---

class ReglaFlujo(BaseModel):
    """
    Representa una entrada de la "Flow Table" equivalente a una regla de OpenFlow.
    Define los criterios de coincidencia (Match Fields) y las acciones asociadas.
    """
    id: str = ""           # Identificador único de la regla (Hash de 8 caracteres)
    note: str              # Descripción académica o propósito de la política
    ipSrc: str = "*"       # Criterio de Coincidencia: IP de Origen (Soporta comodín)
    ipDst: str = "*"       # Criterio de Coincidencia: IP de Destino (Soporta comodín)
    ipProto: str = "*"     # Criterio de Coincidencia: Protocolo de Capa 4 (TCP / UDP)
    tpDst: str = "*"       # Criterio de Coincidencia: Puerto de Destino del servicio
    action: str            # Acción SDN: 'forward' (Aceptar), 'drop' (Bloquear), 'controller' (Alertar)
    priority: int          # Nivel de prioridad estricto para la resolución de conflictos (1=Baja, 2=Media, 3=Alta)
    packets: int = 0       # Contador de paquetes ("Hits") que han hecho 'match' con la regla (Telemetría de la regla)

class ReporteTrafico(BaseModel):
    """
    Estructura de datos utilizada por el Analizador de Tráfico Centralizado.
    Define el esquema JSON que los agentes del plano de datos deben enviar para reportar eventos de red.
    """
    nodo: str              # Identificador o nombre del host sensor que genera el reporte
    protocolo: str         # Protocolo de transporte observado (TCP/UDP)
    puerto: int            # Puerto de destino de la transmisión interceptada
    origen: str            # Dirección IP del host remoto atacante o emisor del tráfico
    accion_tomada: str     # Decisión local ejecutada por el agente (ALLOW o DROP)
    payload: str           # Primeros bytes del contenido del paquete para inspección profunda (DPI)

# --- BASE DE DATOS VOLÁTIL EN MEMORIA (Estado del Controlador) ---

# Repositorio de hosts autenticados. Llave: IP del agente, Valor: Metadatos del nodo
nodos_activos = {}

# Flow Table inicial cargada por defecto con políticas de simulación académica
tabla_reglas = [
    ReglaFlujo(id="r-1", note="Permitir TCP Escolar", ipProto="TCP", tpDst="5000", action="forward", priority=2),
    ReglaFlujo(id="r-2", note="Mitigar Ataque UDP", ipProto="UDP", tpDst="5000", action="drop", priority=3)
]

# Estructura de cola lineal para registrar las cadenas de texto de auditoría del sistema
historial_logs: List[str] = []

# Diccionario de acumulación estadística global para el Analizador de Tráfico Integrado
analiticas = {
    "total_paquetes": 0,
    "paquetes_permitidos": 0,
    "paquetes_bloqueados": 0,
    "alertas_criticas": 0
}


# --- ENDPOINTS DE LA INTERFAZ DE USUARIO (Plano de Aplicación) ---

@app.get("/", response_class=HTMLResponse)
async def get_dashboard_html(request: Request):
    """
    Punto de entrada principal. Renderiza la consola web del administrador de la red.
    Usa la sintaxis moderna compatible con Python 3.14 / Starlette para evitar conflictos de caché en Jinja2.
    """
    return templates.TemplateResponse(
        request=request, 
        name="dashboard.html", 
        context={"request": request}
    )


# --- INTERFACES PROGRAMÁTICAS (Endpoints de la API REST del Controlador) ---

@app.get("/api/dashboard")
async def api_get_dashboard():
    """
    Provee el estado completo de la red en formato JSON a la consola web.
    Antes de enviar las reglas, estas pasan por un proceso de ordenamiento estricto por prioridad.
    """
    # Define la jerarquía numérica interna para garantizar que las prioridades se evalúen correctamente
    priority_order = {3: 0, 2: 1, 1: 2} # 3 (Alta) va primero, luego 2 (Media), luego 1 (Baja)
    sorted_rules = sorted(tabla_reglas, key=lambda x: priority_order.get(x.priority, 2))
    
    return {
        "nodos": nodos_activos,
        "reglas": [r.dict() for r in sorted_rules],
        "logs": historial_logs,
        "analiticas": analiticas
    }

@app.post("/api/nodes/register")
async def register_node(payload: Dict[str, str], request: Request):
    """
    Endpoint de descubrimiento de topología. Permite a un agente del plano de datos 
    darse de alta ante el controlador al arrancar en la LAN.
    """
    ip_cliente = request.client.host  # Extrae la dirección IP real del socket TCP emisor
    nombre = payload.get("nombre", f"Nodo-{ip_cliente}")
    
    # Registra o actualiza el host en el inventario central del controlador
    nodos_activos[ip_cliente] = {"nombre": nombre}
    historial_logs.append(f"[SISTEMA] Agente SDN '{nombre}' enlazado desde la IP {ip_cliente}")
    return {"status": "success"}

@app.get("/api/rules", response_model=List[ReglaFlujo])
async def get_rules_plain():
    """
    Canal de descarga para los agentes. Los clientes de la LAN consultan periódicamente (Pull) 
    este endpoint para descargar las políticas de filtrado vigentes ordenadas por jerarquía.
    """
    priority_order = {3: 0, 2: 1, 1: 2}
    return sorted(tabla_reglas, key=lambda x: priority_order.get(x.priority, 2))

@app.post("/api/rules")
async def add_rule(regla: ReglaFlujo):
    """
    Inyección de políticas en caliente. Permite al administrador añadir nuevas directrices 
    de seguridad desde la interfaz web, las cuales se propagan inmediatamente a la red.
    """
    regla.id = str(uuid.uuid4())[:8]  # Genera un ID único truncado de 8 caracteres
    tabla_reglas.append(regla)       # Inyecta la nueva regla en la tabla de flujos activa
    historial_logs.append(f"[CONTROL] Regla inyectada: '{regla.note}' [Prioridad Nivel: {regla.priority}]")
    return {"status": "created", "id": regla.id}

@app.delete("/api/rules/{rule_id}")
async def delete_rule(rule_id: str):
    """
    Remoción dinámica de flujos. Da de baja una regla de la Flow Table global utilizando su ID.
    """
    global tabla_reglas
    # Filtra la lista en memoria excluyendo la regla seleccionada para su eliminación
    tabla_reglas = [r for r in tabla_reglas if r.id != rule_id]
    historial_logs.append(f"[CONTROL] Regla {rule_id} dada de baja por el administrador.")
    return {"status": "deleted"}

@app.post("/api/rules/match/{rule_id}")
async def match_increment(rule_id: str):
    """
    Contador de Hits de políticas. Invocado por los agentes locales para reportar de forma discreta 
    que un paquete coincidió con una regla de firewall específica, actualizando los contadores de la tabla.
    """
    for r in tabla_reglas:
        if r.id == rule_id:
            r.packets += 1  # Incrementa de forma atómica el contador de paquetes de la regla
            break
    return {"status": "ok"}

# --- EL COMPONENTE DE TELEMETRÍA CENTRAL: ANALIZADOR DE TRÁFICO ---

@app.post("/api/analyzer/report")
async def receive_traffic_report(reporte: ReporteTrafico, request: Request):
    """
    Módulo Analizador de Tráfico (Telemetría de Red). Recibe en tiempo real los metadatos 
    de cada paquete procesado en la LAN, calculando las métricas globales de mitigación de la red.
    """
    ip_origen_nodo = request.client.host  # Obtiene la IP del nodo que está reportando
    
    # Actualización del motor analítico global
    analiticas["total_paquetes"] += 1
    if reporte.accion_tomada == "ALLOW":
        analiticas["paquetes_permitidos"] += 1
    elif reporte.accion_tomada == "DROP":
        analiticas["paquetes_bloqueados"] += 1
        
    # Construcción de la línea de telemetría con formato avanzado para el visor de eventos
    log_linea = f"[{reporte.accion_tomada}] [{reporte.nodo} ({ip_origen_nodo})] -> Flujo {reporte.protocolo}:{reporte.puerto} desde {reporte.origen}. Payload: '{reporte.payload}'"
    historial_logs.append(log_linea)
    return {"status": "telemetry_logged"}

# Inicialización directa del entorno de ejecución de Python
if __name__ == "__main__":
    # Abre el socket HTTP del servidor escuchando en todas las interfaces de red (0.0.0.0) en el puerto 8000
    uvicorn.run(app, host="0.0.0.0", port=8000)