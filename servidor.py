# Importamos las librerías necesarias
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import uvicorn
import uuid
from datetime import datetime

app = FastAPI(title="Controlador SDN - Proyecto de Redes")
templates = Jinja2Templates(directory="templates")

# --- MODELOS DE DATOS ---

class ReglaFlujo(BaseModel):
    """
    Entrada de la Flow Table equivalente a una regla OpenFlow extendida.
    Prioridad: entero libre en el rango [0, 100]. Mayor número = mayor precedencia.
    """
    id: str = ""
    note: str
    # Campos de coincidencia de Capa 3 (IP)
    ipSrc: str = "*"          # IP de origen  (comodín "*" = cualquiera)
    ipDst: str = "*"          # IP de destino (comodín "*" = cualquiera)
    # Campos de coincidencia de Capa 4 (Transporte)
    ipProto: str = "*"        # Protocolo: "TCP", "UDP" o "*"
    tpSrc: str = "*"          # Puerto de ORIGEN del flujo (comodín o número)
    tpDst: str = "*"          # Puerto de DESTINO del servicio (comodín o número)
    # Acción y prioridad
    action: str               # "forward" | "drop" | "controller"
    priority: int = Field(default=50, ge=0, le=100)   # Rango [0-100], mayor = más urgente
    packets: int = 0          # Contador de hits de la regla (telemetría)

class ReporteTrafico(BaseModel):
    nodo: str
    protocolo: str
    puerto: int
    origen: str
    accion_tomada: str
    payload: str

# --- BASE DE DATOS VOLÁTIL EN MEMORIA ---

nodos_activos: Dict[str, Any] = {}

# Flow Table inicial con prioridades en escala 0-100
tabla_reglas: List[ReglaFlujo] = [
    ReglaFlujo(
        id="r-1",
        note="Permitir TCP (puerto 5000)",
        ipProto="TCP", tpDst="5000",
        action="forward", priority=60
    ),
    ReglaFlujo(
        id="r-2",
        note="Mitigar Ataque UDP (puerto 5000)",
        ipProto="UDP", tpDst="5000",
        action="drop", priority=70
    ),
]

historial_logs: List[str] = []

analiticas = {
    "total_paquetes": 0,
    "paquetes_permitidos": 0,
    "paquetes_bloqueados": 0,
    "alertas_criticas": 0,
}

def ts() -> str:
    """Marca de tiempo legible para los logs."""
    return datetime.now().strftime("%H:%M:%S")

# --- ENDPOINTS UI ---

@app.get("/", response_class=HTMLResponse)
async def get_dashboard_html(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"request": request},
    )

# --- API REST ---

@app.get("/api/dashboard")
async def api_get_dashboard():
    """Estado completo de la red en JSON, reglas ordenadas de mayor a menor prioridad."""
    sorted_rules = sorted(tabla_reglas, key=lambda x: x.priority, reverse=True)
    return {
        "nodos": nodos_activos,
        "reglas": [r.dict() for r in sorted_rules],
        "logs": historial_logs,
        "analiticas": analiticas,
    }

@app.post("/api/nodes/register")
async def register_node(payload: Dict[str, str], request: Request):
    ip_cliente = request.client.host
    nombre = payload.get("nombre", f"Nodo-{ip_cliente}")
    nodos_activos[ip_cliente] = {
        "nombre": nombre,
        "ultima_conexion": ts(),
        "estado": "ONLINE",
    }
    historial_logs.append(f"[{ts()}][SISTEMA] Agente '{nombre}' enlazado desde {ip_cliente}")
    return {"status": "success"}

@app.get("/api/rules", response_model=List[ReglaFlujo])
async def get_rules_plain():
    """Canal de descarga para agentes: reglas ordenadas de mayor a menor prioridad."""
    return sorted(tabla_reglas, key=lambda x: x.priority, reverse=True)

@app.post("/api/rules")
async def add_rule(regla: ReglaFlujo):
    regla.id = str(uuid.uuid4())[:8]
    tabla_reglas.append(regla)
    historial_logs.append(
        f"[{ts()}][CONTROL] Regla inyectada: '{regla.note}' "
        f"[Prioridad: {regla.priority}]"
    )
    return {"status": "created", "id": regla.id}

@app.delete("/api/rules/{rule_id}")
async def delete_rule(rule_id: str):
    global tabla_reglas
    tabla_reglas = [r for r in tabla_reglas if r.id != rule_id]
    historial_logs.append(f"[{ts()}][CONTROL] Regla {rule_id} eliminada.")
    return {"status": "deleted"}

@app.post("/api/rules/match/{rule_id}")
async def match_increment(rule_id: str):
    for r in tabla_reglas:
        if r.id == rule_id:
            r.packets += 1
            break
    return {"status": "ok"}

@app.post("/api/analyzer/report")
async def receive_traffic_report(reporte: ReporteTrafico, request: Request):
    ip_origen_nodo = request.client.host
    analiticas["total_paquetes"] += 1
    if reporte.accion_tomada == "ALLOW":
        analiticas["paquetes_permitidos"] += 1
    elif reporte.accion_tomada == "DROP":
        analiticas["paquetes_bloqueados"] += 1
    elif reporte.accion_tomada == "ALERT":
        analiticas["alertas_criticas"] += 1

    log_linea = (
        f"[{ts()}][{reporte.accion_tomada}] "
        f"[{reporte.nodo} ({ip_origen_nodo})] -> "
        f"{reporte.protocolo}:{reporte.puerto} "
        f"desde {reporte.origen} | "
        f"Payload: '{reporte.payload[:60]}'"
    )
    historial_logs.append(log_linea)
    # Limitar historial a 500 entradas para no saturar la memoria
    if len(historial_logs) > 500:
        historial_logs.pop(0)
    return {"status": "telemetry_logged"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
