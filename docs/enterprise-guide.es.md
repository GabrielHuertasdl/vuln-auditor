# ⚡ VulnAudit Enterprise — Guía de Puesta en Marcha

El proyecto ha sido transformado en una plataforma de auditoría defensiva de nivel enterprise.

## 🚀 Despliegue con Docker (Recomendado)

La arquitectura ahora es distribuida (API + Worker + Postgres + Redis).

```bash
# 1. Copia el ejemplo de entorno y configuralo
cp .env.example .env

# 2. Levanta toda la infraestructura
docker-compose up -d --build
```

Servicios disponibles:
- **Web UI & API**: `http://localhost:8000` (Acceso principal)
- **ZAP Proxy**: `http://localhost:8090` (Orquestado por el Worker)

---

## 🛠️ Pasos para empezar a usar el sistema

### 1. Configurar la Organización
Accede a la interfaz web (`http://localhost:8000`) o usa la API para crear tu organización y obtener tu API Key (opcional en modo demo).

### 2. Definir Targets Autorizados
Por seguridad enterprise, el sistema tiene un **Target Validator**.
- Ve a la sección **Targets** en la UI.
- Añade las URLs que tienes permiso para auditar.
- El sistema verificará que no sean IPs privadas o loopback (protección anti-SSRF).

### 3. Configurar Notificaciones (Opcional)
Edita tu `.env` para añadir integración con Slack o Webhooks:
- `SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...`
- `NOTIFICATION_WEBHOOK_URL=https://tu-sistema.com/webhook`

### 4. Lanzar el primer Scan
- Selecciona un target.
- Elige las herramientas (`nmap`, `nikto`, `zap`).
- El sistema encolará el trabajo en **Redis**.
- El **Worker** lo procesará de forma aislada.
- Podrás seguir el progreso en tiempo real desde el Dashboard.

---

## 🏗️ Novedades Técnicas

- **Persistence**: SQLite ha sido reemplazado por PostgreSQL para alta disponibilidad.
- **Async Workers**: Uso de `arq` para que la API nunca se bloquee y los escaneos sean persistentes.
- **Business Intelligence**: Cálculo de `Business Risk Score` automático en cada reporte.
- **Reporting**: Informes Markdown con métricas C-Level y comparativa histórica (Diff).

---

## 🛡️ Seguridad
- **RBAC**: Base técnica lista para roles (Owner, Admin, Auditor).
- **Audit Logs**: Cada acción queda registrada en la tabla `audit_logs`.
- **Isolation**: Los escaneos corren en procesos separados orquestados por el Worker.
