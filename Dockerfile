FROM python:3.12-bookworm AS base

# Configuración de entorno
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Instalación de herramientas de escaneo
# Nota: Instalamos nmap y dependencias de nikto
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    perl \
    libnet-ssleay-perl \
    git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Instalación manual de Nikto (más fiable que el paquete de repo en algunas distros)
RUN git clone --depth=1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

WORKDIR /app

# Instalación de dependencias de Python
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copiar código y preparar entorno
COPY . .
RUN mkdir -p /app/data/scans

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Comando por defecto (API)
CMD ["sh", "-c", "python -m alembic upgrade head && uvicorn api.app:app --host 0.0.0.0 --port 8000 --workers 1"]
