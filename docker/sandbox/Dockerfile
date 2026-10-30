# Ambiente protetto per l'analisi STATICA di campioni sospetti (APK, dex, ...).
# I campioni non vengono mai eseguiti. L'isolamento vero (niente rete,
# filesystem in sola lettura, nessuna capability) è imposto da docker-compose.yml.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends file unzip binutils \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir androguard==4.1.3 yara-python==4.5.1 \
 && useradd --uid 10002 --no-create-home --shell /usr/sbin/nologin analyst

COPY docker/sandbox/triage.py /opt/sandbox/triage.py
COPY docker/sandbox/rules/ /opt/sandbox/rules/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

USER analyst
WORKDIR /reports
ENTRYPOINT ["python3", "/opt/sandbox/triage.py"]
CMD ["/samples"]
