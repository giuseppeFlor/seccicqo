# Componente: controllo phishing negli SMS.
# Contiene solo il client adb; il server gira nel container "adb".
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends adb \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home --shell /usr/sbin/nologin seccicqo

WORKDIR /app
COPY sms_phishing/ /app/sms_phishing/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ADB_SERVER_SOCKET=tcp:adb:5037 \
    HOME=/tmp

USER seccicqo
WORKDIR /data
ENTRYPOINT ["python3", "/app/sms_phishing/check_sms.py"]
CMD ["--adb", "--save-dump", "/data/sms.txt", "--json", "/data/report.json"]
