# Server ADB: è l'unico container che vede il telefono via USB.
# Gli altri container gli parlano in rete (porta 5037) con ADB_SERVER_SOCKET.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends adb \
 && rm -rf /var/lib/apt/lists/*

# Le chiavi RSA di adb restano in un volume, così il telefono non chiede
# di autorizzare il PC a ogni avvio.
ENV HOME=/root
VOLUME /root/.android
EXPOSE 5037

HEALTHCHECK --interval=10s --timeout=5s --retries=3 CMD adb devices >/dev/null || exit 1

# -a: ascolta su tutte le interfacce (la porta NON viene pubblicata sull'host,
# resta sulla rete interna di compose).
CMD ["adb", "-a", "-P", "5037", "server", "nodaemon"]
