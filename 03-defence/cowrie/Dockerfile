# cowrie honeypot container
FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    git libssl-dev libffi-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash cowrie

WORKDIR /opt/cowrie

RUN git clone --depth 1 https://github.com/cowrie/cowrie.git . \
    && pip install --no-cache-dir -r requirements.txt

COPY cowrie.cfg etc/cowrie.cfg
COPY userdb.txt etc/userdb.txt

RUN mkdir -p var/log/cowrie var/lib/cowrie/downloads var/lib/cowrie/ttylog \
    && chown -R cowrie:cowrie /opt/cowrie

USER cowrie

# ssh on 2222, telnet on 2323
EXPOSE 2222 2323

# cowrie doesn't daemonize well in docker, run in foreground
CMD ["twistd", "--nodaemon", "--pidfile=", "-y", "src/cowrie/application.tac"]
