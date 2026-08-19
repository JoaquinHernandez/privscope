FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    libcap2-bin \
    sudo \
    cron \
    findutils \
    && rm -rf /var/lib/apt/lists/*

# Create standard unprivileged user
RUN useradd -m -s /bin/bash auditor && \
    echo "auditor:password123" | chpasswd

# Setup intentional misconfigurations for testing PrivScope:
# 1. SUID binary vector
RUN chmod u+s /usr/bin/find

# 2. Linux Capabilities vector
RUN setcap cap_setuid+ep /usr/bin/python3.10

# 3. Writable cron task
RUN echo "* * * * * root /tmp/backup.sh" > /etc/cron.d/backup_job && \
    echo "#!/bin/bash\ntar -czf /tmp/backup.tar.gz /var/log/*" > /tmp/backup.sh && \
    chmod 777 /tmp/backup.sh

# 4. Insecure PATH entry
ENV PATH=".:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

WORKDIR /app
COPY . /app

USER auditor

CMD ["python3", "-m", "privscope.cli"]
