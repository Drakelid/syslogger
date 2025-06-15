FROM python:3.11-slim

WORKDIR /app

COPY syslogger.py /app/
RUN mkdir -p /logs
VOLUME ["/logs"]

RUN pip install --no-cache-dir --upgrade pip

EXPOSE 514/tcp
EXPOSE 514/udp

CMD ["python", "/app/syslogger.py"]
