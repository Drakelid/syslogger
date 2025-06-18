FROM python:3.11-slim

WORKDIR /app

COPY syslogger.py /app/
RUN mkdir -p /logs
VOLUME ["/logs"]

RUN pip install --no-cache-dir --upgrade pip flask

EXPOSE 514/tcp
EXPOSE 514/udp
EXPOSE 8080

CMD ["python", "/app/syslogger.py"]
