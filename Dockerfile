FROM python:3.14-slim

WORKDIR /app

RUN apt-get update && apt-get upgrade -y && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1001 appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p instance && chown -R appuser:appuser /app

USER appuser

ENV FLASK_DEBUG=0
ENV PORT=5006

EXPOSE 5006

CMD ["gunicorn", "wsgi:app", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:5006"]
