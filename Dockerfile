FROM python:3.12-slim

WORKDIR /app

COPY app.py config.json index.html style.css logo.png ./

RUN pip install --no-cache-dir flask werkzeug pillow pillow-heif waitress

RUN mkdir -p /app/storage

EXPOSE 5000

CMD ["python", "app.py"]
