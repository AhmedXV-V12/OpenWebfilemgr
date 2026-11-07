FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY app.py config.json index.html style.css logo.png ./

RUN mkdir -p /app/storage

EXPOSE 7000

CMD ["python", "app.py"]
