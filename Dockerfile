FROM python:3.10-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends libmagic1 && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir /app
WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

# run as www-data:www-data
USER 33:33

CMD ["python", "bot.py"]
