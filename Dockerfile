FROM python:3.11

# Install required system libraries
RUN apt-get update && apt-get install -y \
    libssl-dev \
    libffi-dev \
    libp11-kit-dev \
    gcc \
    pkg-config \
    openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ .

EXPOSE 5000
CMD ["python", "app.py"]
