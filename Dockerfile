FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . .

# Install BlackWall packages
RUN pip install --no-cache-dir -e packages/core
RUN pip install --no-cache-dir -e packages/dashboard

# Expose Streamlit and FastAPI ports
EXPOSE 8501 8000

# Run the Streamlit application
CMD ["streamlit", "run", "packages/dashboard/dashboard/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
