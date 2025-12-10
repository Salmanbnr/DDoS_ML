FROM python:3.9-slim

# Install necessary packages
RUN apt-get update && apt-get install -y \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the attacker script
COPY docker_ddos_attacker.py /app/

# Make script executable
RUN chmod +x /app/docker_ddos_attacker.py

# Default command
CMD ["python3", "docker_ddos_attacker.py", "--help"]