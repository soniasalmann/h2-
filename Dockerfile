# Multi-agent SOC Simulation Platform Container
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GRADIO_SERVER_NAME="0.0.0.0" \
    GRADIO_SERVER_PORT=7860 \
    GRADIO_SHARE="false"

# Set working directory
WORKDIR /app

# Install system dependencies (curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create an unprivileged user for security compliance
RUN useradd -m -u 1001 socuser && \
    chown -R socuser:socuser /app

# Copy application source code
COPY --chown=socuser:socuser . .

# Switch to non-root user
USER socuser

# Expose Gradio SOC console port
EXPOSE 7860

# Healthcheck to verify the web interface is responding
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:7860/ || exit 1

# Launch the SOC console
CMD ["python", "app.py"]
