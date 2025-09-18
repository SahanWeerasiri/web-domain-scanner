# Docker Deployment Guide

This guide explains how to deploy the Web Domain Scanner using Docker.

## Quick Start

### Using Docker Compose (Recommended)

1. **Clone the repository** (if not already done):
```bash
git clone <repository-url>
cd web-domain-scanner
```

2. **Create environment file** (optional but recommended):
```bash
cp .env.example .env
# Edit .env file with your API keys
```

3. **Build and run with Docker Compose**:
```bash
docker-compose up -d
```

4. **Access the API**:
- API Documentation: http://localhost:8000/api/docs
- Health Check: http://localhost:8000/health

### Using Docker directly

1. **Build the image**:
```bash
docker build -t web-domain-scanner .
```

2. **Run the container**:
```bash
docker run -d \
  --name web-domain-scanner \
  -p 8000:8000 \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/output:/app/output \
  web-domain-scanner
```

## Configuration

### Environment Variables

You can configure the scanner using environment variables:

- `GEMINI_API_KEY`: Google Gemini API key for AI-powered endpoint discovery
- `OPENAI_API_KEY`: OpenAI API key (alternative to Gemini)
- `ANTHROPIC_API_KEY`: Anthropic API key (alternative to Gemini)
- `API_HOST`: Host to bind the server (default: 0.0.0.0)
- `API_PORT`: Port to bind the server (default: 8000)
- `MAX_THREADS`: Maximum number of threads for scanning (default: 10)
- `REQUEST_TIMEOUT`: Default request timeout in seconds (default: 30)

### Volumes

The following directories can be mounted as volumes:

- `/app/logs`: Scan logs and state files
- `/app/output`: Generated reports and scan results
- `/app/config`: Configuration files (read-only recommended)

## Security Considerations

### Network Security
- The container runs on port 8000 by default
- Consider using a reverse proxy (nginx, traefik) for production
- Implement proper authentication if exposing to the internet

### Resource Limits
The docker-compose.yml includes resource limits:
- Memory: 2GB limit, 512MB reservation
- CPU: 1.0 limit, 0.5 reservation

Adjust these based on your scanning requirements.

### User Security
- The container runs as a non-root user (scanner:1000)
- Uses security options like `no-new-privileges`

## Monitoring

### Health Check
The container includes a health check that:
- Checks every 30 seconds
- Has a 10-second timeout
- Retries 3 times before marking as unhealthy
- Waits 60 seconds before first check

### Logs
View container logs:
```bash
docker logs web-domain-scanner
# or with docker-compose
docker-compose logs -f web-domain-scanner
```

## Scaling

### Multiple Instances
You can run multiple instances by changing the port mapping:
```bash
docker run -d \
  --name web-domain-scanner-2 \
  -p 8001:8000 \
  web-domain-scanner
```

### Load Balancing
For production deployments, consider using:
- Nginx or HAProxy for load balancing
- Container orchestration (Kubernetes, Docker Swarm)

## Troubleshooting

### Common Issues

1. **Port already in use**:
   - Change the port mapping: `-p 8001:8000`

2. **Permission issues with volumes**:
   - Ensure the host directories have proper permissions
   - Use `sudo chown -R 1000:1000 logs output` if needed

3. **Browser issues in container**:
   - The container includes Chromium for SeleniumBase
   - If you encounter browser issues, check the logs

4. **Memory issues**:
   - Increase the memory limit in docker-compose.yml
   - Monitor resource usage with `docker stats`

### Debugging

1. **Access container shell**:
```bash
docker exec -it web-domain-scanner /bin/bash
```

2. **Check container resources**:
```bash
docker stats web-domain-scanner
```

3. **View detailed logs**:
```bash
docker logs --details web-domain-scanner
```

## Production Deployment

For production deployments, consider:

1. **Reverse Proxy**: Use nginx or traefik
2. **SSL/TLS**: Implement HTTPS encryption
3. **Authentication**: Add API authentication
4. **Monitoring**: Use Prometheus/Grafana for monitoring
5. **Backup**: Regular backup of logs and output data
6. **Updates**: Plan for container image updates

## API Usage

Once running, you can use the scanner via the REST API:

```bash
# Start a quick scan
curl -X POST "http://localhost:8000/api/pipeline" \
     -H "Content-Type: application/json" \
     -d '{
       "domain": "example.com",
       "scan_mode": "quick",
       "modules": ["subdomain_discovery", "service_discovery"]
     }'

# Check scan status
curl "http://localhost:8000/api/status/{request_id}"
```

For detailed API documentation, visit: http://localhost:8000/api/docs