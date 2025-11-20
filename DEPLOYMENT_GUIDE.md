# Production Deployment Guide
## CyberShield AI - Weeks 11-12 Implementation

## 🚀 Quick Start

### Prerequisites
- Docker Engine 24.0+ and Docker Compose 2.0+
- At least 8GB RAM and 50GB disk space
- Domain name with SSL certificate (for production)
- SMTP server for email delivery
- OpenAI API key (for AI agents)

### 1. Clone and Configure

```bash
# Clone repository
git clone https://github.com/yourusername/CyberShieldAI.git
cd CyberShieldAI

# Copy environment template
cp .env.production.template .env.production

# Edit with your production values
nano .env.production
```

### 2. Deploy with Docker Compose

```bash
# Build and start all services
docker-compose -f docker-compose.prod.yml up -d

# Check service health
docker-compose -f docker-compose.prod.yml ps

# View logs
docker-compose -f docker-compose.prod.yml logs -f
```

### 3. Initialize Database

```bash
# Run database migrations
docker-compose exec backend alembic upgrade head

# Create admin user
docker-compose exec backend python -m scripts.create_admin
```

### 4. Access Application

- **Frontend**: http://localhost:80
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Flower (Celery)**: http://localhost:5555

## 📦 Docker Services Architecture

```
┌──────────────────────────────────────────────────────┐
│                   Nginx Proxy                         │
│                 (Port 80/443)                         │
└──────────────┬───────────────────────────────────────┘
               │
       ┌───────┴────────┐
       │                │
┌──────▼──────┐  ┌─────▼──────┐
│  Frontend   │  │  Backend   │
│  (React)    │  │  (FastAPI) │
│  Port 80    │  │  Port 8000 │
└─────────────┘  └──────┬──────┘
                        │
         ┌──────────────┼──────────────┐
         │              │              │
    ┌────▼────┐   ┌────▼────┐   ┌────▼────┐
    │PostgreSQL│   │  Redis  │   │ Celery  │
    │Port 5432 │   │Port 6379│   │ Worker  │
    └──────────┘   └─────────┘   └─────────┘
```

## 🐳 Services Overview

### 1. **PostgreSQL** (postgres:15-alpine)
- **Purpose**: Primary database
- **Port**: 5432 (internal only)
- **Volume**: `postgres_data`
- **Health Check**: `pg_isready`
- **Resources**: 1GB RAM limit

### 2. **Redis** (redis:7-alpine)
- **Purpose**: Cache & message broker
- **Port**: 6379 (internal only)
- **Volume**: `redis_data`
- **Health Check**: `redis-cli ping`
- **Resources**: 512MB RAM limit

### 3. **Backend** (Custom Python)
- **Purpose**: FastAPI application
- **Port**: 8000
- **Volumes**: 
  - `chroma_data` (vector DB)
  - `report_data` (PDF reports)
  - `upload_data` (file uploads)
- **Health Check**: `/health` endpoint
- **Resources**: 2GB RAM limit
- **Workers**: 4 Gunicorn workers

### 4. **Celery Worker**
- **Purpose**: Background task processing
- **Tasks**: Scans, indexing, email delivery
- **Concurrency**: 4 workers
- **Resources**: 2GB RAM limit
- **Docker Access**: `/var/run/docker.sock` (for sandboxed scans)

### 5. **Celery Beat**
- **Purpose**: Task scheduling
- **Schedule**: Daily vector DB updates, reports

### 6. **Flower**
- **Purpose**: Celery monitoring
- **Port**: 5555
- **Access**: http://localhost:5555

### 7. **Frontend** (Nginx + React)
- **Purpose**: User interface
- **Port**: 80
- **Build**: Multi-stage with optimized assets
- **Resources**: 256MB RAM limit

## 🔐 Security Configuration

### Environment Variables (Critical)

```bash
# Generate strong secrets
SECRET_KEY=$(openssl rand -hex 32)
JWT_SECRET_KEY=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -base64 32)
REDIS_PASSWORD=$(openssl rand -base64 32)
```

### SSL/TLS Setup (Production)

```bash
# Generate self-signed certificate (testing only)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem

# For production, use Let's Encrypt
certbot certonly --standalone -d yourdomain.com
```

### Firewall Rules

```bash
# Allow only necessary ports
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw allow 22/tcp    # SSH (from specific IPs only)
ufw enable
```

## 📊 Monitoring & Logging

### View Logs

```bash
# All services
docker-compose -f docker-compose.prod.yml logs -f

# Specific service
docker-compose -f docker-compose.prod.yml logs -f backend

# Last 100 lines
docker-compose -f docker-compose.prod.yml logs --tail=100 backend
```

### Health Checks

```bash
# Check all services
docker-compose -f docker-compose.prod.yml ps

# Test backend health
curl http://localhost:8000/health

# Test frontend
curl http://localhost:80
```

### Flower Dashboard

Access: http://localhost:5555
- Monitor Celery tasks
- View worker status
- Task history and statistics

### Prometheus Metrics (Optional)

```bash
# Backend metrics endpoint
curl http://localhost:8000/metrics
```

## 🔄 CI/CD Pipeline

### GitHub Actions Workflow

**Triggers**:
- Push to `main` or `develop`
- Pull requests to `main`
- Release published

**Jobs**:
1. **test-backend**: Run pytest with coverage
2. **test-frontend**: Run npm tests and linting
3. **security-scan**: Trivy vulnerability scanning
4. **build-images**: Build and push Docker images to GHCR
5. **deploy-production**: Deploy on release (main branch)
6. **deploy-staging**: Deploy on develop branch

### Required GitHub Secrets

```bash
# Add these in GitHub repo → Settings → Secrets

SSH_PRIVATE_KEY          # SSH key for production server
PRODUCTION_HOST          # Production server IP/domain
PRODUCTION_USER          # SSH username
SLACK_WEBHOOK           # Slack notifications (optional)
```

### Manual Deployment

```bash
# SSH to production server
ssh user@production-server

# Navigate to project
cd /opt/cybershield

# Pull latest changes
git pull origin main

# Pull latest Docker images
docker-compose -f docker-compose.prod.yml pull

# Restart services (zero downtime)
docker-compose -f docker-compose.prod.yml up -d --no-deps

# Run migrations
docker-compose exec backend alembic upgrade head
```

## 💾 Backup & Restore

### Database Backup

```bash
# Create backup
docker-compose exec postgres pg_dump -U cybershield_user cybershield_prod > backup.sql

# Automated daily backup (add to crontab)
0 2 * * * /opt/cybershield/scripts/backup-database.sh
```

### Restore Database

```bash
# Restore from backup
cat backup.sql | docker-compose exec -T postgres psql -U cybershield_user cybershield_prod
```

### Volume Backup

```bash
# Backup volumes
docker run --rm -v cybershield_chroma_data:/data -v $(pwd):/backup \
  alpine tar czf /backup/chroma-backup.tar.gz /data

# Restore volume
docker run --rm -v cybershield_chroma_data:/data -v $(pwd):/backup \
  alpine sh -c "cd /data && tar xzf /backup/chroma-backup.tar.gz --strip 1"
```

## 📈 Performance Tuning

### PostgreSQL Optimization

```sql
-- In postgres container
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET work_mem = '64MB';
SELECT pg_reload_conf();
```

### Redis Optimization

```bash
# In redis.conf or environment
maxmemory 512mb
maxmemory-policy allkeys-lru
```

### Backend Scaling

```yaml
# In docker-compose.prod.yml
backend:
  deploy:
    replicas: 3  # Run 3 backend instances
  environment:
    WORKERS: 4   # 4 Gunicorn workers per instance
```

### Celery Scaling

```yaml
celery-worker:
  deploy:
    replicas: 2  # Run 2 worker instances
  command: celery -A workers.celery_app worker --concurrency=8
```

## 🚨 Troubleshooting

### Service Won't Start

```bash
# Check logs
docker-compose -f docker-compose.prod.yml logs backend

# Check resource usage
docker stats

# Restart specific service
docker-compose -f docker-compose.prod.yml restart backend
```

### Database Connection Issues

```bash
# Test database connectivity
docker-compose exec backend python -c "from utils.database import test_connection; test_connection()"

# Check PostgreSQL logs
docker-compose logs postgres
```

### Celery Tasks Not Running

```bash
# Check worker status in Flower
# http://localhost:5555/workers

# Check Redis connection
docker-compose exec backend python -c "import redis; r=redis.from_url('redis://:password@redis:6379/1'); print(r.ping())"

# Restart workers
docker-compose restart celery-worker celery-beat
```

### High Memory Usage

```bash
# Check container memory
docker stats

# Reduce worker concurrency
docker-compose exec celery-worker celery -A workers.celery_app control pool_shrink 2
```

## 🔧 Maintenance

### Update Application

```bash
# Pull latest code
git pull origin main

# Rebuild images
docker-compose -f docker-compose.prod.yml build

# Restart with new images
docker-compose -f docker-compose.prod.yml up -d
```

### Clean Up

```bash
# Remove stopped containers
docker-compose -f docker-compose.prod.yml down

# Remove unused images
docker image prune -a

# Remove unused volumes (CAREFUL!)
docker volume prune
```

### Database Migrations

```bash
# Create migration
docker-compose exec backend alembic revision --autogenerate -m "description"

# Apply migration
docker-compose exec backend alembic upgrade head

# Rollback
docker-compose exec backend alembic downgrade -1
```

## 📝 Production Checklist

- [ ] All environment variables configured
- [ ] Strong passwords generated for DB, Redis, secrets
- [ ] SSL certificate installed (Let's Encrypt or commercial)
- [ ] Firewall configured (only 80, 443, 22 open)
- [ ] Automated backups configured
- [ ] Monitoring set up (Sentry, Prometheus, etc.)
- [ ] Email delivery tested (SMTP configured)
- [ ] Domain DNS configured
- [ ] Health checks passing
- [ ] CI/CD pipeline tested
- [ ] Admin user created
- [ ] Rate limiting configured
- [ ] CORS origins configured correctly
- [ ] Log rotation configured
- [ ] Disaster recovery plan documented

## 🌐 Cloud Deployment Options

### AWS ECS

```bash
# Deploy to AWS ECS
ecs-cli compose -f docker-compose.prod.yml up
```

### Google Cloud Run

```bash
# Deploy backend to Cloud Run
gcloud run deploy cybershield-backend \
  --source ./backend \
  --region us-central1
```

### DigitalOcean App Platform

```bash
# Use doctl CLI
doctl apps create --spec .do/app.yaml
```

### Azure Container Instances

```bash
# Deploy with Azure CLI
az container create --resource-group cybershield \
  --file docker-compose.prod.yml
```

## 📞 Support

- **Documentation**: https://docs.cybershield.ai
- **GitHub Issues**: https://github.com/yourusername/CyberShieldAI/issues
- **Email**: support@cybershield.ai
- **Slack**: https://cybershield.slack.com

---

**Last Updated**: November 2025
**Version**: 2.0.0
