# 🚀 Tencent Cloud Deployment Guide für Passkey Backend

## 📋 Voraussetzungen
- Tencent Cloud Account
- Docker installiert (lokal zum Testen)
- MongoDB Atlas Account (für gehostete DB) oder Tencent TencentDB
- PostgreSQL bei Neon.tech oder Tencent TencentDB

## 🔧 Deployment-Schritte

### Option 1: Tencent Cloud Lighthouse (Einfachste Lösung)

1. **Lighthouse Instance erstellen**
   ```bash
   # Im Tencent Cloud Console:
   # - Lighthouse → Create Instance
   # - Wähle: Ubuntu 22.04 mit Docker vorinstalliert
   # - Instance Type: Lightweight Application Server
   # - Region: Wähle eine Region nahe deinen Nutzern
   ```

2. **Mit Server verbinden**
   ```bash
   ssh lighthouse@<your-instance-ip>
   ```

3. **Repository klonen**
   ```bash
   git clone https://github.com/alexfriedl/passkey-backend.git
   cd passkey-backend
   ```

4. **Environment Variables setzen**
   ```bash
   cp .env.example .env
   nano .env
   # Füge deine Datenbankverbindungen ein
   ```

5. **Docker Container starten**
   ```bash
   docker-compose up -d
   ```

6. **Nginx als Reverse Proxy einrichten**
   ```bash
   sudo apt install nginx
   sudo nano /etc/nginx/sites-available/passkey
   ```

   Nginx Konfiguration:
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;

       location / {
           proxy_pass http://localhost:3000;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection 'upgrade';
           proxy_set_header Host $host;
           proxy_cache_bypass $http_upgrade;
       }

       location /.well-known/apple-app-site-association {
           proxy_pass http://localhost:3000/.well-known/apple-app-site-association;
           add_header Content-Type application/json;
       }
   }
   ```

   ```bash
   sudo ln -s /etc/nginx/sites-available/passkey /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl restart nginx
   ```

### Option 2: Tencent CVM mit Container Service

1. **CVM Instance erstellen**
   - Tencent Cloud Console → CVM
   - Ubuntu 22.04 LTS
   - Security Group: Ports 80, 443, 3000 öffnen

2. **Docker und Docker Compose installieren**
   ```bash
   curl -fsSL https://get.docker.com -o get-docker.sh
   sudo sh get-docker.sh
   sudo apt install docker-compose
   ```

3. **Deployment mit Docker**
   ```bash
   # Repository klonen
   git clone https://github.com/alexfriedl/passkey-backend.git
   cd passkey-backend

   # Build und Start
   docker-compose up -d --build
   ```

### Option 3: Tencent Serverless (Cloud Function)

Für Serverless benötigst du einen Wrapper für Express:

1. **Serverless Wrapper erstellen**
   ```typescript
   // serverless.ts
   import { app } from './src/server';
   import serverless from 'serverless-http';

   export const main = serverless(app);
   ```

2. **Deploy mit Serverless Framework**
   ```yaml
   # serverless.yml
   service: passkey-backend
   provider:
     name: tencentcloud
     runtime: Nodejs16.13
     region: ap-shanghai
   
   functions:
     api:
       handler: serverless.main
       events:
         - apigw:
             path: /{proxy+}
             method: ANY
   ```

## 🔐 SSL/HTTPS Setup

Für Production MUSS HTTPS aktiviert werden:

```bash
# Let's Encrypt mit Certbot
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

## 🗄️ Datenbank-Setup

### MongoDB (Tencent TencentDB for MongoDB)
1. TencentDB MongoDB Instance erstellen
2. Connection String in `.env` eintragen:
   ```
   MONGODB_URI=mongodb://username:password@host:port/database
   ```

### PostgreSQL (Tencent TencentDB for PostgreSQL)
1. TencentDB PostgreSQL Instance erstellen
2. Connection String in `.env` eintragen:
   ```
   DATABASE_URL=postgresql://username:password@host:port/database?sslmode=require
   ```

## 🚦 Health Check einrichten

Füge einen Health Check Endpoint hinzu:
```typescript
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});
```

## 📊 Monitoring

1. **Tencent Cloud Monitor aktivieren**
   - CPU, Memory, Network Traffic überwachen
   - Alerts für Downtimes einrichten

2. **Docker Logs**
   ```bash
   docker-compose logs -f app
   ```

## 🔄 CI/CD mit GitHub Actions

`.github/workflows/deploy.yml`:
```yaml
name: Deploy to Tencent Cloud

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Deploy to server
        uses: appleboy/ssh-action@v0.1.5
        with:
          host: ${{ secrets.HOST }}
          username: ${{ secrets.USERNAME }}
          key: ${{ secrets.SSH_KEY }}
          script: |
            cd /path/to/passkey-backend
            git pull
            docker-compose down
            docker-compose up -d --build
```

## 🐛 Troubleshooting

1. **Container startet nicht**
   ```bash
   docker-compose logs app
   docker ps -a
   ```

2. **MongoDB/PostgreSQL Verbindung fehlschlägt**
   - Security Groups prüfen
   - Connection Strings validieren
   - SSL-Einstellungen überprüfen

3. **Apple App Site Association funktioniert nicht**
   ```bash
   curl https://your-domain.com/.well-known/apple-app-site-association
   ```

## 💰 Kostenoptimierung

- **Lighthouse**: ~$4-8/Monat für kleine Instanzen
- **Auto-Scaling**: Nur bei hohem Traffic aktivieren
- **Datenbank**: Shared Instances für Development
- **CDN**: Tencent CDN für statische Assets

## 🔗 Nützliche Links

- [Tencent Cloud Console](https://console.cloud.tencent.com/)
- [Lighthouse Dokumentation](https://www.tencentcloud.com/document/product/1103)
- [TencentDB MongoDB](https://www.tencentcloud.com/products/mongodb)
- [TencentDB PostgreSQL](https://www.tencentcloud.com/products/postgresql)