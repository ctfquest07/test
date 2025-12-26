# 🚀 Ultimate CTF Platform Deployment Guide (AWS EC2)

This comprehensive guide covers every step to deploy your CTF platform (Frontend + Backend) to a fresh AWS EC2 instance.

**Target Specs:**
*   **OS:** Ubuntu 22.04 LTS
*   **Instance:** `t3.large` (Recommended for 500+ users)
*   **Concurrent Users:** 500-600

---

## 🛑 Phase 1: AWS Security Group Setup

Before connecting, ensure your **Security Group** has these Inbound Rules:

| Type | Protocol | Port Range | Source | Description |
| :--- | :--- | :--- | :--- | :--- |
| **SSH** | TCP | 22 | My IP | For your access only |
| **HTTP** | TCP | 80 | 0.0.0.0/0 | Public Web Access (Frontend) |
| **HTTPS** | TCP | 443 | 0.0.0.0/0 | Public Web Access (SSL) |
| **Custom**| TCP | 10000 | 127.0.0.1 | **Internal Only** (Backend API) |

---

## 🖥️ Phase 2: System Preparation

**1. Connect to your instance:**
```bash
ssh -i "your-key.pem" ubuntu@<your-ec2-public-ip>
```

**2. Update & Upgrade System:**
```bash
sudo apt update && sudo apt upgrade -y
```

**3. Install Essential Tools:**
```bash
sudo apt install -y git curl build-essential libssl-dev
```

---

## 🗄️ Phase 3: Redis Setup (Database & Cache)

**1. Install Redis:**
```bash
sudo apt install -y redis-server
```

**2. Configure Redis for Production:**
```bash
sudo nano /etc/redis/redis.conf
```
*   Find `supervised no` -> change to `supervised systemd`
*   Find `appendonly no` -> change to `appendonly yes`
*   Ensure `bind 127.0.0.1 ::1` is active (Security critical!)

**3. Restart & Enable Redis:**
```bash
sudo systemctl restart redis.service
sudo systemctl enable redis.service
```

---

## 🟢 Phase 4: Node.js Environment

**1. Install NVM & Node.js v20:**
```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
source ~/.bashrc
nvm install 20
nvm use 20
```

**2. Install Global Tools:**
```bash
npm install -g pm2
```

---

## 📦 Phase 5: Backend Deployment

**1. Clone Repo:**
```bash
cd ~
git clone <YOUR_GITHUB_REPO_URL> ctf-platform
```

**2. Install Backend Dependencies:**
```bash
cd ~/ctf-platform/backend
npm ci --only=production
```

**3. Configure Backend Variables:**
```bash
nano .env
```
(Paste your production env vars, ensuring `PORT=10000` and `NODE_ENV=production`)

**4. Start Backend with PM2:**
```bash
pm2 start ecosystem.config.js --env production
pm2 save
pm2 startup
```

---

## 🎨 Phase 6: Frontend Deployment

**1. Install Frontend Dependencies:**
```bash
cd ~/ctf-platform/frontend
npm install
```

**2. Configure Frontend Build:**
Create a production `.env` file for the frontend builder:
```bash
nano .env
```
Add the following line (pointing to your **public** domain/IP):
```
VITE_API_URL=http://<YOUR-EC2-PUBLIC-IP>
```
*Note: If you are setting up SSL later, use `https://.../api`*

**3. Build for Production:**
```bash
npm run build
```
This creates a `dist` folder at `~/ctf-platform/frontend/dist`.

---

## 🌐 Phase 7: Nginx Reverse Proxy & Static Serving

**1. Install Nginx:**
```bash
sudo apt install -y nginx
```

**2. Configure Nginx:**
Copy your `nginx.conf` (which serves frontend from `/` and proxies `/api` to backend):
```bash
sudo nano /etc/nginx/sites-available/ctf-backend
```
*Paste your updated `nginx.conf` content here.*

**ensure the `root` directive points to correctly:**
`root /home/ubuntu/ctf-platform/frontend/dist;`

**3. Enable Site:**
```bash
sudo ln -s /etc/nginx/sites-available/ctf-backend /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default
```

**4. Restart Nginx:**
```bash
sudo nginx -t
sudo systemctl restart nginx
```

---

## 🔒 Phase 8: SSL (HTTPS)

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

**Deployment Complete! 🚀**
