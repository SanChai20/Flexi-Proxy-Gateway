## Deploy on Ubuntu

### Prerequisites
- Ubuntu 18.04 or later
- Root or sudo access
- A registered domain name
- Cloudflare account with API access

### Deployment Steps

#### 1. Switch to Root User
```bash
sudo su root
```

#### 2. Grant Execute Permissions
```bash
chmod u+x admin/cert.sh
chmod u+x admin/launch.sh
```

#### 3. Deploy SSL Certificate (First Time Only)

The cert.sh script handles SSL certificate issuance and installation via acme.sh.

**Note**: This script only needs to be run once during initial setup.

```bash
admin/cert.sh
```

**What it does:**
- Installs required dependencies
- Installs acme.sh certificate management tool
- Issues SSL certificate via Cloudflare DNS validation
- Installs certificate to Nginx
- Configures automatic certificate renewal

**Required information:**
- Your email address
- Cloudflare API Token (Create here)
    - Required permissions: `Zone - DNS - Edit`
- Cloudflare Zone ID (Find here)
- Your domain name (e.g., example.com)
- Your subdomain (optional, e.g., api.example.com)

#### 4. Launch the Server

The `launch.sh` script starts your application server.
```bash
admin/launch.sh
```
**Note**: Run this script every time you need to start or restart the server.

### Quick Start

For first-time deployment:

```bash
# 1. Switch to root
sudo su root

# 2. Grant permissions
chmod u+x admin/cert.sh admin/launch.sh

# 3. Deploy certificate (one-time setup)
admin/cert.sh

# 4. Launch server
admin/launch.sh
```

For subsequent server restarts:
```bash
sudo su root
admin/launch.sh
```


### Certificate Auto-Renewal

SSL certificates are automatically renewed by acme.sh. The certificates will be renewed 60 days before expiration and Nginx will be reloaded automatically.
