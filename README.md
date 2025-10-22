## Usage Guide

### Option 1: First Time Deployment (Full Setup)
Run this for complete initial setup including dependencies, SSL certificate, and server launch.

```bash
sudo su root
chmod u+x admin/setup.sh
admin/setup.sh
# Select option 1
```

### Option 2: Deploy SSL Certificate Only
Run this to install and configure SSL certificate only.

```bash
sudo su root
admin/setup.sh
# Select option 2
```

### Option 3: Launch Server Only
Run this to start or restart the server (requires previous setup).

```bash
sudo su root
admin/setup.sh
# Select option 3
```

**Note**: Option 3 requires that you have already run Option 1 or 2 at least once.