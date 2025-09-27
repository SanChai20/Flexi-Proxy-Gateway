#!/bin/bash
set -e

echo "Changing to the target directory..."
cd ../../../

echo "Checking if virtual environment already exists..."
if [ -d ".venv" ]; then
    echo ".venv already exists, skipping creation."
else
    echo "Creating Python virtual environment..."
    python3 -m venv .venv
fi

echo "Activating virtual environment..."
source .venv/bin/activate

echo "Installing dependencies..."
pip install -r requirements-linux.txt  

echo "Configuring environment file..."
if [ ! -f ".env" ]; then
    echo "Copying .env.example to .env..."
    cp .env.example .env
else
    echo ".env already exists, skipping copy."
fi

# 打开 .env 文件进行编辑
# Linux 上可使用 nano/vim/code 等，根据你系统选择
if command -v nano >/dev/null 2>&1; then
    nano .env
elif command -v vi >/dev/null 2>&1; then
    vi .env
else
    echo "Please manually edit the .env file using your preferred editor."
fi

# 等待用户确认编辑完成
while true; do
    read -p "Have you finished editing the .env file? (y/n): " user_confirm
    case "$user_confirm" in
        [Yy]* ) break ;;
        [Nn]* ) echo "Please finish editing the .env file." ;;
        * ) echo "Please answer y or n." ;;
    esac
done

echo "Generating key pair..."
python admin/create_key_pair.py

echo "Starting LiteLLM Proxy Server..."
litellm --config config.yaml --port 4000