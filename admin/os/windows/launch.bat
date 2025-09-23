@echo off
setlocal

echo Changing to the target directory...
cd ../../../

echo Activating virtual environment...
call .\.venv\Scripts\activate.bat

echo Generating key pair...
python admin\create_key_pair.py

echo Starting LiteLLM Proxy Server...
litellm --config config.yaml --port 4000