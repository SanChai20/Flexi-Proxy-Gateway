@echo off
setlocal

echo Changing to the target directory...
cd ../../../

echo Checking if virtual environment already exists...
if exist .venv (
    echo .venv already exists, skipping creation.
) else (
    echo Creating Python virtual environment...
    py -m venv .venv
)

echo Activating virtual environment...
call .\.venv\Scripts\activate.bat

echo Installing dependencies...
pip install -r requirements-windows.txt

echo Configuring environment file...
if not exist .env (
    echo Copying .env.example to .env...
    copy .env.example .env
) else (
    echo .env already exists, skipping copy.
)

echo Opening .env file for editing...
start notepad .env

:confirm_env
set /p user_confirm=Have you finished editing the .env file? (y/n): 
if /i "%user_confirm%"=="y" (
    echo Proceeding with setup...
) else (
    echo Please finish editing the .env file.
    goto confirm_env
)

echo Generating key pair...
python admin\create_key_pair.py

echo Starting LiteLLM Proxy Server...
litellm --config config.yaml --port 4000