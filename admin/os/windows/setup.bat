@echo off
setlocal

echo Changing to the target directory...
cd ../../../

echo Creating Python virtual environment...
py -m venv .venv

echo Activating virtual environment...
call .\.venv\Scripts\activate.bat

echo Installing dependencies...
pip install -r requirements-windows.txt

echo Configuring environment file...
copy .env.example .env

echo Setting environment variable...
set LITELLM_MODE=PRODUCTION

echo Setup complete! The virtual environment is now activated.
pause