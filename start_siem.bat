@echo off
title SIEM-Lite Enterprise Security Operations Center
color 0A

echo ======================================================================
echo           🛡️  SIEM-Lite Enterprise Security Operations Center
echo ======================================================================
echo.
echo [*] Initializing SQLite Persistent Database...
echo [*] Starting REST API Ingestion Server on http://localhost:8000
echo [*] Starting RFC Syslog UDP Listener on port 1514
echo.

:: Launch browser in parallel
start "" http://localhost:8000

:: Start Python Backend Server
python server\server.py

pause
