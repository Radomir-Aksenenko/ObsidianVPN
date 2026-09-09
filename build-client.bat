@echo off
setlocal
cd /d "%~dp0"
echo Building Obsidian VPN client CLI...
go build -o bin\obsidian-client.exe .\cmd\client
if errorlevel 1 exit /b 1
echo Building Obsidian VPN server daemon...
go build -o bin\obsidian-server.exe .\cmd\server
if errorlevel 1 exit /b 1
echo Done. Binaries placed in bin\
exit /b 0
