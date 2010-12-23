@echo off
sc stop DrvHide
sc delete DrvHide
del C:\Windows\system32\drivers\DrvHide.sys
pause
