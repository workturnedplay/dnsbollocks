@echo off
certutil -dump cert.pem
echo Note, it only works when dnsbollocks is listening on this IP:
certutil -dump cert.pem|findstr "IP Address"
::echo You would have to delete cert.pem if you change the listen_doh IP in the config.json for the cert(and key.pem) to be regenerated and thus to work when a client tries to connect.
echo Running dnsbollocks will auto-regen the cert if the IP or host doesn't match the 'listen_doh' IP(or host) setting from config.json
pause