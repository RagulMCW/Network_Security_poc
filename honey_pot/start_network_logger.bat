@echo off
REM Start network attack logger in WSL

echo Starting network attack logger...
echo This will log DoS and network-level attacks from rerouted devices

wsl bash /mnt/e/nos/Network_Security_poc/honey_pot/log_network_attacks.sh
