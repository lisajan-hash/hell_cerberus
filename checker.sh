#!/bin/bash
# Usage: ./trace_and_hunt_json.sh "command to trace" outputfile

if [ $# -lt 2 ]; then
  echo "Usage: $0 \"command with args\" outputfile"
  exit 1
fi

CMD="$1"
OUTFILE="$2"


SYSCALLS="setsockopt|connect|execve|system|fork|clone|accept|bind|listen|socket|sendto|recvfrom|sendmsg|recvmsg|ptrace|chmod|chown|unlink|rename|mmap|kill|open|write|read|creat|dup|pipe|mount|umount"
PERSISTENCE_CMDS="nc|netcat|bash -i|/bin/bash -i|/dev/tcp/|/dev/udp/|curl|wget|python -c.*socket|perl -e.*socket|socat|crontab|cron|systemd|service|rc\.local|atd|init\.d|bash -c|nohup|disown|tmux|screen|ssh|dropbear|reverse shell|startup|autorun"
PATTERNS="$SYSCALLS|$PERSISTENCE_CMDS"


strace -e trace=%network,%file -f -o "$OUTFILE" bash -c "$CMD"


suspicious_activity=$(grep -E "$PATTERNS" "$OUTFILE" | sort | uniq | sed 's/"/\\"/g' | awk '{print "    \"" $0 "\","}')
ip_addresses=$(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$OUTFILE" | sort | uniq | awk '{print "    \"" $0 "\","}')
domains=$(grep -Eo '([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}' "$OUTFILE" | grep -vE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | sort | uniq | awk '{print "    \"" $0 "\","}')
rev_shells=$(grep -Ei "$PERSISTENCE_CMDS" "$OUTFILE" | sort | uniq | sed 's/"/\\"/g' | awk '{print "    \"" $0 "\","}')


trim_comma() { sed '$s/,$//'; }


echo "{" > findings.json
echo "  \"suspicious_activity\": [" >> findings.json
echo "$suspicious_activity" | trim_comma >> findings.json
echo "  ]," >> findings.json

echo "  \"ip_addresses\": [" >> findings.json
echo "$ip_addresses" | trim_comma >> findings.json
echo "  ]," >> findings.json

echo "  \"domains\": [" >> findings.json
echo "$domains" | trim_comma >> findings.json
echo "  ]," >> findings.json

echo "  \"reverse_shell_or_persistence\": [" >> findings.json
echo "$rev_shells" | trim_comma >> findings.json
echo "  ]" >> findings.json
echo "}" >> findings.json

echo "Results saved in findings.json"
