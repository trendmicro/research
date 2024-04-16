#!/bin/bash

# This script looks for suspicious configuration
# files and binaries related to SSHDoor
# Reference: <our blogpost link here>
# Author: Fernando Merces @ Trend Micro FTR
# Date: 2024-04-03
# Version: 1.0.0

for i in awk find shasum grep; do
	which $i >/dev/null || { echo Required program: $i not found. Aborting...; exit 1; }
done

echo '[+] Checking sshd config files'
for i in $(find / -type f -name sshd_config 2>/dev/null); do
	echo -n "Checking ${i}..."
	grep -qi 'GatewayPorts.*yes' "$i"  && echo ' GatewayPorts configuration found' || echo
done

iocs=(
25fca7e8a65bcdabdad9e4dc41dbb4649dedebdc
605505b8bf167aad873fc700b02cc5a7389d7fe7
b3b0e5f685bce3e22943ad2fe292cb7aa64d4c50
6c8e356c9fed009678842c93685cabf58b8954ad
3a7f6615f5cb341df0cd123c403c4defa3a13e53
67f514337a18ace4fc10a9e3d7836b2ab957853e
26b6e595d6e94863ccf0597a46a6765ce4d0387e
14ad09321b977ee738a1df59710ab765053f40ea
)

echo -e '\n[+] Checking sshd binaries'
for i in $(find / -type f -name sshd 2>/dev/null); do
	echo -n Checking $i...
	hash=$(shasum "${i}" | awk '{print $1}')
	for j in "${iocs[@]}"; do
		[[ $hash == $j ]] && { echo -n " matches a known IOC: ${j}"; break; }
	done
	echo
done
