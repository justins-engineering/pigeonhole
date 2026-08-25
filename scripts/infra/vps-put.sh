#!/usr/bin/env bash
# Copies one local file to a host over ssh's stdin and reports success only
# once the remote sha256 matches the local one.
#
#   scripts/infra/vps-put.sh <local-file> <user@host> <remote-path>
#
# Why not scp or rsync: the VPS silently drops new port-22 connections past
# six a minute, so every command that runs there wants to share one
# connection. This opens (or reuses) a control master and leaves it open
# for ten minutes, so the runbook's follow-on ssh commands ride the same
# connection instead of each spending one against that throttle.
#
# The remote path must be writable by the ssh user. Installing into a
# root-owned location is a separate `sudo install` over the same
# connection, so the transfer itself never runs as root and the file lands
# 0600 until then.
set -euo pipefail

if [ $# -ne 3 ]; then
  echo "usage: $0 <local-file> <user@host> <remote-path>" >&2
  exit 64
fi
local_file=$1
host=$2
remote_path=$3

if [ ! -r "$local_file" ]; then
  echo "$local_file: not readable" >&2
  exit 66
fi

ssh_opts=(
  -o ControlMaster=auto
  -o ControlPath="${VPS_PUT_CONTROL_PATH:-$HOME/.ssh/cm-%r@%h:%p}"
  -o ControlPersist=10m
  -o BatchMode=yes
)

local_sum=$(sha256sum "$local_file" | cut -d' ' -f1)
size=$(stat -c %s "$local_file")

# The checksum is taken from the bytes that landed on disk, not from what
# was sent, which is the only reading that proves the transfer.
# shellcheck disable=SC2029  # the remote path is meant to expand here
remote_sum=$(ssh "${ssh_opts[@]}" "$host" \
  "umask 077 && cat > '$remote_path' && sha256sum '$remote_path' | cut -d' ' -f1" \
  < "$local_file")

if [ "$remote_sum" != "$local_sum" ]; then
  echo "checksum mismatch: local $local_sum remote $remote_sum" >&2
  exit 1
fi
echo "$remote_path on $host: $size bytes, sha256 $local_sum"
