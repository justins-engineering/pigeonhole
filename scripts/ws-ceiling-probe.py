#!/usr/bin/env python3
"""Measures how many concurrent device WebSocket connections one source
address can hold against dovecote's edge.

The bridge holds one such socket per live MQTT session (it is the session's
authentication, its shadow feed, and the QoS 0 telemetry fast path), so a
per-source ceiling below the broker's own connection ceiling would cap the
fleet a single broker instance can serve, and the push design would have to
change. The number this prints is what that question gets answered with.

Only the upgrade is exercised: a ceiling, if one exists, is imposed on the
connection, not on the frames. Received bytes are drained and discarded, so
the server's snapshot-on-accept frame does not stall a socket.

Credentials come from a file of "<pigeon_id> <token>" lines and are never
printed. One connection needs one pigeon: the Durable Object closes an
older socket when a new one arrives for the same pigeon.
"""

import argparse
import asyncio
import base64
import os
import ssl
import sys
import time


async def open_socket(host, port, pigeon_id, token, ctx):
  """Performs the WebSocket upgrade and returns the open streams, or raises."""
  reader, writer = await asyncio.open_connection(host, port, ssl=ctx, server_hostname=host)
  key = base64.b64encode(os.urandom(16)).decode()
  request = (
    f"GET /device/pigeons/{pigeon_id}/ws HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    f"Authorization: Bearer {token}\r\n"
    "\r\n"
  )
  writer.write(request.encode())
  await writer.drain()

  status_line = await asyncio.wait_for(reader.readline(), timeout=30)
  status = status_line.decode(errors="replace").strip()
  while True:
    line = await asyncio.wait_for(reader.readline(), timeout=30)
    if line in (b"\r\n", b"\n", b""):
      break
  if " 101 " not in status:
    writer.close()
    raise RuntimeError(status or "no status line")
  return reader, writer


async def drain(reader):
  """Keeps the receive buffer empty so a held socket never backs up."""
  try:
    while await reader.read(4096):
      pass
  except Exception:
    pass


async def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("--host", required=True, help="dovecote host, no scheme")
  parser.add_argument("--port", type=int, default=443)
  parser.add_argument("--credentials", required=True, help="file of '<pigeon_id> <token>' lines")
  parser.add_argument("--target", type=int, default=0, help="0 means every credential in the file")
  parser.add_argument("--batch", type=int, default=16, help="connections opened in parallel")
  parser.add_argument("--hold", type=int, default=60, help="seconds to hold the open set")
  args = parser.parse_args()

  credentials = []
  with open(args.credentials) as handle:
    for line in handle:
      parts = line.split()
      if len(parts) == 2:
        credentials.append((parts[0], parts[1]))
  if args.target:
    credentials = credentials[: args.target]
  if not credentials:
    print("no credentials", file=sys.stderr)
    return 1

  ctx = ssl.create_default_context()
  held = []
  drains = []
  failures = []
  started = time.monotonic()

  for start in range(0, len(credentials), args.batch):
    batch = credentials[start : start + args.batch]
    results = await asyncio.gather(
      *(open_socket(args.host, args.port, pid, token, ctx) for pid, token in batch),
      return_exceptions=True,
    )
    for (pid, _), result in zip(batch, results):
      if isinstance(result, Exception):
        failures.append((pid, f"{type(result).__name__}: {result}"))
      else:
        reader, writer = result
        held.append(writer)
        drains.append(asyncio.create_task(drain(reader)))
    print(
      f"opened {len(held)}/{len(credentials)}  failed {len(failures)}"
      f"  elapsed {time.monotonic() - started:.1f}s",
      flush=True,
    )
    if failures and len(failures) >= 8:
      print("stopping: eight consecutive-window failures", flush=True)
      break

  peak = len(held)
  print(f"peak concurrent upgrades: {peak}", flush=True)
  if failures:
    print(f"first failures: {failures[:5]}", flush=True)

  print(f"holding {peak} sockets for {args.hold}s", flush=True)
  await asyncio.sleep(args.hold)

  still_open = sum(1 for writer in held if not writer.is_closing())
  print(f"still open after {args.hold}s: {still_open}/{peak}", flush=True)

  for writer in held:
    writer.close()
  for task in drains:
    task.cancel()
  return 0


if __name__ == "__main__":
  sys.exit(asyncio.run(main()))
