#!/usr/bin/env python3

import ssl, socket, sys, time, hashlib, struct, json, os

if "-h" in sys.argv or "--help" in sys.argv:
    print("Usage: ssl_server.py [--debug] [port] [outfile]")
    print("  port     Port to listen on (default: 5200)")
    print("  outfile  File to write received data to (default: 'received')")
    print("  --debug  Enable debug output")
    print("  -h       Show this help message")
    sys.exit(0)

debug   = "--debug" in sys.argv
args    = [a for a in sys.argv[1:] if a != "--debug"]

port    = int(args[0]) if len(args) > 0 else 5200
outfile = args[1] if len(args) > 1 else "received"

WINDOW_SIZE = 64

def dbg(msg):
    if debug:
        print(f"[DEBUG] {msg}", flush=True)

def send_msg(ssock, obj):
    data = json.dumps(obj).encode()
    ssock.sendall(struct.pack("!I", len(data)) + data)

def recv_msg(ssock):
    raw = ssock.recv(4)
    if not raw:
        return None
    length = struct.unpack("!I", raw)[0]
    data = b""
    while len(data) < length:
        chunk = ssock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return json.loads(data)

def recv_exact(ssock, n):
    buf = b""
    while len(buf) < n:
        chunk = ssock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf += chunk
    return buf

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("cert.pem", "key.pem")

dbg(f"Server starting on port {port}")

with socket.socket() as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(1)
    print(f"Listening on port {port}...", flush=True)

    conn, addr = sock.accept()
    dbg(f"TCP connection accepted from {addr}")

    with ctx.wrap_socket(conn, server_side=True) as ssock:
        cipher = ssock.cipher()
        print(f"Connection from {addr}  [{cipher[0]} / {cipher[1]}]", flush=True)
        dbg("TLS handshake complete")

        dbg("Waiting for client first message...")
        first4  = recv_exact(ssock, 4)
        length  = struct.unpack("!I", first4)[0]

        if length > 0 and length < 65536:
            # SCP mode
            dbg(f"SCP mode detected (msg length={length})")
            raw = b""
            while len(raw) < length:
                chunk = ssock.recv(length - len(raw))
                if not chunk:
                    break
                raw += chunk
            meta = json.loads(raw)

            filename   = meta["filename"]
            filesize   = meta["filesize"]
            chunk_size = meta["chunk_size"]
            num_chunks = meta["num_chunks"]
            client_md5 = meta["md5"]

            print(f"\n  File:       {filename}")
            print(f"  Size:       {filesize/1e9:.3f} GB ({filesize:,} bytes)")
            print(f"  Chunks:     {num_chunks} x {chunk_size/1024:.0f} KB")
            print(f"  Client MD5: {client_md5}", flush=True)

            dbg(f"Sending ready ACK with window={WINDOW_SIZE}...")
            send_msg(ssock, {"status": "ready", "window": WINDOW_SIZE})
            dbg("Ready ACK sent, starting data receive...")

            hasher = hashlib.md5()
            total  = 0
            start  = time.perf_counter()

            with open(outfile, "wb") as f:
                for chunk_idx in range(num_chunks):
                    dbg(f"Waiting for chunk {chunk_idx}...")
                    raw_len = recv_exact(ssock, 4)
                    clen    = struct.unpack("!I", raw_len)[0]
                    chunk   = recv_exact(ssock, clen)
                    f.write(chunk)
                    hasher.update(chunk)
                    total += len(chunk)
                    dbg(f"Chunk {chunk_idx} received ({len(chunk)} bytes)")

                    if (chunk_idx + 1) % WINDOW_SIZE == 0 or chunk_idx == num_chunks - 1:
                        elapsed_so_far = time.perf_counter() - start
                        gbps = (total * 8 / 1e9) / elapsed_so_far if elapsed_so_far > 0 else 0
                        pct  = total / filesize * 100
                        #print(f"  {total/1e9:.2f} GB / {filesize/1e9:.2f} GB ({pct:.1f}%)"
                        #      f"  |  avg: {gbps:.2f} Gbps", flush=True)
                        dbg(f"Sending ACK {chunk_idx+1}/{num_chunks}")
                        send_msg(ssock, {"ack": chunk_idx + 1})

            elapsed    = time.perf_counter() - start
            server_md5 = hasher.hexdigest()
            match      = server_md5 == client_md5

            dbg("Transfer complete, sending checksum result...")
            send_msg(ssock, {
                "status": "complete",
                "md5":    server_md5,
                "match":  match,
                "bytes":  total
            })
            dbg("Checksum result sent")

            print(f"\n--- Transfer Summary (SCP mode) ---")
            print(f"  File:       {outfile}")
            print(f"  Cipher:     {cipher[0]} / {cipher[1]}")
            print(f"  Received:   {total:,} bytes ({total/1e9:.3f} GB)")
            print(f"  Time:       {elapsed:.3f} sec")
            print(f"  Rate:       {total/1e6/elapsed:.2f} MB/s  ({total*8/1e9/elapsed:.2f} Gbps)")
            print(f"  Server MD5: {server_md5}")
            print(f"  Checksum:   {'OK' if match else 'MISMATCH !!!'}")

        else:
            # Raw mode
            dbg("Raw mode detected")
            total = 0
            start = time.perf_counter()

            with open(outfile, "wb") as f:
                f.write(first4)
                total += len(first4)
                while True:
                    try:
                        chunk = ssock.recv(65536)
                        if not chunk:
                            break
                        f.write(chunk)
                        total += len(chunk)
                    except ssl.SSLEOFError:
                        break

            elapsed = time.perf_counter() - start
            print(f"\n--- Transfer Summary (raw mode) ---")
            print(f"  File:     {outfile}")
            print(f"  Cipher:   {cipher[0]} / {cipher[1]}")
            print(f"  Received: {total:,} bytes ({total/1e9:.3f} GB)")
            print(f"  Time:     {elapsed:.3f} sec")
            print(f"  Rate:     {total/1e6/elapsed:.2f} MB/s  ({total*8/1e9/elapsed:.2f} Gbps)")

