#!/usr/bin/env python3

import ssl, socket, sys, time, threading, hashlib, struct, json, os

if "-h" in sys.argv or "--help" in sys.argv:
    print("Usage: ssl_client.py [--scp] [--debug] <host> [port] [infile]")
    print("  host     Remote host to connect to")
    print("  port     Port to connect to (default: 5200)")
    print("  infile   File to send (default: stdin)")
    print("  --scp    Emulate SCP behavior (metadata handshake + windowed ACKs)")
    print("  --debug  Enable debug output")
    print("  -h       Show this help message")
    sys.exit(0)

scp_mode = "--scp"   in sys.argv
debug    = "--debug" in sys.argv
args     = [a for a in sys.argv[1:] if a not in ("--scp", "--debug")]

if len(args) < 1:
    print("Error: host is required. Use -h for help.")
    sys.exit(1)

host   = args[0]
port   = int(args[1]) if len(args) > 1 else 5200
infile = args[2] if len(args) > 2 else None

CHUNK_SIZE  = 32768           # 32KB per SSL chunk (SCP style)
READ_SIZE   = 100 * 1024 * 1024  # 100MB read buffer

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

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

# Get file size without reading it
if infile:
    total = os.path.getsize(infile)
    dbg(f"File size: {total/1e9:.3f} GB")
else:
    total = 0  # unknown for stdin

if scp_mode:
    # Must compute MD5 up front — read whole file once just for that
    dbg("Computing MD5 (pre-read)...")
    hasher = hashlib.md5()
    with open(infile, "rb") as f:
        while True:
            buf = f.read(READ_SIZE)
            if not buf:
                break
            hasher.update(buf)
    md5      = hasher.hexdigest()
    filename = os.path.basename(infile) if infile else "stdin"
    num_chunks = (total + CHUNK_SIZE - 1) // CHUNK_SIZE
    print(f"SCP mode  |  {filename}  |  MD5: {md5}", flush=True)
    dbg(f"MD5 complete: {md5}  chunks: {num_chunks}")

# Shared progress state
bytes_sent = 0
done       = False

def progress_reporter(start_time):
    last_bytes = 0
    last_time  = start_time
    while not done:
        time.sleep(1)
        now            = time.perf_counter()
        current        = bytes_sent
        interval_bytes = current - last_bytes
        interval_time  = now - last_time
        elapsed        = now - start_time
        overall_gbps   = (current * 8 / 1e9) / elapsed if elapsed > 0 else 0
        interval_gbps  = (interval_bytes * 8 / 1e9) / interval_time if interval_time > 0 else 0
        pct            = (current / total * 100) if total else 0
        print(f"  {current/1e9:.2f} GB / {total/1e9:.2f} GB ({pct:.1f}%)"
              f"  |  interval: {interval_gbps:.2f} Gbps"
              f"  |  avg: {overall_gbps:.2f} Gbps",
              flush=True)
        last_bytes = current
        last_time  = now

dbg(f"Connecting to {host}:{port}...")
with socket.create_connection((host, port)) as sock:
    with ctx.wrap_socket(sock) as ssock:
        cipher = ssock.cipher()
        print(f"Connected to {host}:{port}  [{cipher[0]} / {cipher[1]}]", flush=True)
        dbg("TLS handshake complete")

        if scp_mode:
            dbg("Sending metadata...")
            send_msg(ssock, {
                "filename":   filename,
                "filesize":   total,
                "chunk_size": CHUNK_SIZE,
                "num_chunks": num_chunks,
                "md5":        md5
            })
            dbg("Metadata sent, waiting for server ready...")
            ready       = recv_msg(ssock)
            dbg(f"Server ready response: {ready}")
            WINDOW_SIZE = ready["window"]
            print(f"Server ready  (window: {WINDOW_SIZE} chunks)\n", flush=True)

            start      = time.perf_counter()
            reporter   = threading.Thread(target=progress_reporter, args=(start,), daemon=True)
            reporter.start()

            chunk_idx  = 0
            fh         = open(infile, "rb") if infile else sys.stdin.buffer
            try:
                while True:
                    read_buf = fh.read(READ_SIZE)
                    if not read_buf:
                        break
                    dbg(f"Read {len(read_buf)/1e6:.0f} MB block from disk")

                    # Slice the read buffer into CHUNK_SIZE pieces and send
                    offset = 0
                    while offset < len(read_buf):
                        chunk = read_buf[offset:offset + CHUNK_SIZE]
                        offset += CHUNK_SIZE
                        dbg(f"Sending chunk {chunk_idx} ({len(chunk)} bytes)...")
                        ssock.sendall(struct.pack("!I", len(chunk)) + chunk)
                        bytes_sent += len(chunk)
                        dbg(f"Chunk {chunk_idx} sent")

                        if (chunk_idx + 1) % WINDOW_SIZE == 0 or bytes_sent == total:
                            dbg(f"Waiting for ACK after chunk {chunk_idx+1}/{num_chunks}...")
                            ack = recv_msg(ssock)
                            dbg(f"Got ACK: {ack}")
                            if ack.get("ack") != chunk_idx + 1:
                                print(f"ERROR: expected ACK {chunk_idx+1}, got {ack}")
                                sys.exit(1)
                        chunk_idx += 1
            finally:
                if infile:
                    fh.close()

            done    = True
            elapsed = time.perf_counter() - start

            dbg("All chunks sent, waiting for checksum result...")
            result = recv_msg(ssock)
            dbg(f"Checksum result: {result}")
            try:
                ssock.unwrap()
            except ssl.SSLEOFError:
                pass

            print(f"\n--- Transfer Summary (SCP mode) ---")
            print(f"  File:       {filename}")
            print(f"  Cipher:     {cipher[0]} / {cipher[1]}")
            print(f"  Sent:       {total:,} bytes ({total/1e9:.3f} GB)")
            print(f"  Time:       {elapsed:.3f} sec")
            print(f"  Rate:       {total/1e6/elapsed:.2f} MB/s  ({total*8/1e9/elapsed:.2f} Gbps)")
            print(f"  Client MD5: {md5}")
            print(f"  Server MD5: {result['md5']}")
            print(f"  Checksum:   {'OK' if result['match'] else 'MISMATCH !!!'}")

        else:
            # Raw mode — stream in 100MB blocks, send in 1MB chunks
            RAW_CHUNK = 1024 * 1024
            start     = time.perf_counter()
            reporter  = threading.Thread(target=progress_reporter, args=(start,), daemon=True)
            reporter.start()

            fh = open(infile, "rb") if infile else sys.stdin.buffer
            try:
                while True:
                    read_buf = fh.read(READ_SIZE)
                    if not read_buf:
                        break
                    dbg(f"Read {len(read_buf)/1e6:.0f} MB block from disk")
                    offset = 0
                    while offset < len(read_buf):
                        chunk = read_buf[offset:offset + RAW_CHUNK]
                        offset += RAW_CHUNK
                        ssock.sendall(chunk)
                        bytes_sent += len(chunk)
            finally:
                if infile:
                    fh.close()

            try:
                ssock.unwrap()
            except ssl.SSLEOFError:
                pass
            finally:
                done    = True
                elapsed = time.perf_counter() - start

            print(f"\n--- Transfer Summary (raw mode) ---")
            print(f"  File:     {infile or 'stdin'}")
            print(f"  Cipher:   {cipher[0]} / {cipher[1]}")
            print(f"  Sent:     {total:,} bytes ({total/1e9:.3f} GB)")
            print(f"  Time:     {elapsed:.3f} sec")
            print(f"  Rate:     {total/1e6/elapsed:.2f} MB/s  ({total*8/1e9/elapsed:.2f} Gbps)")

