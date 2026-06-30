This is a simple program to try to simulate scp performance. The purpose of this program is for performance benchmarks in environments 
where port 22 is blocked, but other higher level ports are open.

## Sample Use

### Server

Generate keys
```
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 30 -nodes -subj "/CN=test"
```
start server
```
ssl_server.py 5200 test.dat
```

### Client

normal mode
```
ssl_client.py sunn-ps-tp.es.net 5200 10G-random.dat
```
scp emulation mode
```
ssl_client.py --scp sunn-ps-tp.es.net 5200 10G-random.dat
```
