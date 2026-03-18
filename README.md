# POX Load Balancer Controller

This POX controller application implements a load balancer that queries servers for their load and distributes traffic accordingly.

## Architecture

### Components

1. **POX Controller** ([load_balancer.py](controller/pox/load_balancer.py))
   - Queries servers every 5 seconds for their current load
   - Distributes incoming traffic to the least-loaded server
   - Maintains client-to-server session persistence
   - Provides a virtual IP (20.0.1.100) for load-balanced services

2. **Load Monitor Service** ([load_monitor.py](shared/load_monitor.py))
   - Runs on each server (s1, s2, s3)
   - HTTP server on port 8080
   - Endpoints:
     - `GET /load` - Returns current system load
     - `GET /health` - Returns health status

### Network Topology

```
Clients (h1, h2, h3)  ----[Network D]----
                                          \
                                           \
                                            [r1 - OpenFlow Switch]
                                           /                      \
                                          /                        \
Servers (s1, s2) ----[Network B]--------                            [Network G]----Controller
Server (s3) ---------[Network C]--------                                          
```

## How It Works

1. **Load Monitoring**: The controller periodically queries each server via HTTP to get their current system load
2. **Load Balancing**: When a client tries to connect to the virtual IP (20.0.1.100), the controller:
   - Selects the least-loaded available server
   - Installs OpenFlow rules to rewrite packets
   - Maps the client to the selected server (session persistence)
3. **Traffic Routing**: 
   - Client → Virtual IP traffic is redirected to the selected server
   - Server → Client traffic is rewritten to appear from the virtual IP

## Testing the Load Balancer

### Start the Environment
```bash
kathara lstart
```

### Test Load Monitoring
From the controller or any host with network access:
```bash
# Check server loads
curl http://20.0.0.1:8080/load
curl http://20.0.0.2:8080/load
curl http://30.0.0.1:8080/load
```

### Test Load Balancing
From a client (h1, h2, or h3):
```bash
# All requests to virtual IP should be distributed
ping 20.0.1.100
# or try HTTP requests if you set up a web service
curl http://20.0.1.100:8080
```

### View Controller Logs
```bash
# Connect to controller
kathara connect controller

# View POX logs (they appear in the terminal)
# Look for messages like:
# "Querying server loads..."
# "Server 20.0.0.1 load: 0.15"
# "Selected server 20.0.0.1 with load 0.15"
```

## Configuration

### Modify Server Pool
Edit [load_balancer.py](controller/pox/load_balancer.py):
```python
SERVERS = [
    {"ip": "20.0.0.1", "mac": "00:00:00:00:01:01", "port": 8080, "load": 0},
    {"ip": "20.0.0.2", "mac": "00:00:00:00:01:02", "port": 8080, "load": 0}
]
```

### Change Virtual IP
```python
VIRTUAL_IP = "20.0.1.100"
VIRTUAL_MAC = EthAddr("00:00:00:00:00:FF")
```

### Adjust Polling Interval
In the `__init__` method:
```python
Timer(5, self._query_server_loads, recurring=True)  # Query every 5 seconds
```

## Features

- **Dynamic Load Balancing**: Distributes traffic based on real-time server load
- **Health Monitoring**: Detects unavailable servers (load = 999 on query failure)
- **Session Persistence**: Clients maintain connection to the same server
- **Virtual IP**: Provides a single entry point for clients
- **Automatic Failover**: Redirects traffic away from failed servers

## Future Enhancements

- Add weighted load balancing algorithms
- Implement health check endpoints
- Add support for multiple virtual IPs
- Implement least-connections algorithm
- Add metrics collection and reporting
