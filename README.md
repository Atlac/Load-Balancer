# SDN Load Balancer with POX Controller

This project implements a Software-Defined Networking (SDN) load balancer using POX controller and OpenFlow. It distributes TCP traffic across multiple backend servers based on connection count and calculates server utilization metrics.

## Architecture

### Components

1. **POX Controller** ([controller/pox/ext/lb.py](controller/pox/ext/lb.py))
   - OpenFlow controller that manages packet routing
   - Implements least-loaded server selection algorithm
   - Tracks active TCP connections per server
   - Calculates server utilization: ρ(t) = (n × d) / b
     - n: number of active connections
     - d: demand per connection (100,000 bps)
     - b: server capacity (1,000,000 bps)
   - Logs server metrics every 5 seconds

2. **Backend Servers** ([shared/server.py](shared/server.py))
   - TCP servers listening on port 6653
   - Handle incoming client connections
   - Log received messages and connection count

3. **Client Simulator** ([shared/client.py](shared/client.py))
   - Generates traffic to the service IP
   - Sends 10 packets per connection repeatedly

### Network Topology

```
     Network A (10.0.0.0/16)              Network B (20.0.0.0/16)
    ┌────────────────────┐               ┌─────────────────────┐
    │                    │               │                     │
    │  h1 10.0.0.1       │               │  server1 20.0.0.1   │
    │  h2 10.0.0.2       │               │  server2 20.0.0.2   │
    │  h3 10.0.0.3       │               │  server3 20.0.0.3   │
    │                    │               │                     │
    └──────┬─────────────┘               └──────┬──────────────┘
           │                                    │
           │                                    │
           └────────┬───────────────────────────┘
                    │
              ┌─────▼──────┐
              │            │
              │  s1        │  OpenFlow Switch
              │  (OVS)     │  Gateway: 10.0.1.1, 20.0.1.1
              │            │
              └─────┬──────┘
                    │
                    │ Network G (50.0.1.0/16)
                    │
              ┌─────▼──────┐
              │ controller │  POX Controller
              │ 50.0.1.4   │  OpenFlow port: 6653
              └────────────┘
```

## How It Works

The load balancer operates at Layer 3/4 using OpenFlow to dynamically route traffic:

1. **Connection Establishment**:
   - Clients connect to service IP **20.0.1.2:6653**
   - Controller intercepts packets via `PACKET_IN` messages
   - For each new TCP connection, selects the least-loaded server

2. **Load Calculation**:
   - Tracks active TCP connections per server
   - Calculates utilization: ρ(t) = (connections × 100,000) / 1,000,000
   - Logs metrics every 5 seconds

3. **Traffic Rewriting**:
   - **Client → Server**: Rewrites destination from 20.0.1.2 to selected server IP
   - **Server → Client**: Rewrites source from server IP back to 20.0.1.2
   - Maintains session state per TCP connection

4. **Connection Tracking**:
   - Maps (client_ip, src_port) to selected server
   - Decrements load counter on FIN/RST flags
   - No HTTP layer involved - pure TCP load balancing

## Getting Started

### Prerequisites
- Kathara (network emulation environment)
- POX controller (included in kathara/pox image)

### Start the Environment
```bash
cd Load-Balancer
kathara lstart
```

This starts:
- 3 clients (h1, h2, h3) that continuously send traffic
- 3 servers (server1, server2, server3) listening on port 6653
- 1 OpenFlow switch (s1) configured with Open vSwitch
- 1 POX controller running the load balancer

### View Controller Logs
```bash
# Connect to controller
kathara connect controller

# Start POX with the load balancer module
./pox/pox.py samples.pretty_log openflow.of_01 --port=6653 lb

# You'll see logs like:
# INFO:iplb:Server 20.0.0.1: active_connections=2, rho(t)=0.2000
# INFO:iplb:Forwarded 10.0.0.1 -> 20.0.1.2 via 20.0.0.1 (n=3, rho=0.3000)
```

### View Server Activity
```bash
# Connect to a server
kathara connect server1

# Server automatically runs, you'll see:
# [+] Server listening on 0.0.0.0:6653
# [+] New connection from ('10.0.0.1', 54321)
# [('10.0.0.1', 54321)] Received: Packet 1
# [load_monitor] Current load: 3
```

### Stop the Environment
```bash
kathara lclean
```

## Configuration

### Modify Server Pool
Edit [controller/pox/ext/lb.py](controller/pox/ext/lb.py) line 232:
```python
iplb(event.connection, SERVICE_IP, ["20.0.0.1", "20.0.0.2", "20.0.0.3"])
```

### Change Service IP/Port
Edit [controller/pox/ext/lb.py](controller/pox/ext/lb.py):
```python
SERVICE_IP = IPAddr("20.0.1.2")  # The virtual IP clients connect to
```

And update [shared/client.py](shared/client.py):
```python
SERVER_HOST = '20.0.1.2'
SERVER_PORT = 6653
```

### Adjust Server Capacity
Modify capacity in [controller/pox/ext/lb.py](controller/pox/ext/lb.py):
```python
SERVER_CAPACITY = {
  IPAddr("20.0.0.1"): 1_000_000,  # bps
  IPAddr("20.0.0.2"): 1_000_000,
  IPAddr("20.0.0.3"): 1_000_000,
}
```

### Change Demand per Request
```python
SERVICE_DEMAND = 100_000  # bps per connection
```

## Key Files

- `lab.conf` - Kathara network topology configuration
- `controller/pox/ext/lb.py` - POX load balancer implementation
- `shared/server.py` - TCP server for backend nodes
- `shared/client.py` - Traffic generator client
- `*.startup` - Node initialization scripts
- `s1.startup` - Configures Open vSwitch and connects to controller

## Features

- **Connection-Based Load Balancing**: Distributes based on active TCP connections
- **Least-Loaded Selection**: Always picks server with lowest utilization
- **Per-Connection Tracking**: Maintains state for each TCP flow
- **Transparent Proxying**: Clients see only the service IP
- **Real-Time Metrics**: Logs server load every 5 seconds
- **Graceful Connection Cleanup**: Tracks FIN/RST to decrement counters

## Algorithm

The load balancer uses a **least-utilization** algorithm:

```
For each new connection:
  for each server s:
    ρ(s) = (active_connections(s) × demand) / capacity(s)

  selected_server = argmin(ρ(s))
  route_connection(client, selected_server)
  active_connections(selected_server) += 1
```

## Limitations

- No health checks - assumes all servers are always available
- No flow table installation - all packets go through controller
- Simple connection counting (doesn't measure actual bandwidth usage)
- No support for UDP or other protocols
- Session persistence per TCP connection only

## Future Enhancements

- Install OpenFlow rules to bypass controller for established flows
- Add server health monitoring
- Implement weighted round-robin algorithm
- Support multiple service IPs
- Add HTTP/HTTPS layer awareness
- Collect and export Prometheus metrics
