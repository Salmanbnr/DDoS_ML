# Docker DDoS Attack Simulator - Complete Setup Guide

## 🎯 Overview

This setup allows you to run a DDoS attack simulator from a Docker container that attacks your Windows 11 laptop, enabling you to test your ML-based DDoS detection system with realistic traffic.

## 📋 Prerequisites

### 1. Install Docker Desktop for Windows

1. Download Docker Desktop from: https://www.docker.com/products/docker-desktop/
2. Install Docker Desktop
3. Restart your computer if prompted
4. Start Docker Desktop
5. Verify installation:
   ```cmd
   docker --version
   docker ps
   ```

### 2. Enable Required Settings

In Docker Desktop:
- Settings → General → Enable "Use the WSL 2 based engine" (recommended)
- Settings → Resources → Increase Memory to at least 4GB
- Apply & Restart

## 🔧 Setup Steps

### Step 1: Get Your Windows 11 IP Address

Open Command Prompt:
```cmd
ipconfig
```

Look for "IPv4 Address" under your active network adapter (Wi-Fi or Ethernet).

Example output:
```
Ethernet adapter Ethernet:
   IPv4 Address. . . . . . . . . . . : 192.168.1.100
```

**Note this IP address** - you'll need it!

### Step 2: Configure Firewall

#### Option A: Allow Port in Windows Firewall

1. Open Windows Defender Firewall → Advanced Settings
2. Click "Inbound Rules" → "New Rule"
3. Select "Port" → Next
4. Select "TCP" → Specific local ports: `8050` → Next
5. Select "Allow the connection" → Next
6. Check all profiles → Next
7. Name: "DDoS Detection Dashboard" → Finish

#### Option B: Temporarily Disable Firewall (Testing Only)

```cmd
netsh advfirewall set allprofiles state off
```

**⚠️ Remember to re-enable:**
```cmd
netsh advfirewall set allprofiles state on
```

### Step 3: Start Your Detection System

1. Start your dashboard:
   ```cmd
   cd path\to\detection\system
   python dashboard.py
   ```

2. Verify it's running at: `http://127.0.0.1:8050`

### Step 4: Build Docker Image

Navigate to the docker-ddos-attacker folder:

```cmd
cd path\to\DockerAttackSimulator
docker build -t ddos-attacker .
```

This will create the Docker image with the attack simulator.

### Step 5: Run Attack

#### Option A: Using Batch Script (Easiest)

```cmd
run_docker_attack.bat
```

Follow the prompts to:
- Confirm your IP address
- Select attack type
- Set duration and intensity

#### Option B: Manual Docker Command

```cmd
docker run --rm -it ddos-attacker python3 docker_ddos_attacker.py ^
    --target YOUR_IP_HERE ^
    --port 8050 ^
    --type http ^
    --duration 120 ^
    --intensity medium
```

Replace `YOUR_IP_HERE` with your Windows 11 IP address.

#### Option C: Using Docker Compose

1. Edit `docker-compose.yml` and change `TARGET_IP`:
   ```yaml
   environment:
     - TARGET_IP=192.168.1.100  # Your IP here
   ```

2. Run:
   ```cmd
   docker-compose up
   ```

## 🎮 Attack Types

### 1. HTTP Flood (Recommended for Testing)
```cmd
docker run --rm -it ddos-attacker python3 docker_ddos_attacker.py ^
    --target 192.168.1.100 --type http --duration 120 --intensity medium
```

**Characteristics:**
- Sends many HTTP requests
- Creates multiple connections
- Good for testing web server attacks

### 2. SYN Flood
```cmd
docker run --rm -it ddos-attacker python3 docker_ddos_attacker.py ^
    --target 192.168.1.100 --type syn --duration 120 --intensity medium
```

**Characteristics:**
- Creates incomplete TCP connections
- Exhausts connection table
- Classic DDoS attack

### 3. UDP Flood
```cmd
docker run --rm -it ddos-attacker python3 docker_ddos_attacker.py ^
    --target 192.168.1.100 --type udp --duration 90 --intensity low
```

**Characteristics:**
- High-volume UDP packets
- No connection required
- Very fast attack

### 4. Slowloris
```cmd
docker run --rm -it ddos-attacker python3 docker_ddos_attacker.py ^
    --target 192.168.1.100 --type slowloris --connections 30 --duration 150
```

**Characteristics:**
- Keeps many connections open
- Sends data very slowly
- Low bandwidth attack

## 📊 Intensity Levels

### Low
- 5 threads
- Lower packet rate
- Good for initial testing

### Medium (Recommended)
- 15 threads
- Moderate packet rate
- Balanced for detection testing

### High
- 30 threads
- High packet rate
- Stress testing

## 🔍 Monitoring the Attack

### In Docker Container
You'll see real-time statistics:
```
📊 Time: 45s/120s | Packets: 12,543 | PPS: 278.7 | Conns: 423 | Errors: 12 | Remaining: 75s
```

### In Your Dashboard
- Check `http://127.0.0.1:8050`
- Watch for DDoS detections
- Monitor Active Threats table
- View Detection Timeline

### In Windows Task Manager
- Open Task Manager
- Go to Performance → Network
- You should see increased network activity

## 🛑 Stopping the Attack

### Graceful Stop
Press `Ctrl+C` in the Docker terminal

### Force Stop
```cmd
docker ps
docker stop CONTAINER_ID
```

### Stop All Containers
```cmd
docker stop $(docker ps -q)
```

## 🧪 Testing Workflow

### Complete Test Sequence

1. **Start Detection System:**
   ```cmd
   python dashboard.py
   ```
   Wait for "Starting Dashboard on http://127.0.0.1:8050"

2. **Open Dashboard:**
   Navigate to `http://127.0.0.1:8050` in browser

3. **Click "Start Capture"** in dashboard

4. **Launch Attack:**
   ```cmd
   run_docker_attack.bat
   ```

5. **Monitor Detection:**
   - Watch dashboard for alerts
   - Check detection timeline
   - View active threats

6. **Stop Attack:**
   - Press Ctrl+C or wait for duration
   - Attack stops automatically

7. **Verify Results:**
   - Check detection rate
   - Review blocked IPs
   - Examine detection history

## 📈 Expected Results

### Successful Detection

You should see in your dashboard:
- ✅ Increasing packet count
- ✅ Active flows detected
- ✅ DDoS alerts appearing
- ✅ Source IP (Docker container) in Active Threats
- ✅ High detection rate (>80%)

### Dashboard Alerts

```
🚨 DDoS ATTACK DETECTED!
   Source: 172.17.0.2
   Destination: 192.168.1.100:8050
   Confidence: 92.5%
   Severity: HIGH
```

## 🔧 Troubleshooting

### Issue: "Cannot connect to target"

**Solution:**
1. Verify firewall allows port 8050
2. Check Windows 11 IP is correct
3. Ensure dashboard is running
4. Try: `telnet YOUR_IP 8050` from Docker

### Issue: "No packets detected"

**Solution:**
1. Verify capture is started in dashboard
2. Check network interface in `dashboard.py`
3. Ensure traffic is going to correct IP
4. Check Docker network: `docker network inspect bridge`

### Issue: "Docker build failed"

**Solution:**
```cmd
docker system prune -a
docker build --no-cache -t ddos-attacker .
```

### Issue: "No DDoS detected"

**Solution:**
1. Increase attack intensity
2. Increase duration (>120s)
3. Try different attack types
4. Check model threshold in `ddos_detector.py`
5. Verify features match training data

### Issue: "Too many false positives"

**Solution:**
- Reduce detection threshold
- Increase smoothing window
- Use HTTP flood (most realistic)

## 🔒 Security Notes

### ⚠️ Important Warnings

1. **Only test on your own systems**
2. **Never attack unauthorized targets**
3. **Use isolated network if possible**
4. **Inform other users on your network**
5. **Stop attack immediately if issues occur**

### Legal Disclaimer

This tool is for:
- ✅ Educational purposes
- ✅ Testing YOUR OWN systems
- ✅ Security research
- ✅ ML model validation

Never use for:
- ❌ Attacking others' systems
- ❌ Unauthorized penetration testing
- ❌ Malicious activities

## 📝 Advanced Configuration

### Custom Attack Parameters

Edit `docker_ddos_attacker.py` to customize:

```python
# Adjust thread count
num_threads = 20  # Line ~50

# Modify packet rate
delay_range = (0.05, 0.15)  # Line ~53

# Change request patterns
requests_per_conn = (10, 30)  # Line ~125
```

### Network Configuration

For isolated testing, create a custom Docker network:

```cmd
docker network create --subnet=172.20.0.0/16 ddos-test-net

docker run --rm -it --network ddos-test-net ^
    ddos-attacker python3 docker_ddos_attacker.py ^
    --target 192.168.1.100 --type http
```

## 📚 Additional Resources

### Docker Commands Reference

```cmd
# List images
docker images

# List running containers
docker ps

# View logs
docker logs CONTAINER_ID

# Remove image
docker rmi ddos-attacker

# Clean everything
docker system prune -a
```

### Network Diagnostics

```cmd
# Test connectivity
ping YOUR_IP

# Test port
telnet YOUR_IP 8050

# Check Docker network
docker network ls
docker network inspect bridge
```

## 🎓 Understanding the Output

### Attack Statistics

```
Total Packets: 15,234
Average PPS: 127.8
Total Connections: 1,245
```

- **Packets**: Number of packets sent
- **PPS**: Packets per second (should match training data)
- **Connections**: TCP connections made

### Detection Metrics

In your dashboard, look for:
- **Detection Rate**: % of flows classified as DDoS
- **Confidence**: ML model probability (0-100%)
- **Severity**: LOW, MEDIUM, HIGH, CRITICAL

## 🚀 Quick Start Checklist

- [ ] Docker Desktop installed and running
- [ ] Files created in correct folder structure
- [ ] Windows 11 IP address identified
- [ ] Firewall configured (port 8050 open)
- [ ] Detection system running
- [ ] Dashboard accessible at http://127.0.0.1:8050
- [ ] Capture started in dashboard
- [ ] Docker image built successfully
- [ ] Attack launched and monitored
- [ ] DDoS detections appearing in dashboard

## 📞 Support

If you encounter issues:
1. Check this troubleshooting section
2. Verify all prerequisites
3. Check Docker Desktop logs
4. Ensure Python environment is correct
5. Verify model files are loaded

## 🎉 Success Indicators

You'll know it's working when you see:
1. Docker attack running with no errors
2. Network activity in Task Manager
3. Packets appearing in dashboard
4. DDoS alerts triggering
5. Active threats showing Docker IP
6. Detection timeline updating

Good luck with your DDoS detection testing! 🛡️