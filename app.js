const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const Database = require("better-sqlite3");
const { exec } = require("child_process");
const { promisify } = require("util");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");

const execAsync = promisify(exec);

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

// Security configuration
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-in-production-" + Math.random();
const JWT_EXPIRES_IN = "24h";
const SALT_ROUNDS = 10;

app.use(express.json());
app.use(cookieParser());

// Rate limiting for login attempts
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
    message: { error: "Too many login attempts, please try again later" }
});

// Rate limiting for API
const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 100,
    message: { error: "Too many requests" }
});

/* ============================
   DATABASE SETUP
============================ */
const db = new Database("./ddos.db");

console.log("✓ Database connected");

// Enable WAL mode for better concurrency
db.pragma("journal_mode = WAL");

db.exec(`
    CREATE TABLE IF NOT EXISTS ips (
        ip TEXT PRIMARY KEY,
        requests INTEGER DEFAULT 0,
        bandwidth INTEGER DEFAULT 0,
        threads INTEGER DEFAULT 0,
        blocked INTEGER DEFAULT 0,
        blocked_at INTEGER,
        first_seen INTEGER,
        last_seen INTEGER,
        country TEXT,
        threat_level TEXT DEFAULT 'low'
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS attack_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        timestamp INTEGER,
        requests INTEGER,
        bandwidth INTEGER,
        action TEXT
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY,
        rate_limit_per_minute INTEGER DEFAULT 60,
        max_bandwidth_per_minute INTEGER DEFAULT 1048576,
        auto_block INTEGER DEFAULT 1,
        block_duration INTEGER DEFAULT 3600,
        threat_threshold_medium INTEGER DEFAULT 100,
        threat_threshold_high INTEGER DEFAULT 500,
        threat_threshold_critical INTEGER DEFAULT 1000,
        auto_block_syn_recv INTEGER DEFAULT 50,
        auto_block_high_connections INTEGER DEFAULT 150,
        auto_block_port_scan INTEGER DEFAULT 10,
        auto_block_time_wait INTEGER DEFAULT 300,
        intelligent_blocking INTEGER DEFAULT 1
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        role TEXT DEFAULT 'admin',
        created_at INTEGER,
        last_login INTEGER,
        login_attempts INTEGER DEFAULT 0,
        locked_until INTEGER DEFAULT 0
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        token TEXT UNIQUE,
        ip_address TEXT,
        user_agent TEXT,
        created_at INTEGER,
        expires_at INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
`);

// Insert default settings
const insertSettings = db.prepare("INSERT OR IGNORE INTO settings (id) VALUES (?)");
insertSettings.run(1);

// Create default admin user
const defaultPassword = "admin123";
const hash = bcrypt.hashSync(defaultPassword, SALT_ROUNDS);

const insertUser = db.prepare(`
    INSERT OR IGNORE INTO users (username, password, email, role, created_at) 
    VALUES (?, ?, ?, ?, ?)
`);

try {
    insertUser.run("admin", hash, "admin@localhost", "admin", Date.now());
    console.log("✓ Default admin user ready (username: admin, password: admin123)");
    console.log("⚠️  CHANGE DEFAULT PASSWORD IMMEDIATELY!");
} catch (err) {
    if (!err.message.includes("UNIQUE")) {
        console.error("Error creating default admin:", err);
    }
}

/* ============================
   MEMORY CACHE (FAST LIVE)
============================ */
let liveIPs = {};
let minuteTracker = {};
let settings = {
    rate_limit_per_minute: 60,
    max_bandwidth_per_minute: 1048576,
    auto_block: 1,
    block_duration: 3600,
    threat_threshold_medium: 100,
    threat_threshold_high: 500,
    threat_threshold_critical: 1000,
    auto_block_syn_recv: 50,
    auto_block_high_connections: 150,
    auto_block_port_scan: 10,
    auto_block_time_wait: 300,
    intelligent_blocking: 1
};

let stats = {
    total_requests: 0,
    total_blocked: 0,
    active_connections: 0,
    total_bandwidth: 0,
    total_connections: 0,
    suspicious_ips: 0,
    critical_threats: 0,
    high_threats: 0,
    medium_threats: 0,
    server_load: 0,
    memory_usage: 0,
    total_network_connections: 0,
    established_connections: 0,
    syn_recv_total: 0,
    last_scan: 0
};

/* ============================
   LOAD SETTINGS
============================ */
function loadSettings() {
    try {
        const row = db.prepare("SELECT * FROM settings WHERE id = 1").get();
        if (row) {
            settings = row;
            console.log("✓ Settings loaded");
        }
    } catch (err) {
        console.error("Settings load error:", err);
    }
}
loadSettings();

/* ============================
   REAL-TIME NETWORK MONITORING
============================ */

// Platform detection
const isLinux = process.platform === 'linux';
const isWindows = process.platform === 'win32';

if (isLinux) {
    console.log("✓ Linux detected - Full network monitoring enabled");
} else if (isWindows) {
    console.log("⚠️  Windows detected - Network monitoring disabled (Linux VPS required for full protection)");
} else {
    console.log(`⚠️  ${process.platform} detected - Network monitoring may not work properly`);
}

// Helper function to validate IPv4 addresses
function isValidIPv4(ip) {
    if (!ip || typeof ip !== 'string') return false;
    
    // Check format
    const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    const match = ip.match(ipRegex);
    
    if (!match) return false;
    
    // Check each octet is 0-255
    for (let i = 1; i <= 4; i++) {
        const octet = parseInt(match[i]);
        if (octet < 0 || octet > 255) return false;
    }
    
    // Exclude special IPs
    if (ip === '0.0.0.0' || ip === '127.0.0.1' || ip === '255.255.255.255') return false;
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.')) return false;
    if (ip.startsWith('169.254.')) return false; // Link-local
    if (ip.startsWith('224.') || ip.startsWith('240.')) return false; // Multicast/Reserved
    
    return true;
}

// Enhanced network monitoring with multiple detection methods
async function monitorActiveConnections() {
    if (!isLinux) return {};
    
    try {
        // Method 1: ss command for active connections - filter for IPv4 only
        const { stdout: ssOutput } = await execAsync(`ss -ntu state established 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' | sort | uniq -c | sort -nr | head -100`);
        
        const connections = {};
        const lines = ssOutput.trim().split('\n').filter(line => line.trim());
        
        lines.forEach(line => {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 2) {
                const count = parseInt(parts[0]);
                const ip = parts[1];
                
                if (isValidIPv4(ip)) {
                    connections[ip] = (connections[ip] || 0) + count;
                }
            }
        });
        
        return connections;
    } catch (err) {
        console.error("Connection monitoring error:", err.message);
        return {};
    }
}

// Monitor all connection states (ESTABLISHED, SYN_SENT, SYN_RECV, etc.)
async function monitorAllConnectionStates() {
    if (!isLinux) return {};
    
    try {
        const { stdout } = await execAsync(`ss -ntu 2>/dev/null | awk '{print $1, $5}' | grep -E '^[A-Z]+ [0-9]+\.' | awk '{print $2, $1}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -100`);
        
        const statesByIP = {};
        const lines = stdout.trim().split('\n').filter(line => line.trim());
        
        lines.forEach(line => {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 3) {
                const count = parseInt(parts[0]);
                const ip = parts[1];
                const state = parts[2];
                
                if (ip && !ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('127.')) {
                    if (!statesByIP[ip]) statesByIP[ip] = {};
                    statesByIP[ip][state] = (statesByIP[ip][state] || 0) + count;
                }
            }
        });
        
        return statesByIP;
    } catch (err) {
        return {};
    }
}

// Monitor SYN flood attacks (multiple methods)
async function monitorSynFlood() {
    if (!isLinux) return {};
    
    try {
        const synFlood = {};
        
        // Method 1: Check SYN_RECV state
        const { stdout: synRecv } = await execAsync(`ss -ntu state syn-recv 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\.' | sort | uniq -c | sort -nr | head -50`);
        
        synRecv.trim().split('\n').filter(line => line.trim()).forEach(line => {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 2) {
                const count = parseInt(parts[0]);
                const ip = parts[1];
                if (ip && count > 5) {
                    synFlood[ip] = (synFlood[ip] || 0) + count;
                }
            }
        });
        
        // Method 2: Check SYN_SENT state
        const { stdout: synSent } = await execAsync(`ss -ntu state syn-sent 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\.' | sort | uniq -c | sort -nr | head -50`);
        
        synSent.trim().split('\n').filter(line => line.trim()).forEach(line => {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 2) {
                const count = parseInt(parts[0]);
                const ip = parts[1];
                if (ip && count > 3) {
                    synFlood[ip] = (synFlood[ip] || 0) + count;
                }
            }
        });
        
        return synFlood;
    } catch (err) {
        return {};
    }
}

// Monitor network traffic using netstat as backup
async function monitorNetworkTraffic() {
    if (!isLinux) return {};
    
    try {
        const { stdout } = await execAsync(`netstat -ntu 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\.' | sort | uniq -c | sort -nr | head -100`);
        
        const traffic = {};
        const lines = stdout.trim().split('\n').filter(line => line.trim());
        
        lines.forEach(line => {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 2) {
                const count = parseInt(parts[0]);
                const ip = parts[1];
                
                if (ip && ip !== '0.0.0.0' && ip !== '127.0.0.1' && !ip.startsWith('10.') && !ip.startsWith('192.168.')) {
                    traffic[ip] = count;
                }
            }
        });
        
        return traffic;
    } catch (err) {
        return {};
    }
}

// Detect port scanning with enhanced detection
async function detectPortScanning() {
    if (!isLinux) return {};
    
    try {
        // Count unique ports per IP
        const { stdout } = await execAsync(`ss -ntu 2>/dev/null | awk '{print $5}' | grep -E '^[0-9]+\.' | sort | uniq | awk -F: '{print $1}' | uniq -c | sort -nr | head -50`);
        
        const scanners = {};
        const lines = stdout.trim().split('\n').filter(line => line.trim());
        
        lines.forEach(line => {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 2) {
                const portCount = parseInt(parts[0]);
                const ip = parts[1];
                
                if (portCount > 3 && ip && !ip.startsWith('10.') && !ip.startsWith('192.168.')) {
                    scanners[ip] = portCount;
                }
            }
        });
        
        return scanners;
    } catch (err) {
        return {};
    }
}

// Detect UDP flood attacks
async function detectUDPFlood() {
    if (!isLinux) return {};
    
    try {
        const { stdout } = await execAsync(`ss -nu 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\.' | sort | uniq -c | sort -nr | head -50`);
        
        const udpFlood = {};
        const lines = stdout.trim().split('\n').filter(line => line.trim());
        
        lines.forEach(line => {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 2) {
                const count = parseInt(parts[0]);
                const ip = parts[1];
                
                if (count > 20 && ip) {
                    udpFlood[ip] = count;
                }
            }
        });
        
        return udpFlood;
    } catch (err) {
        return {};
    }
}

// NEW: Advanced SYN_RECV detection using netstat
async function detectSynRecvNetstat() {
    if (!isLinux) return {};
    
    try {
        // Count SYN_RECV connections
        const { stdout: synCount } = await execAsync(`netstat -nat 2>/dev/null | grep SYN_RECV | wc -l`);
        const totalSynRecv = parseInt(synCount.trim()) || 0;
        
        // Get IPs with SYN_RECV state
        const { stdout: synIPs } = await execAsync(`netstat -nat 2>/dev/null | grep SYN_RECV | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr`);
        
        const synRecvData = {
            total: totalSynRecv,
            ips: {}
        };
        
        synIPs.trim().split('\n').filter(line => line.trim()).forEach(line => {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 2) {
                const count = parseInt(parts[0]);
                const ip = parts[1];
                if (ip && count > 3) {
                    synRecvData.ips[ip] = count;
                }
            }
        });
        
        return synRecvData;
    } catch (err) {
        return { total: 0, ips: {} };
    }
}

// NEW: Detect high connection IPs using ss with threshold
async function detectHighConnectionIPs() {
    if (!isLinux) return {};
    
    try {
        const { stdout } = await execAsync(`ss -ntu 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' | sort | uniq -c | awk '$1 > 50 {print $1, $2}'`);
        
        const highConnIPs = {};
        const lines = stdout.trim().split('\n').filter(line => line.trim());
        
        lines.forEach(line => {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 2) {
                const count = parseInt(parts[0]);
                const ip = parts[1];
                
                if (isValidIPv4(ip)) {
                    highConnIPs[ip] = count;
                }
            }
        });
        
        return highConnIPs;
    } catch (err) {
        return {};
    }
}

// NEW: Get currently blocked IPs from iptables with details
async function getBlockedIPsDetails() {
    if (!isLinux) return [];
    
    try {
        const { stdout } = await execAsync(`iptables -L INPUT -n -v 2>/dev/null | grep DROP | awk '{print $8, $1, $2}'`);
        
        const blocked = [];
        const lines = stdout.trim().split('\n').filter(line => line.trim());
        
        lines.forEach(line => {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 3) {
                blocked.push({
                    ip: parts[0],
                    packets: parseInt(parts[1]) || 0,
                    bytes: parseInt(parts[2]) || 0
                });
            }
        });
        
        return blocked;
    } catch (err) {
        return [];
    }
}

// NEW: Detect connection rate anomalies (connections per second)
async function detectConnectionRateAnomalies() {
    if (!isLinux) return {};
    
    try {
        // Get all connections and group by IP
        const { stdout } = await execAsync(`ss -ntu 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\.' | sort | uniq -c | sort -nr | head -100`);
        
        const anomalies = {};
        const lines = stdout.trim().split('\n').filter(line => line.trim());
        
        lines.forEach(line => {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 2) {
                const count = parseInt(parts[0]);
                const ip = parts[1];
                
                // Flag IPs with unusually high connection counts
                if (count > 30 && ip && !ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('127.')) {
                    anomalies[ip] = {
                        connections: count,
                        rate_score: Math.min(count / 10, 100) // Score 0-100
                    };
                }
            }
        });
        
        return anomalies;
    } catch (err) {
        return {};
    }
}

// NEW: Detect TIME_WAIT abuse (connection exhaustion attack)
async function detectTimeWaitAbuse() {
    if (!isLinux) return {};
    
    try {
        const { stdout } = await execAsync(`ss -ntu state time-wait 2>/dev/null | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\.' | sort | uniq -c | sort -nr | head -50`);
        
        const timeWaitAbuse = {};
        const lines = stdout.trim().split('\n').filter(line => line.trim());
        
        lines.forEach(line => {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 2) {
                const count = parseInt(parts[0]);
                const ip = parts[1];
                
                // TIME_WAIT abuse: more than 100 connections in TIME_WAIT state
                if (count > 100 && ip) {
                    timeWaitAbuse[ip] = count;
                }
            }
        });
        
        return timeWaitAbuse;
    } catch (err) {
        return {};
    }
}

// Get server load and resource usage
async function getServerStats() {
    if (!isLinux) {
        // Return mock data for Windows
        return {
            load_1min: 0,
            load_5min: 0,
            load_15min: 0,
            memory_total: 0,
            memory_used: 0,
            memory_free: 0,
            memory_percent: 0,
            total_network_connections: 0,
            established_connections: 0
        };
    }
    
    try {
        const stats = {};
        
        // CPU load
        const { stdout: loadavg } = await execAsync(`cat /proc/loadavg 2>/dev/null`);
        const loads = loadavg.trim().split(/\s+/);
        stats.load_1min = parseFloat(loads[0]) || 0;
        stats.load_5min = parseFloat(loads[1]) || 0;
        stats.load_15min = parseFloat(loads[2]) || 0;
        
        // Memory usage
        const { stdout: meminfo } = await execAsync(`free -m 2>/dev/null | grep Mem`);
        const memParts = meminfo.trim().split(/\s+/);
        stats.memory_total = parseInt(memParts[1]) || 0;
        stats.memory_used = parseInt(memParts[2]) || 0;
        stats.memory_free = parseInt(memParts[3]) || 0;
        stats.memory_percent = Math.round((stats.memory_used / stats.memory_total) * 100) || 0;
        
        // Network connections count
        const { stdout: connCount } = await execAsync(`ss -ntu 2>/dev/null | wc -l`);
        stats.total_network_connections = parseInt(connCount.trim()) - 1 || 0;
        
        // Established connections
        const { stdout: estabCount } = await execAsync(`ss -ntu state established 2>/dev/null | wc -l`);
        stats.established_connections = parseInt(estabCount.trim()) - 1 || 0;
        
        return stats;
    } catch (err) {
        return {
            load_1min: 0,
            load_5min: 0,
            load_15min: 0,
            memory_total: 0,
            memory_used: 0,
            memory_free: 0,
            memory_percent: 0,
            total_network_connections: 0,
            established_connections: 0
        };
    }
}

// Analyze and update IP tracking with comprehensive network data
async function analyzeNetworkActivity() {
    try {
        const [
            connections, 
            connectionStates, 
            synFlood, 
            traffic, 
            scanners, 
            udpFlood, 
            serverStats,
            synRecvData,
            highConnIPs,
            rateAnomalies,
            timeWaitAbuse
        ] = await Promise.all([
            monitorActiveConnections(),
            monitorAllConnectionStates(),
            monitorSynFlood(),
            monitorNetworkTraffic(),
            detectPortScanning(),
            detectUDPFlood(),
            getServerStats(),
            detectSynRecvNetstat(),
            detectHighConnectionIPs(),
            detectConnectionRateAnomalies(),
            detectTimeWaitAbuse()
        ]);
        
        const now = Date.now();
        const allIPs = [
            ...Object.keys(connections),
            ...Object.keys(synFlood),
            ...Object.keys(traffic),
            ...Object.keys(scanners),
            ...Object.keys(udpFlood),
            ...Object.keys(synRecvData.ips || {}),
            ...Object.keys(highConnIPs),
            ...Object.keys(rateAnomalies),
            ...Object.keys(timeWaitAbuse)
        ];
        
        // Filter to only valid IPv4 addresses
        const detectedIPs = new Set(allIPs.filter(ip => isValidIPv4(ip)));
        
        // Update server stats
        stats.server_load = serverStats.load_1min;
        stats.memory_usage = serverStats.memory_percent;
        stats.total_network_connections = serverStats.total_network_connections;
        stats.established_connections = serverStats.established_connections;
        stats.syn_recv_total = synRecvData.total || 0;
        
        let criticalCount = 0;
        let highCount = 0;
        let mediumCount = 0;
        
        for (const ip of detectedIPs) {
            const connectionCount = connections[ip] || 0;
            const synCount = synFlood[ip] || 0;
            const trafficCount = traffic[ip] || 0;
            const portScanCount = scanners[ip] || 0;
            const udpCount = udpFlood[ip] || 0;
            const ipStates = connectionStates[ip] || {};
            const synRecvCount = synRecvData.ips?.[ip] || 0;
            const highConnCount = highConnIPs[ip] || 0;
            const rateAnomaly = rateAnomalies[ip];
            const timeWaitCount = timeWaitAbuse[ip] || 0;
            
            // Calculate comprehensive threat score with intelligent weighting
            let threatScore = 0;
            let attackType = [];
            let attackDetails = {};
            
            // SYN_RECV detection (highest priority - clear attack indicator)
            if (synRecvCount > 50) {
                threatScore += synRecvCount * 20; // Very high weight
                attackType.push('syn_recv_flood');
                attackDetails.syn_recv = synRecvCount;
            } else if (synRecvCount > 20) {
                threatScore += synRecvCount * 10;
                attackType.push('syn_recv_attack');
                attackDetails.syn_recv = synRecvCount;
            }
            
            // High connection count (from ss command with >50 threshold)
            if (highConnCount > 200) {
                threatScore += highConnCount * 3;
                attackType.push('massive_connection_flood');
                attackDetails.high_connections = highConnCount;
            } else if (highConnCount > 100) {
                threatScore += highConnCount * 2;
                attackType.push('connection_flood');
                attackDetails.high_connections = highConnCount;
            } else if (highConnCount > 50) {
                threatScore += highConnCount;
                attackType.push('high_connections');
                attackDetails.high_connections = highConnCount;
            }
            
            // Connection rate anomalies
            if (rateAnomaly) {
                threatScore += rateAnomaly.rate_score * 5;
                attackType.push('rate_anomaly');
                attackDetails.rate_score = rateAnomaly.rate_score;
                attackDetails.anomaly_connections = rateAnomaly.connections;
            }
            
            // TIME_WAIT abuse (connection exhaustion)
            if (timeWaitCount > 500) {
                threatScore += timeWaitCount * 2;
                attackType.push('time_wait_exhaustion');
                attackDetails.time_wait = timeWaitCount;
            } else if (timeWaitCount > 200) {
                threatScore += timeWaitCount;
                attackType.push('time_wait_abuse');
                attackDetails.time_wait = timeWaitCount;
            }
            
            // Regular connection count
            if (connectionCount > 100) {
                threatScore += connectionCount * 2;
                if (!attackType.includes('connection_flood')) {
                    attackType.push('connection_flood');
                }
                attackDetails.connections = connectionCount;
            } else if (connectionCount > 50) {
                threatScore += connectionCount;
                attackType.push('high_connections');
                attackDetails.connections = connectionCount;
            }
            
            // SYN flood detection
            if (synCount > 20) {
                threatScore += synCount * 10;
                attackType.push('syn_flood');
                attackDetails.syn_packets = synCount;
            } else if (synCount > 10) {
                threatScore += synCount * 5;
                attackType.push('syn_attack');
                attackDetails.syn_packets = synCount;
            }
            
            // Port scanning
            if (portScanCount > 10) {
                threatScore += portScanCount * 15;
                attackType.push('aggressive_scan');
                attackDetails.ports_scanned = portScanCount;
            } else if (portScanCount > 5) {
                threatScore += portScanCount * 10;
                attackType.push('port_scan');
                attackDetails.ports_scanned = portScanCount;
            }
            
            // Traffic flood
            if (trafficCount > 200) {
                threatScore += trafficCount * 2;
                attackType.push('traffic_flood');
                attackDetails.traffic_count = trafficCount;
            } else if (trafficCount > 100) {
                threatScore += trafficCount;
                attackType.push('high_traffic');
                attackDetails.traffic_count = trafficCount;
            }
            
            // UDP flood
            if (udpCount > 50) {
                threatScore += udpCount * 5;
                attackType.push('udp_flood');
                attackDetails.udp_packets = udpCount;
            } else if (udpCount > 20) {
                threatScore += udpCount * 3;
                attackType.push('udp_attack');
                attackDetails.udp_packets = udpCount;
            }
            
            // Update or create IP tracking
            if (!liveIPs[ip]) {
                // Check if IP exists in database and get blocked status
                const existingIP = dbGet("SELECT blocked, blocked_at FROM ips WHERE ip = ?", [ip]);
                
                liveIPs[ip] = {
                    requests: 0,
                    bandwidth: 0,
                    threads: 0,
                    first_seen: now,
                    last_seen: now,
                    threat_level: 'low',
                    connections: 0,
                    attack_type: [],
                    threat_score: 0,
                    attack_details: {},
                    blocked: existingIP?.blocked || false,
                    blocked_at: existingIP?.blocked_at || null
                };
                
                dbRun("INSERT OR IGNORE INTO ips (ip, first_seen, last_seen) VALUES (?, ?, ?)", [ip, now, now]);
            }
            
            liveIPs[ip].connections = connectionCount;
            liveIPs[ip].last_seen = now;
            liveIPs[ip].threat_score = threatScore;
            liveIPs[ip].attack_type = attackType;
            liveIPs[ip].attack_details = attackDetails;
            liveIPs[ip].connection_states = ipStates;
            liveIPs[ip].syn_count = synCount;
            liveIPs[ip].udp_count = udpCount;
            liveIPs[ip].port_scan_count = portScanCount;
            liveIPs[ip].syn_recv_count = synRecvCount;
            liveIPs[ip].high_conn_count = highConnCount;
            liveIPs[ip].time_wait_count = timeWaitCount;
            
            // Determine threat level based on score and thresholds
            if (threatScore >= settings.threat_threshold_critical) {
                liveIPs[ip].threat_level = 'critical';
                criticalCount++;
            } else if (threatScore >= settings.threat_threshold_high) {
                liveIPs[ip].threat_level = 'high';
                highCount++;
            } else if (threatScore >= settings.threat_threshold_medium) {
                liveIPs[ip].threat_level = 'medium';
                mediumCount++;
            } else {
                liveIPs[ip].threat_level = 'low';
            }
            
            // Intelligent auto-blocking with multiple criteria
            const shouldBlock = settings.auto_block && (
                // Critical threat score
                liveIPs[ip].threat_level === 'critical' ||
                threatScore >= settings.threat_threshold_critical ||
                
                // Intelligent blocking based on specific attack patterns
                (settings.intelligent_blocking && (
                    synRecvCount >= settings.auto_block_syn_recv ||
                    highConnCount >= settings.auto_block_high_connections ||
                    portScanCount >= settings.auto_block_port_scan ||
                    timeWaitCount >= settings.auto_block_time_wait ||
                    
                    // Multiple attack types detected
                    attackType.length >= 3 ||
                    
                    // Combination attacks (more dangerous)
                    (synRecvCount > 20 && highConnCount > 100) ||
                    (portScanCount > 5 && synCount > 10) ||
                    (udpCount > 30 && connectionCount > 50)
                ))
            );
            
            if (shouldBlock) {
                // Check if already blocked in memory or database
                const alreadyBlocked = liveIPs[ip]?.blocked || false;
                const ipData = dbGet("SELECT blocked FROM ips WHERE ip = ?", [ip]);
                
                if (!alreadyBlocked && (!ipData || !ipData.blocked)) {
                    const blockResult = await blockIP(ip, attackType.join(',') || 'auto');
                    
                    if (blockResult.success) {
                        // Mark as blocked in memory
                        liveIPs[ip].blocked = true;
                        liveIPs[ip].blocked_at = Date.now();
                        
                        console.log(`🚨 INTELLIGENT AUTO-BLOCK: ${ip}`);
                        console.log(`   Threat Level: ${liveIPs[ip].threat_level} | Score: ${threatScore}`);
                        console.log(`   Attack Types: ${attackType.join(', ')}`);
                        console.log(`   Details:`, JSON.stringify(attackDetails, null, 2));
                        
                        // Log specific triggers
                        const triggers = [];
                        if (synRecvCount >= settings.auto_block_syn_recv) triggers.push(`SYN_RECV: ${synRecvCount}`);
                        if (highConnCount >= settings.auto_block_high_connections) triggers.push(`High Conn: ${highConnCount}`);
                        if (portScanCount >= settings.auto_block_port_scan) triggers.push(`Port Scan: ${portScanCount}`);
                        if (timeWaitCount >= settings.auto_block_time_wait) triggers.push(`TIME_WAIT: ${timeWaitCount}`);
                        if (triggers.length > 0) {
                            console.log(`   Triggers: ${triggers.join(', ')}`);
                        }
                    }
                }
            }
        } // End of for loop
        
        // Update global stats
        stats.total_connections = Object.values(connections).reduce((a, b) => a + b, 0);
        stats.suspicious_ips = detectedIPs.size;
        stats.critical_threats = criticalCount;
        stats.high_threats = highCount;
        stats.medium_threats = mediumCount;
        stats.last_scan = now;
        
    } catch (err) {
        console.error("Network analysis error:", err);
    }
}

// Start continuous network monitoring with faster interval
setInterval(analyzeNetworkActivity, 3000); // Every 3 seconds for real-time detection

// Initial scan
setTimeout(analyzeNetworkActivity, 1000);

console.log("✓ Real-time network monitoring started (3s interval)");

/* ============================
   DATABASE HELPER FUNCTIONS
============================ */
// Helper to execute prepared statements
function dbRun(sql, params = []) {
    try {
        const stmt = db.prepare(sql);
        return stmt.run(...params);
    } catch (err) {
        console.error("DB Run Error:", err);
        throw err;
    }
}

function dbGet(sql, params = []) {
    try {
        const stmt = db.prepare(sql);
        return stmt.get(...params);
    } catch (err) {
        console.error("DB Get Error:", err);
        throw err;
    }
}

function dbAll(sql, params = []) {
    try {
        const stmt = db.prepare(sql);
        return stmt.all(...params);
    } catch (err) {
        console.error("DB All Error:", err);
        throw err;
    }
}

/* ============================
   IPTABLES FUNCTIONS
============================ */
async function blockIP(ip, reason = "auto") {
    if (!isLinux) {
        console.log(`⚠️  Cannot block ${ip} on Windows - iptables requires Linux`);
        return { success: false, message: "Blocking requires Linux VPS" };
    }
    
    // Validate IP
    if (!isValidIPv4(ip)) {
        console.error(`❌ Invalid IP address: ${ip}`);
        return { success: false, message: "Invalid IP address" };
    }
    
    try {
        // Check if already blocked in iptables
        const { stdout } = await execAsync(`iptables -L INPUT -n | grep ${ip}`);
        if (stdout.includes(ip)) {
            // Already blocked in iptables, update database to match
            dbRun("UPDATE ips SET blocked = 1, blocked_at = ? WHERE ip = ?", [Date.now(), ip]);
            return { success: true, message: "Already blocked" };
        }
    } catch (err) {
        // Not found in iptables, proceed to block
    }

    try {
        await execAsync(`iptables -A INPUT -s ${ip} -j DROP`);
        console.log(`🚫 Blocked: ${ip} (${reason})`);
        
        stats.total_blocked++;
        
        dbRun("UPDATE ips SET blocked = 1, blocked_at = ? WHERE ip = ?", [Date.now(), ip]);
        dbRun("INSERT INTO attack_logs (ip, timestamp, requests, bandwidth, action) VALUES (?, ?, ?, ?, ?)",
            [ip, Date.now(), liveIPs[ip]?.requests || 0, liveIPs[ip]?.bandwidth || 0, `blocked_${reason}`]);

        io.emit("ip_blocked", { ip, reason, timestamp: Date.now() });
        
        return { success: true, message: "IP blocked" };
    } catch (err) {
        // Check if error is because it's already blocked
        if (err.message.includes('already') || err.message.includes('exist')) {
            dbRun("UPDATE ips SET blocked = 1, blocked_at = ? WHERE ip = ?", [Date.now(), ip]);
            return { success: true, message: "Already blocked" };
        }
        console.error(`❌ Block failed for ${ip}:`, err.message);
        return { success: false, error: err.message };
    }
}

async function unblockIP(ip) {
    if (!isLinux) {
        console.log(`⚠️  Cannot unblock ${ip} on Windows - iptables requires Linux`);
        return { success: false, message: "Unblocking requires Linux VPS" };
    }
    
    try {
        await execAsync(`iptables -D INPUT -s ${ip} -j DROP`);
        console.log(`✓ Unblocked: ${ip}`);
        
        dbRun("UPDATE ips SET blocked = 0, blocked_at = NULL WHERE ip = ?", [ip]);
        dbRun("INSERT INTO attack_logs (ip, timestamp, requests, bandwidth, action) VALUES (?, ?, ?, ?, ?)",
            [ip, Date.now(), 0, 0, "unblocked"]);

        io.emit("ip_unblocked", { ip, timestamp: Date.now() });
        
        return { success: true, message: "IP unblocked" };
    } catch (err) {
        console.error(`❌ Unblock failed for ${ip}:`, err.message);
        return { success: false, error: err.message };
    }
}

async function listBlockedIPs() {
    if (!isLinux) return [];
    
    try {
        const { stdout } = await execAsync("iptables -L INPUT -n | grep DROP");
        return stdout.split("\n").filter(line => line.includes("DROP"));
    } catch (err) {
        return [];
    }
}

/* ============================
   HELPER FUNCTIONS
============================ */
function getThreatLevel(requests, bandwidth) {
    if (requests >= settings.threat_threshold_high || bandwidth >= settings.max_bandwidth_per_minute * 5) {
        return "critical";
    } else if (requests >= settings.threat_threshold_medium || bandwidth >= settings.max_bandwidth_per_minute * 2) {
        return "high";
    } else if (requests >= settings.rate_limit_per_minute || bandwidth >= settings.max_bandwidth_per_minute) {
        return "medium";
    }
    return "low";
}

function getClientIP(req) {
    return (
        req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
        req.headers["x-real-ip"] ||
        req.socket.remoteAddress ||
        req.connection.remoteAddress
    ).replace("::ffff:", "");
}

/* ============================
   AUTHENTICATION MIDDLEWARE
============================ */
function authenticateToken(req, res, next) {
    const token = req.cookies.token || req.headers["authorization"]?.split(" ")[1];

    if (!token) {
        return res.status(401).json({ error: "Access denied. No token provided." });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: "Invalid or expired token" });
        }

        // Check if session exists and is valid
        try {
            const session = db.prepare(
                "SELECT * FROM sessions WHERE token = ? AND expires_at > ?"
            ).get(token, Date.now());

            if (!session) {
                return res.status(403).json({ error: "Session expired or invalid" });
            }

            req.user = user;
            req.sessionToken = token;
            next();
        } catch (err) {
            return res.status(500).json({ error: "Database error" });
        }
    });
}

function authenticateSocketToken(socket, next) {
    const token = socket.handshake.auth.token || socket.handshake.headers.cookie?.match(/token=([^;]+)/)?.[1];

    if (!token) {
        return next(new Error("Authentication required"));
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return next(new Error("Invalid token"));
        }

        try {
            const session = db.prepare(
                "SELECT * FROM sessions WHERE token = ? AND expires_at > ?"
            ).get(token, Date.now());

            if (!session) {
                return next(new Error("Session expired"));
            }

            socket.user = user;
            next();
        } catch (err) {
            return next(new Error("Database error"));
        }
    });
}

/* ============================
   AUTHENTICATION ROUTES
============================ */

// Login
app.post("/api/auth/login", loginLimiter, async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Username and password required" });
    }

    try {
        const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);

        if (!user) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        // Check if account is locked
        if (user.locked_until > Date.now()) {
            const minutesLeft = Math.ceil((user.locked_until - Date.now()) / 60000);
            return res.status(423).json({ 
                error: `Account locked. Try again in ${minutesLeft} minutes.` 
            });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            // Increment login attempts
            const attempts = user.login_attempts + 1;
            const lockedUntil = attempts >= 5 ? Date.now() + 15 * 60 * 1000 : 0;

            db.prepare(
                "UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?"
            ).run(attempts, lockedUntil, user.id);

            return res.status(401).json({ 
                error: "Invalid credentials",
                attemptsLeft: Math.max(0, 5 - attempts)
            });
        }

        // Reset login attempts
        db.prepare(
            "UPDATE users SET login_attempts = 0, locked_until = 0, last_login = ? WHERE id = ?"
        ).run(Date.now(), user.id);

        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        );

        // Store session
        const clientIP = getClientIP(req);
        const userAgent = req.headers["user-agent"] || "unknown";
        const expiresAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

        db.prepare(
            `INSERT INTO sessions (user_id, token, ip_address, user_agent, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?)`
        ).run(user.id, token, clientIP, userAgent, Date.now(), expiresAt);

        // Set HTTP-only cookie
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 24 * 60 * 60 * 1000,
            sameSite: "strict"
        });

        res.json({
            success: true,
            message: "Login successful",
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            },
            token
        });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ error: "Login failed" });
    }
});

// Logout
app.post("/api/auth/logout", authenticateToken, (req, res) => {
    try {
        dbRun("DELETE FROM sessions WHERE token = ?", [req.sessionToken]);
        res.clearCookie("token");
        res.json({ success: true, message: "Logged out successfully" });
    } catch (err) {
        res.status(500).json({ error: "Logout failed" });
    }
});

// Check authentication status
app.get("/api/auth/me", authenticateToken, (req, res) => {
    try {
        const user = dbGet("SELECT id, username, email, role, created_at, last_login FROM users WHERE id = ?", [req.user.id]);
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        res.json({ user });
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch user" });
    }
});

// Change password
app.post("/api/auth/change-password", authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: "Current and new password required" });
    }

    if (newPassword.length < 6) {
        return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    try {
        const user = dbGet("SELECT * FROM users WHERE id = ?", [req.user.id]);
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        const validPassword = await bcrypt.compare(currentPassword, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: "Current password is incorrect" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
        dbRun("UPDATE users SET password = ? WHERE id = ?", [hashedPassword, user.id]);
        
        // Invalidate all sessions except current
        dbRun("DELETE FROM sessions WHERE user_id = ? AND token != ?", [user.id, req.sessionToken]);

        res.json({ success: true, message: "Password changed successfully" });
    } catch (err) {
        res.status(500).json({ error: "Failed to update password" });
    }
});

// Get active sessions
app.get("/api/auth/sessions", authenticateToken, (req, res) => {
    try {
        const sessions = dbAll(
            `SELECT id, ip_address, user_agent, created_at, expires_at, 
             CASE WHEN token = ? THEN 1 ELSE 0 END as is_current
             FROM sessions 
             WHERE user_id = ? AND expires_at > ?
             ORDER BY created_at DESC`,
            [req.sessionToken, req.user.id, Date.now()]
        );
        res.json({ sessions });
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch sessions" });
    }
});

// Revoke session
app.delete("/api/auth/sessions/:id", authenticateToken, (req, res) => {
    const sessionId = req.params.id;

    try {
        const result = dbRun(
            "DELETE FROM sessions WHERE id = ? AND user_id = ? AND token != ?",
            [sessionId, req.user.id, req.sessionToken]
        );

        if (result.changes === 0) {
            return res.status(404).json({ error: "Session not found or cannot revoke current session" });
        }

        res.json({ success: true, message: "Session revoked" });
    } catch (err) {
        res.status(500).json({ error: "Failed to revoke session" });
    }
});

/* ============================
   TRACK REQUEST MIDDLEWARE
============================ */
app.use((req, res, next) => {
    const ip = getClientIP(req);
    const now = Date.now();
    const currentMinute = Math.floor(now / 60000);

    stats.total_requests++;
    stats.active_connections++;

    // Initialize tracking
    if (!liveIPs[ip]) {
        liveIPs[ip] = {
            requests: 0,
            bandwidth: 0,
            threads: 0,
            first_seen: now,
            last_seen: now,
            threat_level: "low"
        };
        
        dbRun("INSERT OR IGNORE INTO ips (ip, first_seen, last_seen) VALUES (?, ?, ?)", [ip, now, now]);
    }

    if (!minuteTracker[ip]) {
        minuteTracker[ip] = { minute: currentMinute, requests: 0, bandwidth: 0 };
    }

    // Reset per-minute counter if new minute
    if (minuteTracker[ip].minute !== currentMinute) {
        minuteTracker[ip] = { minute: currentMinute, requests: 0, bandwidth: 0 };
    }

    // Track metrics
    liveIPs[ip].requests++;
    liveIPs[ip].threads++;
    liveIPs[ip].last_seen = now;
    minuteTracker[ip].requests++;

    const size = parseInt(req.headers["content-length"] || 0);
    liveIPs[ip].bandwidth += size;
    minuteTracker[ip].bandwidth += size;
    stats.total_bandwidth += size;

    // Update threat level
    liveIPs[ip].threat_level = getThreatLevel(
        minuteTracker[ip].requests,
        minuteTracker[ip].bandwidth
    );

    // AUTO BLOCK LOGIC (per minute rate limiting)
    if (settings.auto_block) {
        const exceedsRate = minuteTracker[ip].requests > settings.rate_limit_per_minute;
        const exceedsBandwidth = minuteTracker[ip].bandwidth > settings.max_bandwidth_per_minute;

        if (exceedsRate || exceedsBandwidth) {
            const reason = exceedsRate ? "rate_limit" : "bandwidth_limit";
            blockIP(ip, reason);
            
            return res.status(429).json({
                error: "Too many requests",
                message: "Your IP has been blocked due to excessive requests",
                ip: ip
            });
        }
    }

    res.on("finish", () => {
        liveIPs[ip].threads--;
        stats.active_connections--;
    });

    next();
});

/* ============================
   PERIODIC TASKS
============================ */

// Save to database every 3s
setInterval(() => {
    for (let ip in liveIPs) {
        let data = liveIPs[ip];

        dbRun(
            `INSERT INTO ips (ip, requests, bandwidth, threads, last_seen, threat_level, first_seen)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(ip) DO UPDATE SET
             requests = requests + ?,
             bandwidth = bandwidth + ?,
             threads = ?,
             last_seen = ?,
             threat_level = ?`,
            [
                ip, data.requests, data.bandwidth, data.threads, data.last_seen, data.threat_level, data.first_seen,
                data.requests, data.bandwidth, data.threads, data.last_seen, data.threat_level
            ]
        );
    }

    // Broadcast live data
    io.emit("live_update", {
        ips: liveIPs,
        stats: stats,
        timestamp: Date.now()
    });
}, 3000);

// Clean old minute trackers every minute
setInterval(() => {
    const currentMinute = Math.floor(Date.now() / 60000);
    for (let ip in minuteTracker) {
        if (minuteTracker[ip].minute < currentMinute - 2) {
            delete minuteTracker[ip];
        }
    }
}, 60000);

// Auto-unblock IPs after block duration
setInterval(() => {
    if (settings.block_duration > 0) {
        const expireTime = Date.now() - (settings.block_duration * 1000);
        
        try {
            const rows = dbAll("SELECT ip FROM ips WHERE blocked = 1 AND blocked_at < ?", [expireTime]);
            rows.forEach(row => {
                unblockIP(row.ip);
                console.log(`⏰ Auto-unblocked: ${row.ip} (duration expired)`);
            });
        } catch (err) {
            console.error("Auto-unblock error:", err);
        }
    }
}, 30000);

/* ============================
   API ROUTES (ADMIN) - PROTECTED
============================ */

// Apply authentication and rate limiting to all admin routes
app.use("/api/admin", authenticateToken, apiLimiter);

// Dashboard stats
app.get("/api/admin/stats", (req, res) => {
    try {
        const row = dbGet("SELECT COUNT(*) as total_ips, SUM(blocked) as blocked_count FROM ips");
        res.json({
            ...stats,
            total_ips: row?.total_ips || 0,
            blocked_ips: row?.blocked_count || 0,
            settings: settings
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get all IPs with pagination
app.get("/api/admin/ips", (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;
    const filter = req.query.filter || "all";

    let query = "SELECT * FROM ips";
    let params = [];

    if (filter === "blocked") {
        query += " WHERE blocked = 1";
    } else if (filter === "active") {
        query += " WHERE last_seen > ?";
        params.push(Date.now() - 300000); // Last 5 minutes
    } else if (filter === "threat") {
        query += " WHERE threat_level IN ('high', 'critical')";
    }

    query += " ORDER BY requests DESC LIMIT ? OFFSET ?";
    params.push(limit, offset);

    try {
        const rows = dbAll(query, params);
        const count = dbGet("SELECT COUNT(*) as total FROM ips");
        
        res.json({
            ips: rows,
            pagination: {
                page,
                limit,
                total: count?.total || 0,
                pages: Math.ceil((count?.total || 0) / limit)
            }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get single IP details
app.get("/api/admin/ip/:ip", (req, res) => {
    const { ip } = req.params;
    
    try {
        const ipData = dbGet("SELECT * FROM ips WHERE ip = ?", [ip]);
        if (!ipData) return res.status(404).json({ error: "IP not found" });
        
        const logs = dbAll("SELECT * FROM attack_logs WHERE ip = ? ORDER BY timestamp DESC LIMIT 100", [ip]);
        
        res.json({
            ...ipData,
            live: liveIPs[ip] || null,
            logs: logs || []
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Block IP
app.post("/api/admin/block", async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: "IP required" });
    
    const result = await blockIP(ip, "manual");
    res.json(result);
});

// Unblock IP
app.post("/api/admin/unblock", async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: "IP required" });
    
    const result = await unblockIP(ip);
    res.json(result);
});

// Bulk block IPs
app.post("/api/admin/bulk-block", async (req, res) => {
    const { ips } = req.body;
    if (!Array.isArray(ips)) return res.status(400).json({ error: "IPs array required" });
    
    const results = await Promise.all(ips.map(ip => blockIP(ip, "bulk")));
    res.json({ results });
});

// Get blocked IPs from iptables
app.get("/api/admin/iptables", async (req, res) => {
    const blocked = await listBlockedIPs();
    res.json({ blocked });
});

// Clear IP data
app.delete("/api/admin/ip/:ip", (req, res) => {
    const { ip } = req.params;
    
    try {
        dbRun("DELETE FROM ips WHERE ip = ?", [ip]);
        dbRun("DELETE FROM attack_logs WHERE ip = ?", [ip]);
        delete liveIPs[ip];
        delete minuteTracker[ip];
        res.json({ success: true, message: "IP data cleared" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get settings
app.get("/api/admin/settings", (req, res) => {
    res.json(settings);
});

// Update settings
app.post("/api/admin/settings", (req, res) => {
    const {
        rate_limit_per_minute,
        max_bandwidth_per_minute,
        auto_block,
        block_duration,
        threat_threshold_medium,
        threat_threshold_high
    } = req.body;

    try {
        dbRun(
            `UPDATE settings SET 
             rate_limit_per_minute=?, 
             max_bandwidth_per_minute=?, 
             auto_block=?,
             block_duration=?,
             threat_threshold_medium=?,
             threat_threshold_high=?
             WHERE id=1`,
            [
                rate_limit_per_minute,
                max_bandwidth_per_minute,
                auto_block,
                block_duration,
                threat_threshold_medium,
                threat_threshold_high
            ]
        );
        loadSettings();
        io.emit("settings_updated", settings);
        res.json({ success: true, settings });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get attack logs
app.get("/api/admin/logs", (req, res) => {
    const limit = parseInt(req.query.limit) || 100;
    
    try {
        const rows = dbAll("SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT ?", [limit]);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get real-time network analysis
app.get("/api/admin/network-analysis", async (req, res) => {
    try {
        const [connections, synFlood, scanners] = await Promise.all([
            monitorActiveConnections(),
            monitorSynFlood(),
            detectPortScanning()
        ]);
        
        res.json({
            active_connections: connections,
            syn_flood_attacks: synFlood,
            port_scanners: scanners,
            total_connections: Object.values(connections).reduce((a, b) => a + b, 0),
            suspicious_count: Object.keys(synFlood).length + Object.keys(scanners).length,
            timestamp: Date.now()
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get live connection details for specific IP
app.get("/api/admin/ip/:ip/connections", async (req, res) => {
    const { ip } = req.params;
    
    try {
        const { stdout } = await execAsync(`ss -ntu | grep ${ip} | awk '{print $1, $4, $5}' | head -50`);
        const lines = stdout.trim().split('\n').filter(line => line.trim());
        
        const connections = lines.map(line => {
            const parts = line.split(/\s+/);
            return {
                state: parts[0],
                local: parts[1],
                remote: parts[2]
            };
        });
        
        res.json({
            ip,
            connections,
            count: connections.length,
            live_data: liveIPs[ip] || null
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* ============================
   PUBLIC API
============================ */

// Public attack view (limited data)
app.get("/api/public/attacks", (req, res) => {
    try {
        const rows = dbAll(
            `SELECT 
                ip, 
                requests, 
                bandwidth, 
                threat_level,
                blocked,
                last_seen
             FROM ips 
             WHERE requests > 10
             ORDER BY requests DESC 
             LIMIT 100`
        );
        res.json({
            attacks: rows,
            total_attacks: stats.total_requests,
            blocked_count: stats.total_blocked,
            timestamp: Date.now()
        });
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch data" });
    }
});

// Public live stats
app.get("/api/public/stats", (req, res) => {
    try {
        const row = dbGet("SELECT COUNT(*) as total, SUM(blocked) as blocked FROM ips");
        res.json({
            total_requests: stats.total_requests,
            total_ips: row?.total || 0,
            blocked_ips: row?.blocked || 0,
            active_connections: stats.active_connections,
            timestamp: Date.now()
        });
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch data" });
    }
});

// Public threat map data
app.get("/api/public/threats", (req, res) => {
    try {
        const rows = dbAll(
            `SELECT threat_level, COUNT(*) as count 
             FROM ips 
             GROUP BY threat_level`
        );
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch data" });
    }
});

/* ============================
   SOCKET.IO (LIVE DATA) - PUBLIC & PROTECTED
============================ */

// Optional authentication for socket connections (public can view, admin can control)
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    
    if (!token) {
        // Allow public access with limited permissions
        socket.user = { username: 'public', role: 'public' };
        return next();
    }
    
    // Verify token for admin access
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const session = dbGet("SELECT * FROM sessions WHERE token = ? AND expires_at > ?", [token, Date.now()]);
        
        if (!session) {
            socket.user = { username: 'public', role: 'public' };
            return next();
        }
        
        socket.user = decoded;
        socket.sessionToken = token;
        next();
    } catch (err) {
        socket.user = { username: 'public', role: 'public' };
        next();
    }
});

io.on("connection", (socket) => {
    console.log(`🔌 Client connected: ${socket.id} (User: ${socket.user.username})`);

    // Send initial data (public gets limited data)
    const initialData = {
        ips: liveIPs,
        stats: stats,
        user: socket.user
    };
    
    if (socket.user.role !== 'public') {
        initialData.settings = settings;
    }
    
    socket.emit("initial_data", initialData);

    // Admin room
    socket.on("join_admin", () => {
        socket.join("admin");
        console.log(`👤 Admin joined: ${socket.id} (${socket.user.username})`);
    });

    // Public room (still requires auth but limited data)
    socket.on("join_public", () => {
        socket.join("public");
        console.log(`👁 Public viewer joined: ${socket.id} (${socket.user.username})`);
    });

    socket.on("disconnect", () => {
        console.log(`🔌 Client disconnected: ${socket.id}`);
    });
});

/* ============================
   BASIC ROUTES
/* ============================
   BASIC ROUTES
============================ */

// Serve static files (login page, etc.)
app.use(express.static("public"));

// Main landing page - redirect to public view (no auth required)
app.get("/", (req, res) => {
    res.redirect("/public.html");
});

app.get("/health", (req, res) => {
    res.json({ 
        status: "healthy", 
        uptime: process.uptime(),
        timestamp: Date.now()
    });
});

/* ============================
   ERROR HANDLING
============================ */
app.use((err, req, res, next) => {
    console.error("Error:", err);
    res.status(500).json({ 
        error: "Internal server error",
        message: err.message 
    });
});

/* ============================
   START SERVER
============================ */
const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════╗
║   🛡️  DDoS Protection System Started     ║
╠═══════════════════════════════════════════╣
║   Port: ${PORT}                              ║
║   Status: ✓ Running                       ║
║   Database: ✓ Connected                   ║
║   Socket.IO: ✓ Active                     ║
╠═══════════════════════════════════════════╣
║   Admin API: http://localhost:${PORT}/api/admin  ║
║   Public API: http://localhost:${PORT}/api/public║
╚═══════════════════════════════════════════╝
    `);
});

// Graceful shutdown
process.on("SIGINT", () => {
    console.log("\n🛑 Shutting down gracefully...");
    server.close(() => {
        console.log("✓ Server closed");
        try {
            db.close();
            console.log("✓ Database closed");
        } catch (err) {
            console.error("Database close error:", err);
        }
        process.exit(0);
    });
    
    // Force exit after 5 seconds if graceful shutdown fails
    setTimeout(() => {
        console.log("⚠️  Forcing shutdown...");
        process.exit(1);
    }, 5000);
});
