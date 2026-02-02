#!/usr/bin/env python3
"""
LAN IDS Testing Framework
Suricata and Scapy-based IDS testing for covert channel detection in LAN environments
Designed for testing between two VMs with specific network interfaces
"""

import json
import time
import subprocess
import threading
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import yaml
import os
import socket

try:
    from scapy.all import (
        sniff, DNS, DNSQR, DNSRR, IP, UDP, Raw,
        wrpcap, rdpcap, get_if_list, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available - packet capture features will be limited")


class LANIDSTester:
    """LAN-specific IDS testing framework using Suricata and Scapy"""
    
    def __init__(self, config_path: Optional[Path] = None, 
                 interface: Optional[str] = None, role: str = "receiver"):
        """
        Initialize LAN IDS tester
        
        Args:
            config_path: Path to IDS configuration file
            interface: Network interface to monitor (e.g., 'enp0s1', 'eth0')
            role: VM role - 'sender' or 'receiver'
        """
        self.config = self._load_config(config_path)
        self.logger = logging.getLogger(__name__)
        self.role = role
        self.interface = interface or self._detect_interface()
        self.test_results = []
        self.suricata_process = None
        self.capture_thread = None
        self.captured_packets = []
        self.is_capturing = False
        
        # Update config with LAN-specific settings
        self.config['suricata']['interface'] = self.interface
        
        self.logger.info(f"Initialized LAN IDS Tester - Role: {role}, Interface: {self.interface}")
    
    def _load_config(self, config_path: Optional[Path] = None) -> dict:
        """Load IDS configuration from file or use defaults"""
        if config_path and config_path.exists():
            with open(config_path, 'r') as f:
                return json.load(f)
        
        return {
            'suricata': {
                'enabled': True,
                'rules_path': './rules/',
                'log_path': './logs/ids_testing/suricata/',
                'interface': 'tailscale0'  # Will be auto-detected
            },
            'scapy': {
                'enabled': SCAPY_AVAILABLE,
                'capture_filter': 'udp port 53 or udp port 5353',
                'packet_count': 0,  # 0 = unlimited
                'timeout': 300  # 5 minutes
            },
            'lan_testing': {
                'receiver_ip': '192.168.1.5',
                'receiver_interface': 'tailscale0',
                'sender_ip': '192.168.1.7',
                'sender_interface': 'tailscale0',
                'test_port': 5353
            },
            'detection_thresholds': {
                'dns_query_rate': 50,  # queries per minute
                'suspicious_domains': 10,
                'entropy_threshold': 4.5,
                'timing_anomaly': 0.3,
                'packet_size_anomaly': 512  # bytes
            }
        }
    
    def _detect_interface(self) -> str:
        """Auto-detect appropriate network interface based on role"""
        if not SCAPY_AVAILABLE:
            return self.config['lan_testing'].get(f'{self.role}_interface', 'tailscale0')
        
        try:
            interfaces = get_if_list()
            self.logger.info(f"Available interfaces: {interfaces}")
            
            for iface in interfaces:
                if 'tailscale' in iface.lower():
                    self.logger.info(f"✅ Detected Tailscale interface: {iface}")
                    return iface
            
            # Priority 2: Try to match expected interface based on role
            expected_if = self.config['lan_testing'].get(f'{self.role}_interface')
            if expected_if in interfaces:
                self.logger.info(f"Using expected interface: {expected_if}")
                return expected_if
            
            # Priority 3: Fallback to first non-loopback interface
            for iface in interfaces:
                if iface not in ['lo', 'lo0']:
                    self.logger.info(f"Using fallback interface: {iface}")
                    return iface
            
            return 'tailscale0'
            
        except Exception as e:
            self.logger.warning(f"Failed to detect interface: {e}")
            return 'tailscale0'
    
    def setup_lan_ids_environment(self) -> bool:
        """Setup LAN IDS testing environment"""
        try:
            self.logger.info("Setting up LAN IDS testing environment...")
            
            # Create log directories
            log_dir = Path(self.config['suricata']['log_path'])
            log_dir.mkdir(parents=True, exist_ok=True)
            
            pcap_dir = Path("logs/ids_testing/pcap")
            pcap_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate Suricata rules for covert channel detection
            rules_file = self._generate_lan_detection_rules()
            
            # Check Suricata availability
            suricata_available = self._check_suricata_available()
            
            if suricata_available:
                self.logger.info("Suricata is available and will be used for IDS detection")
            else:
                self.logger.warning("Suricata not available - using Scapy-only mode")
            
            # Check Scapy availability
            if SCAPY_AVAILABLE:
                self.logger.info("Scapy is available for packet capture and analysis")
            else:
                self.logger.warning("Scapy not available - limited packet analysis")
            
            self.logger.info(f"LAN IDS environment setup complete:")
            self.logger.info(f"  - Role: {self.role}")
            self.logger.info(f"  - Interface: {self.interface}")
            self.logger.info(f"  - Suricata rules: {rules_file}")
            self.logger.info(f"  - Log directory: {log_dir}")
            self.logger.info(f"  - PCAP directory: {pcap_dir}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup LAN IDS environment: {e}")
            return False
    
    def _check_suricata_available(self) -> bool:
        """Check if Suricata is available on the system"""
        try:
            result = subprocess.run(['which', 'suricata'], 
                                  capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def _generate_lan_detection_rules(self) -> str:
        """Generate Suricata rules optimized for LAN covert channel detection"""
        rules_dir = Path(self.config['suricata']['rules_path'])
        rules_dir.mkdir(parents=True, exist_ok=True)
        
        # Get LAN-specific IPs
        lan_config = self.config['lan_testing']
        receiver_ip = lan_config['receiver_ip']
        sender_ip = lan_config['sender_ip']
        
        rules = [
            # LAN-specific DNS covert channel detection
            f'alert dns {sender_ip} any -> {receiver_ip} any (msg:"LAN DNS Covert Channel - High Entropy Query"; '
            f'dns.query; pcre:"/[A-Za-z0-9+\\/]{{30,}}/"; '
            f'threshold:type limit, track by_src, count 5, seconds 60; '
            f'sid:2000001; rev:1;)',
            
            # DNSSEC-based covert channel on LAN
            f'alert dns {sender_ip} any -> {receiver_ip} any (msg:"LAN DNSSEC Covert Channel - Large DNSKEY"; '
            f'dns.query; dns.rrtype:48; dsize:>400; '
            f'threshold:type threshold, track by_src, count 10, seconds 30; '
            f'sid:2000002; rev:1;)',
            
            # Rapid DNS queries between specific hosts
            f'alert dns {sender_ip} any -> {receiver_ip} any (msg:"LAN DNS Timing Anomaly - Rapid Queries"; '
            f'dns.query; threshold:type threshold, track by_src, count 30, seconds 10; '
            f'sid:2000003; rev:1;)',
            
            # Suspicious DNS query patterns
            f'alert dns {sender_ip} any -> {receiver_ip} any (msg:"LAN DNS Covert - Base64 Pattern"; '
            f'dns.query; pcre:"/^[A-Za-z0-9+\\/]{{20,}}={{0,2}}\\./"; '
            f'threshold:type limit, track by_src, count 3, seconds 60; '
            f'sid:2000004; rev:1;)',
            
            # Sequential DNSKEY queries (covert channel indicator)
            f'alert dns {sender_ip} any -> {receiver_ip} any (msg:"LAN DNSSEC Sequential Pattern"; '
            f'dns.query; dns.rrtype:48; content:"covert"; nocase; '
            f'threshold:type threshold, track by_src, count 5, seconds 20; '
            f'sid:2000005; rev:1;)',
            
            # Large DNS responses (data exfiltration)
            f'alert dns {receiver_ip} any -> {sender_ip} any (msg:"LAN DNS Large Response"; '
            f'dsize:>512; threshold:type limit, track by_dst, count 5, seconds 60; '
            f'sid:2000006; rev:1;)',
            
            # Non-standard DNS port usage
            f'alert udp {sender_ip} any -> {receiver_ip} 5353 (msg:"LAN DNS Non-Standard Port 5353"; '
            f'content:"|00 00|"; offset:2; depth:2; '
            f'threshold:type threshold, track by_src, count 20, seconds 60; '
            f'sid:2000007; rev:1;)',
        ]
        
        rules_file = rules_dir / 'lan_covert_channel.rules'
        with open(rules_file, 'w') as f:
            f.write('# LAN Covert Channel Detection Rules\n')
            f.write(f'# Generated: {datetime.now().isoformat()}\n')
            f.write(f'# Sender: {sender_ip}, Receiver: {receiver_ip}\n\n')
            f.write('\n'.join(rules) + '\n')
        
        self.logger.info(f"Generated {len(rules)} LAN-specific detection rules")
        return str(rules_file)
    
    def start_lan_ids_monitoring(self) -> bool:
        """Start LAN IDS monitoring with Suricata and Scapy"""
        try:
            self.logger.info("Starting LAN IDS monitoring...")
            
            # Start Suricata if available
            if self._check_suricata_available():
                self._start_suricata_lan()
            else:
                self.logger.warning("Suricata not available, using Scapy-only mode")
            
            # Start Scapy packet capture
            if SCAPY_AVAILABLE:
                self._start_scapy_capture()
            else:
                self.logger.warning("Scapy not available, limited monitoring")
            
            # Wait for systems to initialize
            time.sleep(3)
            
            self.logger.info("LAN IDS monitoring active")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start LAN IDS monitoring: {e}")
            return False
    
    def _start_suricata_lan(self):
        """Start Suricata for LAN monitoring"""
        try:
            log_path = Path(self.config['suricata']['log_path'])
            log_path.mkdir(parents=True, exist_ok=True)
            
            # Check if we need sudo
            needs_sudo = os.geteuid() != 0
            
            cmd = []
            if needs_sudo:
                cmd.append('sudo')
            
            cmd.extend([
                'suricata',
                '-i', self.interface,
                '-l', str(log_path),
                '-S', str(Path(self.config['suricata']['rules_path']) / 'lan_covert_channel.rules'),
                '--init-errors-fatal'
            ])
            
            self.logger.info(f"Starting Suricata on interface {self.interface}")
            self.logger.info(f"Command: {' '.join(cmd)}")
            
            self.suricata_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            self.logger.info("Suricata started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start Suricata: {e}")
            self.logger.info("Continuing without Suricata...")
    
    def _start_scapy_capture(self):
        """Start Scapy packet capture in background thread"""
        if not SCAPY_AVAILABLE:
            return
        
        self.is_capturing = True
        self.captured_packets = []
        
        def capture_packets():
            try:
                self.logger.info(f"Starting Scapy capture on {self.interface}")
                
                # Define packet filter for DNS traffic
                filter_str = self.config['scapy']['capture_filter']
                
                # Start sniffing
                packets = sniff(
                    iface=self.interface,
                    filter=filter_str,
                    prn=self._process_packet,
                    store=True,
                    stop_filter=lambda x: not self.is_capturing,
                    timeout=self.config['scapy']['timeout']
                )
                
                self.captured_packets.extend(packets)
                self.logger.info(f"Captured {len(packets)} packets")
                
            except Exception as e:
                self.logger.error(f"Scapy capture error: {e}")
        
        self.capture_thread = threading.Thread(target=capture_packets, daemon=True)
        self.capture_thread.start()
        self.logger.info("Scapy capture thread started")
    
    def _process_packet(self, packet):
        """Process captured packet in real-time"""
        try:
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                src_ip = packet[IP].src if packet.haslayer(IP) else 'unknown'
                
                # Calculate entropy of query
                entropy = self._calculate_entropy(query)
                
                # Check for suspicious patterns
                if entropy > self.config['detection_thresholds']['entropy_threshold']:
                    self.logger.warning(f"High entropy DNS query detected: {query[:50]}... "
                                      f"(entropy: {entropy:.2f}) from {src_ip}")
                
                # Check for Base64 patterns
                if self._has_base64_pattern(query):
                    self.logger.warning(f"Base64-like pattern in DNS query from {src_ip}")
                
        except Exception as e:
            self.logger.debug(f"Error processing packet: {e}")
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0.0
        
        import math
        from collections import Counter
        
        # Count character frequencies
        counter = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _has_base64_pattern(self, data: str) -> bool:
        """Check if string contains Base64-like patterns"""
        import re
        # Base64 pattern: alphanumeric + / + with optional = padding
        pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        return bool(re.search(pattern, data))
    
    def stop_lan_ids_monitoring(self):
        """Stop LAN IDS monitoring"""
        self.logger.info("Stopping LAN IDS monitoring...")
        
        # Stop Scapy capture
        self.is_capturing = False
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
            self.logger.info("Scapy capture stopped")
        
        # Stop Suricata
        if self.suricata_process:
            try:
                self.suricata_process.terminate()
                self.suricata_process.wait(timeout=10)
                self.logger.info("Suricata stopped")
            except Exception as e:
                self.logger.warning(f"Error stopping Suricata: {e}")
                try:
                    self.suricata_process.kill()
                except:
                    pass
        
        self.logger.info("LAN IDS monitoring stopped")
    
    def analyze_lan_traffic(self) -> Dict:
        """Analyze captured LAN traffic for covert channel indicators"""
        self.logger.info("Analyzing captured LAN traffic...")
        
        analysis = {
            'total_packets': len(self.captured_packets),
            'dns_queries': 0,
            'high_entropy_queries': 0,
            'base64_patterns': 0,
            'large_queries': 0,
            'suspicious_timing': False,
            'query_rate': 0.0,
            'unique_domains': set(),
            'packet_sizes': [],
            'timestamps': []
        }
        
        if not SCAPY_AVAILABLE or not self.captured_packets:
            self.logger.warning("No packets to analyze")
            return analysis
        
        try:
            for packet in self.captured_packets:
                if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                    analysis['dns_queries'] += 1
                    
                    query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                    analysis['unique_domains'].add(query)
                    
                    # Entropy analysis
                    entropy = self._calculate_entropy(query)
                    if entropy > self.config['detection_thresholds']['entropy_threshold']:
                        analysis['high_entropy_queries'] += 1
                    
                    # Base64 pattern detection
                    if self._has_base64_pattern(query):
                        analysis['base64_patterns'] += 1
                    
                    # Size analysis
                    query_size = len(query)
                    analysis['packet_sizes'].append(query_size)
                    if query_size > self.config['detection_thresholds']['packet_size_anomaly']:
                        analysis['large_queries'] += 1
                    
                    # Timestamp for timing analysis
                    if hasattr(packet, 'time'):
                        analysis['timestamps'].append(packet.time)
            
            # Calculate query rate
            if len(analysis['timestamps']) > 1:
                time_span = analysis['timestamps'][-1] - analysis['timestamps'][0]
                if time_span > 0:
                    analysis['query_rate'] = analysis['dns_queries'] / time_span
            
            # Timing anomaly detection
            if analysis['query_rate'] > self.config['detection_thresholds']['dns_query_rate'] / 60:
                analysis['suspicious_timing'] = True
            
            # Convert set to list for JSON serialization
            analysis['unique_domains'] = list(analysis['unique_domains'])
            
            self.logger.info(f"Traffic analysis complete:")
            self.logger.info(f"  - Total packets: {analysis['total_packets']}")
            self.logger.info(f"  - DNS queries: {analysis['dns_queries']}")
            self.logger.info(f"  - High entropy: {analysis['high_entropy_queries']}")
            self.logger.info(f"  - Base64 patterns: {analysis['base64_patterns']}")
            self.logger.info(f"  - Query rate: {analysis['query_rate']:.2f} queries/sec")
            
        except Exception as e:
            self.logger.error(f"Error analyzing traffic: {e}")
        
        return analysis
    
    def save_pcap(self, filename: Optional[str] = None):
        """Save captured packets to PCAP file"""
        if not SCAPY_AVAILABLE or not self.captured_packets:
            self.logger.warning("No packets to save")
            return None
        
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"lan_capture_{self.role}_{timestamp}.pcap"
        
        pcap_dir = Path("logs/ids_testing/pcap")
        pcap_dir.mkdir(parents=True, exist_ok=True)
        pcap_path = pcap_dir / filename
        
        try:
            wrpcap(str(pcap_path), self.captured_packets)
            self.logger.info(f"Saved {len(self.captured_packets)} packets to {pcap_path}")
            return str(pcap_path)
        except Exception as e:
            self.logger.error(f"Failed to save PCAP: {e}")
            return None
    
    def analyze_suricata_alerts(self) -> Dict:
        """Analyze Suricata alert logs"""
        alerts = {
            'total_alerts': 0,
            'alert_types': {},
            'alerts_by_severity': {},
            'timeline': []
        }
        
        try:
            # Check for fast.log (human-readable alerts)
            fast_log = Path(self.config['suricata']['log_path']) / 'fast.log'
            if fast_log.exists():
                with open(fast_log, 'r') as f:
                    for line in f:
                        if line.strip():
                            alerts['total_alerts'] += 1
                            alerts['timeline'].append({
                                'timestamp': datetime.now().isoformat(),
                                'alert': line.strip()
                            })
                            
                            # Extract alert type
                            if 'LAN DNS Covert' in line:
                                alert_type = 'DNS Covert Channel'
                            elif 'LAN DNSSEC' in line:
                                alert_type = 'DNSSEC Anomaly'
                            elif 'Timing Anomaly' in line:
                                alert_type = 'Timing Anomaly'
                            else:
                                alert_type = 'Other'
                            
                            alerts['alert_types'][alert_type] = alerts['alert_types'].get(alert_type, 0) + 1
            
            # Check for eve.json (detailed JSON logs)
            eve_log = Path(self.config['suricata']['log_path']) / 'eve.json'
            if eve_log.exists():
                with open(eve_log, 'r') as f:
                    for line in f:
                        try:
                            event = json.loads(line)
                            if event.get('event_type') == 'alert':
                                severity = event.get('alert', {}).get('severity', 'unknown')
                                alerts['alerts_by_severity'][str(severity)] = \
                                    alerts['alerts_by_severity'].get(str(severity), 0) + 1
                        except json.JSONDecodeError:
                            continue
            
            self.logger.info(f"Suricata analysis: {alerts['total_alerts']} alerts found")
            
        except Exception as e:
            self.logger.error(f"Error analyzing Suricata alerts: {e}")
        
        return alerts
    
    def generate_lan_test_report(self, output_file: Optional[str] = None) -> Dict:
        """Generate comprehensive LAN IDS test report"""
        self.logger.info("Generating LAN IDS test report...")
        
        # Analyze traffic
        traffic_analysis = self.analyze_lan_traffic()
        
        # Analyze Suricata alerts
        suricata_alerts = self.analyze_suricata_alerts()
        
        # Calculate detection score
        detection_score = self._calculate_detection_score(traffic_analysis, suricata_alerts)
        
        report = {
            'test_info': {
                'timestamp': datetime.now().isoformat(),
                'role': self.role,
                'interface': self.interface,
                'lan_config': self.config['lan_testing']
            },
            'traffic_analysis': traffic_analysis,
            'suricata_alerts': suricata_alerts,
            'detection_summary': {
                'total_detections': suricata_alerts['total_alerts'] + 
                                   traffic_analysis['high_entropy_queries'] +
                                   traffic_analysis['base64_patterns'],
                'detection_score': detection_score,
                'stealth_score': 100 - detection_score,
                'detected': detection_score > 30
            },
            'recommendations': self._generate_lan_recommendations(traffic_analysis, suricata_alerts)
        }
        
        # Save report
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            self.logger.info(f"Report saved to {output_file}")
        
        return report
    
    def _calculate_detection_score(self, traffic_analysis: Dict, suricata_alerts: Dict) -> float:
        """Calculate detection score (0-100, higher = more detected)"""
        score = 0.0
        
        # Suricata alerts (high weight)
        score += suricata_alerts['total_alerts'] * 10
        
        # High entropy queries
        if traffic_analysis['dns_queries'] > 0:
            entropy_ratio = traffic_analysis['high_entropy_queries'] / traffic_analysis['dns_queries']
            score += entropy_ratio * 30
        
        # Base64 patterns
        if traffic_analysis['dns_queries'] > 0:
            base64_ratio = traffic_analysis['base64_patterns'] / traffic_analysis['dns_queries']
            score += base64_ratio * 25
        
        # Suspicious timing
        if traffic_analysis['suspicious_timing']:
            score += 15
        
        # Large queries
        if traffic_analysis['dns_queries'] > 0:
            large_ratio = traffic_analysis['large_queries'] / traffic_analysis['dns_queries']
            score += large_ratio * 20
        
        return min(100.0, score)
    
    def _generate_lan_recommendations(self, traffic_analysis: Dict, suricata_alerts: Dict) -> List[str]:
        """Generate recommendations based on LAN test results"""
        recommendations = []
        
        if suricata_alerts['total_alerts'] > 10:
            recommendations.append("High number of Suricata alerts - covert channel is easily detectable")
            recommendations.append("Consider implementing traffic shaping and timing randomization")
        
        if traffic_analysis['high_entropy_queries'] > 5:
            recommendations.append("High entropy DNS queries detected - use domain-like encoding")
            recommendations.append("Consider splitting data across multiple legitimate-looking domains")
        
        if traffic_analysis['base64_patterns'] > 3:
            recommendations.append("Base64 patterns detected - use alternative encoding schemes")
            recommendations.append("Consider DNS-safe encoding or domain name encoding")
        
        if traffic_analysis['suspicious_timing']:
            recommendations.append("Suspicious timing patterns detected")
            recommendations.append("Implement variable delays between queries (e.g., 2-10 seconds)")
        
        if traffic_analysis['large_queries'] > 5:
            recommendations.append("Large DNS queries detected - reduce chunk size")
            recommendations.append("Keep queries under 255 characters for better stealth")
        
        if not recommendations:
            recommendations.append("Covert channel shows good stealth characteristics on LAN")
            recommendations.append("Continue monitoring for detection patterns")
        
        return recommendations


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Initialize LAN IDS tester
    tester = LANIDSTester(role="receiver", interface=None)
    
    # Setup environment
    if tester.setup_lan_ids_environment():
        print(f"LAN IDS testing environment ready on interface: {tester.interface}")
    else:
        print("Failed to setup LAN IDS environment")
