"""
Firewall Detection Responder
Probes environment, detects blocking/DPI/RSTs and triggers adaptation
"""

import socket
import subprocess
import time
import logging
import threading
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
import scapy.all as scapy

class FirewallDetector:
    """Detects firewall interference and DPI analysis"""
    
    def __init__(self, callback: Optional[Callable] = None):
        self.callback = callback  # Callback for adaptation triggers
        self.detection_results: Dict[str, Any] = {}
        self.monitoring_active = False
        self.monitor_thread: Optional[threading.Thread] = None
        
        # Detection thresholds
        self.thresholds = {
            'rst_rate_threshold': 0.1,      # 10% RST rate triggers alert
            'timeout_rate_threshold': 0.2,   # 20% timeout rate triggers alert
            'dpi_anomaly_threshold': 3,      # 3 consecutive anomalies
            'latency_spike_threshold': 2.0   # 2x normal latency
        }
        
        # Baseline measurements
        self.baseline_latency = 0.0
        self.baseline_established = False
        
    def start_monitoring(self, target_domain: str, interval: int = 30):
        """Start continuous firewall detection monitoring"""
        if self.monitoring_active:
            logging.warning("Monitoring already active")
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(target_domain, interval),
            daemon=True
        )
        self.monitor_thread.start()
        
        logging.info(f"Started firewall monitoring for {target_domain}")
    
    def stop_monitoring(self):
        """Stop firewall detection monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)
        
        logging.info("Stopped firewall monitoring")
    
    def _monitor_loop(self, target_domain: str, interval: int):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Perform detection probes
                results = self.probe_environment(target_domain)
                
                # Analyze results for threats
                threat_level = self._analyze_threats(results)
                
                # Store results
                self.detection_results[datetime.now().isoformat()] = {
                    'results': results,
                    'threat_level': threat_level
                }
                
                # Trigger adaptation if needed
                if threat_level != 'none' and self.callback:
                    self.callback(threat_level)
                
                # Wait for next probe cycle
                time.sleep(interval)
                
            except Exception as e:
                logging.error(f"Error in monitoring loop: {e}")
                time.sleep(5)
    
    def probe_environment(self, target_domain: str) -> Dict[str, Any]:
        """Perform comprehensive environment probing"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'target_domain': target_domain,
            'tcp_probe': self._probe_tcp_connectivity(),
            'udp_probe': self._probe_udp_connectivity(),
            'dns_probe': self._probe_dns_behavior(target_domain),
            'icmp_probe': self._probe_icmp_connectivity(),
            'dpi_probe': self._probe_dpi_behavior(target_domain),
            'latency_probe': self._probe_latency(target_domain)
        }
        
        logging.info(f"Environment probe completed for {target_domain}")
        return results
    
    def _probe_tcp_connectivity(self) -> Dict[str, Any]:
        """Probe TCP connectivity and RST detection"""
        results = {
            'ports_tested': [],
            'successful_connections': 0,
            'rst_received': 0,
            'timeouts': 0,
            'connection_refused': 0
        }
        
        # Test common ports
        test_ports = [53, 80, 443, 8080, 8443]
        
        for port in test_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                
                start_time = time.time()
                result = sock.connect_ex(('8.8.8.8', port))
                end_time = time.time()
                
                results['ports_tested'].append({
                    'port': port,
                    'result_code': result,
                    'latency': end_time - start_time
                })
                
                if result == 0:
                    results['successful_connections'] += 1
                elif result == 111:  # Connection refused
                    results['connection_refused'] += 1
                
                sock.close()
                
            except socket.timeout:
                results['timeouts'] += 1
            except Exception as e:
                logging.debug(f"TCP probe error on port {port}: {e}")
        
        return results
    
    def _probe_udp_connectivity(self) -> Dict[str, Any]:
        """Probe UDP connectivity"""
        results = {
            'dns_queries': 0,
            'successful_responses': 0,
            'timeouts': 0,
            'icmp_unreachable': 0
        }
        
        # Test DNS queries to different servers
        dns_servers = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
        
        for dns_server in dns_servers:
            try:
                # Simple DNS query
                result = subprocess.run([
                    'dig', '+short', '+time=3', f'@{dns_server}', 'google.com', 'A'
                ], capture_output=True, text=True, timeout=5)
                
                results['dns_queries'] += 1
                
                if result.returncode == 0 and result.stdout.strip():
                    results['successful_responses'] += 1
                else:
                    results['timeouts'] += 1
                    
            except subprocess.TimeoutExpired:
                results['timeouts'] += 1
            except Exception as e:
                logging.debug(f"UDP probe error for {dns_server}: {e}")
        
        return results
    
    def _probe_dns_behavior(self, target_domain: str) -> Dict[str, Any]:
        """Probe DNS-specific behavior and anomalies"""
        results = {
            'queries_sent': 0,
            'responses_received': 0,
            'truncated_responses': 0,
            'nxdomain_responses': 0,
            'servfail_responses': 0,
            'tcp_fallback_triggered': 0,
            'response_times': []
        }
        
        # Test different query types
        query_types = ['A', 'AAAA', 'MX', 'TXT', 'DNSKEY', 'DS']
        
        for qtype in query_types:
            try:
                start_time = time.time()
                
                # UDP query first
                result = subprocess.run([
                    'dig', '+short', '+time=3', target_domain, qtype
                ], capture_output=True, text=True, timeout=5)
                
                end_time = time.time()
                response_time = end_time - start_time
                
                results['queries_sent'] += 1
                results['response_times'].append(response_time)
                
                if result.returncode == 0:
                    results['responses_received'] += 1
                    
                    # Check for truncation (would trigger TCP fallback)
                    if 'truncated' in result.stderr.lower():
                        results['truncated_responses'] += 1
                        
                        # Try TCP fallback
                        tcp_result = subprocess.run([
                            'dig', '+tcp', '+short', '+time=3', target_domain, qtype
                        ], capture_output=True, text=True, timeout=5)
                        
                        if tcp_result.returncode == 0:
                            results['tcp_fallback_triggered'] += 1
                
                # Check response codes
                if 'NXDOMAIN' in result.stderr:
                    results['nxdomain_responses'] += 1
                elif 'SERVFAIL' in result.stderr:
                    results['servfail_responses'] += 1
                
            except subprocess.TimeoutExpired:
                results['queries_sent'] += 1
            except Exception as e:
                logging.debug(f"DNS probe error for {qtype}: {e}")
        
        return results
    
    def _probe_icmp_connectivity(self) -> Dict[str, Any]:
        """Probe ICMP connectivity"""
        results = {
            'pings_sent': 0,
            'pings_received': 0,
            'avg_latency': 0.0,
            'packet_loss': 0.0
        }
        
        try:
            # Ping test
            result = subprocess.run([
                'ping', '-c', '5', '-W', '3', '8.8.8.8'
            ], capture_output=True, text=True, timeout=20)
            
            if result.returncode == 0:
                # Parse ping output
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'packets transmitted' in line:
                        parts = line.split()
                        results['pings_sent'] = int(parts[0])
                        results['pings_received'] = int(parts[3])
                    elif 'avg' in line and 'ms' in line:
                        # Extract average latency
                        parts = line.split('/')
                        if len(parts) >= 5:
                            results['avg_latency'] = float(parts[4])
                
                # Calculate packet loss
                if results['pings_sent'] > 0:
                    results['packet_loss'] = (results['pings_sent'] - results['pings_received']) / results['pings_sent']
        
        except Exception as e:
            logging.debug(f"ICMP probe error: {e}")
        
        return results
    
    def _probe_dpi_behavior(self, target_domain: str) -> Dict[str, Any]:
        """Probe for Deep Packet Inspection behavior"""
        results = {
            'suspicious_patterns_detected': 0,
            'connection_resets': 0,
            'unusual_latencies': 0,
            'pattern_tests': []
        }
        
        # Test patterns that might trigger DPI
        test_patterns = [
            ('normal_query', f'{target_domain}'),
            ('long_subdomain', f'{"a" * 50}.{target_domain}'),
            ('suspicious_txt', f'_test.{target_domain}'),
            ('dnssec_query', f'{target_domain}')
        ]
        
        for pattern_name, query in test_patterns:
            try:
                start_time = time.time()
                
                result = subprocess.run([
                    'dig', '+short', '+time=5', query, 'A'
                ], capture_output=True, text=True, timeout=10)
                
                end_time = time.time()
                latency = end_time - start_time
                
                test_result = {
                    'pattern': pattern_name,
                    'query': query,
                    'success': result.returncode == 0,
                    'latency': latency,
                    'response': result.stdout.strip()[:100]  # First 100 chars
                }
                
                results['pattern_tests'].append(test_result)
                
                # Check for anomalies
                if latency > 5.0:  # Unusually high latency
                    results['unusual_latencies'] += 1
                
                if not test_result['success'] and pattern_name == 'normal_query':
                    results['suspicious_patterns_detected'] += 1
                
            except subprocess.TimeoutExpired:
                results['suspicious_patterns_detected'] += 1
            except Exception as e:
                logging.debug(f"DPI probe error for {pattern_name}: {e}")
        
        return results
    
    def _probe_latency(self, target_domain: str) -> Dict[str, Any]:
        """Probe latency patterns"""
        results = {
            'measurements': [],
            'avg_latency': 0.0,
            'min_latency': float('inf'),
            'max_latency': 0.0,
            'jitter': 0.0
        }
        
        # Perform multiple latency measurements
        for i in range(10):
            try:
                start_time = time.time()
                
                result = subprocess.run([
                    'dig', '+short', '+time=2', target_domain, 'A'
                ], capture_output=True, text=True, timeout=5)
                
                end_time = time.time()
                latency = end_time - start_time
                
                if result.returncode == 0:
                    results['measurements'].append(latency)
                    results['min_latency'] = min(results['min_latency'], latency)
                    results['max_latency'] = max(results['max_latency'], latency)
                
                time.sleep(0.5)  # Small delay between measurements
                
            except Exception as e:
                logging.debug(f"Latency probe error: {e}")
        
        # Calculate statistics
        if results['measurements']:
            results['avg_latency'] = sum(results['measurements']) / len(results['measurements'])
            
            # Calculate jitter (standard deviation)
            if len(results['measurements']) > 1:
                variance = sum((x - results['avg_latency']) ** 2 for x in results['measurements']) / len(results['measurements'])
                results['jitter'] = variance ** 0.5
        
        return results
    
    def _analyze_threats(self, probe_results: Dict[str, Any]) -> str:
        """Analyze probe results for threat level"""
        threat_indicators = []
        
        # Check TCP connectivity issues
        tcp_results = probe_results.get('tcp_probe', {})
        if tcp_results.get('rst_received', 0) > 0:
            threat_indicators.append('tcp_rst')
        
        # Check DNS anomalies
        dns_results = probe_results.get('dns_probe', {})
        queries_sent = dns_results.get('queries_sent', 1)
        truncated_rate = dns_results.get('truncated_responses', 0) / queries_sent
        
        if truncated_rate > self.thresholds['rst_rate_threshold']:
            threat_indicators.append('dns_truncation')
        
        # Check DPI indicators
        dpi_results = probe_results.get('dpi_probe', {})
        if dpi_results.get('suspicious_patterns_detected', 0) >= self.thresholds['dpi_anomaly_threshold']:
            threat_indicators.append('dpi_detected')
        
        # Check latency spikes
        latency_results = probe_results.get('latency_probe', {})
        current_latency = latency_results.get('avg_latency', 0)
        
        if self.baseline_established and current_latency > self.baseline_latency * self.thresholds['latency_spike_threshold']:
            threat_indicators.append('latency_spike')
        elif not self.baseline_established and current_latency > 0:
            self.baseline_latency = current_latency
            self.baseline_established = True
        
        # Determine overall threat level
        if len(threat_indicators) >= 3:
            return 'high'
        elif len(threat_indicators) >= 2:
            return 'medium'
        elif len(threat_indicators) >= 1:
            return 'low'
        else:
            return 'none'
    
    def get_detection_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get detection history for the last N hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        history = []
        for timestamp_str, data in self.detection_results.items():
            timestamp = datetime.fromisoformat(timestamp_str)
            if timestamp >= cutoff_time:
                history.append({
                    'timestamp': timestamp_str,
                    'threat_level': data['threat_level'],
                    'summary': self._summarize_results(data['results'])
                })
        
        return sorted(history, key=lambda x: x['timestamp'])
    
    def _summarize_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Create a summary of probe results"""
        summary = {}
        
        # TCP summary
        tcp = results.get('tcp_probe', {})
        summary['tcp_success_rate'] = tcp.get('successful_connections', 0) / max(1, len(tcp.get('ports_tested', [])))
        
        # DNS summary
        dns = results.get('dns_probe', {})
        summary['dns_success_rate'] = dns.get('responses_received', 0) / max(1, dns.get('queries_sent', 1))
        summary['dns_avg_latency'] = sum(dns.get('response_times', [0])) / max(1, len(dns.get('response_times', [1])))
        
        # DPI summary
        dpi = results.get('dpi_probe', {})
        summary['dpi_anomalies'] = dpi.get('suspicious_patterns_detected', 0)
        
        return summary
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive detection report"""
        if not self.detection_results:
            return {'error': 'No detection data available'}
        
        # Get recent results
        recent_results = list(self.detection_results.values())[-10:]  # Last 10 probes
        
        # Calculate aggregated statistics
        threat_levels = [r['threat_level'] for r in recent_results]
        threat_counts = {
            'none': threat_levels.count('none'),
            'low': threat_levels.count('low'),
            'medium': threat_levels.count('medium'),
            'high': threat_levels.count('high')
        }
        
        # Overall assessment
        if threat_counts['high'] > 0:
            overall_risk = 'high'
        elif threat_counts['medium'] > 2:
            overall_risk = 'medium'
        elif threat_counts['low'] > 5:
            overall_risk = 'low'
        else:
            overall_risk = 'minimal'
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_probes': len(self.detection_results),
            'recent_probes_analyzed': len(recent_results),
            'threat_level_distribution': threat_counts,
            'overall_risk_assessment': overall_risk,
            'baseline_latency': self.baseline_latency,
            'recommendations': self._generate_recommendations(overall_risk, threat_counts)
        }
        
        return report
    
    def _generate_recommendations(self, risk_level: str, threat_counts: Dict[str, int]) -> List[str]:
        """Generate recommendations based on threat analysis"""
        recommendations = []
        
        if risk_level == 'high':
            recommendations.extend([
                "Switch to stealth mode immediately",
                "Reduce transmission frequency significantly",
                "Consider switching to timing-based covert channel",
                "Implement additional traffic obfuscation"
            ])
        elif risk_level == 'medium':
            recommendations.extend([
                "Increase inter-transmission delays",
                "Add more jitter to timing patterns",
                "Monitor for escalation in detection"
            ])
        elif risk_level == 'low':
            recommendations.extend([
                "Continue current operations with caution",
                "Slightly increase timing randomization"
            ])
        else:
            recommendations.append("Current operations appear undetected")
        
        return recommendations
