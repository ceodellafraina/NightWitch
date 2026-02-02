#!/usr/bin/env python3
"""
IDS Testing Framework
Integrates with Suricata and Zeek for automated covert channel detection testing
"""

import json
import time
import subprocess
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import yaml
import logging
from datetime import datetime, timedelta
import re
import os

class IDSTester:
    """Automated IDS testing framework for covert channel detection"""
    
    def __init__(self, config_path: str = "config/ids_config.yaml"):
        self.config = self._load_config(config_path)
        self.logger = logging.getLogger(__name__)
        self.test_results = []
        self.suricata_process = None
        self.zeek_process = None
        self.simulation_mode = True  # Enable simulation mode by default
        
    def _load_config(self, config_path: str) -> Dict:
        """Load IDS testing configuration"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            return self._default_config()
    
    def _default_config(self) -> Dict:
        """Default IDS testing configuration"""
        return {
            'suricata': {
                'enabled': True,
                'config_path': '/etc/suricata/suricata.yaml',
                'rules_path': '/var/lib/suricata/rules/',
                'log_path': '/var/log/suricata/',
                'interface': 'eth0'
            },
            'zeek': {
                'enabled': True,
                'config_path': '/usr/local/zeek/etc/zeekctl.cfg',
                'log_path': '/usr/local/zeek/logs/',
                'scripts_path': '/usr/local/zeek/share/zeek/site/'
            },
            'test_scenarios': [
                'baseline_traffic',
                'covert_channel_detection',
                'evasion_techniques',
                'performance_impact'
            ],
            'detection_thresholds': {
                'dns_query_rate': 100,
                'suspicious_domains': 10,
                'entropy_threshold': 0.8,
                'timing_anomaly': 0.3
            }
        }
    
    def setup_ids_environment(self) -> bool:
        """Setup IDS testing environment"""
        try:
            self.logger.info("Setting up IDS testing environment...")
            
            log_dir = Path("logs/ids_testing")
            log_dir.mkdir(parents=True, exist_ok=True)
            
            # Update config to use local paths
            self.config['suricata']['log_path'] = str(log_dir / "suricata")
            self.config['zeek']['log_path'] = str(log_dir / "zeek")
            
            Path(self.config['suricata']['log_path']).mkdir(parents=True, exist_ok=True)
            Path(self.config['zeek']['log_path']).mkdir(parents=True, exist_ok=True)
            
            # Generate custom rules for covert channel detection
            rules_file = self._generate_detection_rules()
            
            # Configure Zeek scripts
            scripts_file = self._setup_zeek_scripts()
            
            self.logger.info(f"IDS environment setup complete:")
            self.logger.info(f"  - Suricata rules: {rules_file}")
            self.logger.info(f"  - Zeek scripts: {scripts_file}")
            self.logger.info(f"  - Log directory: {log_dir}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup IDS environment: {e}")
            return False
    
    def _generate_detection_rules(self):
        """Generate Suricata rules for covert channel detection"""
        rules_dir = Path("config/suricata_rules")
        rules_dir.mkdir(parents=True, exist_ok=True)
        
        rules = [
            # DNS-based covert channel detection
            r'alert dns any any -> any any (msg:"Possible DNS Covert Channel - High Entropy"; '
            r'dns.query; content:!".com"; content:!".org"; content:!".net"; '
            r'threshold:type limit, track by_src, count 10, seconds 60; '
            r'sid:1000001; rev:1;)',
            
            # DNSSEC anomaly detection
            r'alert dns any any -> any any (msg:"DNSSEC Anomaly - Unusual DNSKEY Size"; '
            r'dns.query; dns.rrtype:48; dsize:>512; threshold:type limit, track by_src, '
            r'count 5, seconds 30; sid:1000002; rev:1;)',
            
            # Timing-based detection
            r'alert dns any any -> any any (msg:"DNS Timing Anomaly"; dns.query; '
            r'threshold:type threshold, track by_src, count 50, seconds 10; '
            r'sid:1000003; rev:1;)',
            
            # Base64-like patterns in DNS - Fixed regex escaping
            r'alert dns any any -> any any (msg:"Possible Base64 in DNS Query"; '
            r'dns.query; pcre:"/[A-Za-z0-9+\/]{20,}={0,2}/"; '
            r'threshold:type limit, track by_src, count 3, seconds 60; sid:1000004; rev:1;)',
            
            r'alert dns any any -> any any (msg:"DNSSEC Covert Channel - Sequential DNSKEY"; '
            r'dns.query; dns.rrtype:48; content:"test.local"; '
            r'threshold:type threshold, track by_src, count 10, seconds 30; '
            r'sid:1000005; rev:1;)',
            
            r'alert dns any any -> any any (msg:"DNS TXT Covert Channel"; '
            r'dns.query; dns.rrtype:16; dsize:>200; '
            r'threshold:type limit, track by_src, count 5, seconds 60; '
            r'sid:1000006; rev:1;)'
        ]
        
        rules_file = rules_dir / 'covert_channel.rules'
        with open(rules_file, 'w') as f:
            f.write('\n'.join(rules) + '\n')
        
        self.logger.info(f"Generated {len(rules)} detection rules in {rules_file}")
        return str(rules_file)

    def _setup_zeek_scripts(self):
        """Setup Zeek scripts for covert channel analysis"""
        scripts_dir = Path("config/zeek_scripts")
        scripts_dir.mkdir(parents=True, exist_ok=True)
        
        dns_analysis_script = r'''
@load base/protocols/dns

module CovertDNS;

export {
    redef enum Log::ID += { LOG };
    
    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        query: string &log;
        entropy: double &log;
        suspicious: bool &log;
        query_length: count &log;
        has_base64: bool &log;
    };
    
    global log_covert_dns: event(rec: Info);
}

event zeek_init() {
    Log::create_stream(CovertDNS::LOG, [$columns=Info, $path="covert_dns"]);
}

function calculate_entropy(s: string): double {
    local chars: table[string] of count;
    local total = |s|;
    
    if (total == 0) return 0.0;
    
    for (i in s) {
        local c = s[i];
        if (c in chars)
            chars[c] += 1;
        else
            chars[c] = 1;
    }
    
    local entropy = 0.0;
    for (c in chars) {
        local p = chars[c] * 1.0 / total;
        if (p > 0)
            entropy += -p * log2(p);
    }
    
    return entropy;
}

function has_base64_pattern(s: string): bool {
    # Simple check for base64-like patterns
    local base64_chars = 0;
    local total_chars = |s|;
    
    for (i in s) {
        local c = s[i];
        if (/[A-Za-z0-9+\/=]/ in c)
            base64_chars += 1;
    }
    
    return (base64_chars * 1.0 / total_chars) > 0.8 && total_chars > 10;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    local entropy = calculate_entropy(query);
    local query_len = |query|;
    local has_b64 = has_base64_pattern(query);
    local suspicious = entropy > 4.0 || query_len > 50 || has_b64;
    
    # Additional suspicion for DNSSEC queries
    if (qtype == 48 || qtype == 43 || qtype == 46) {  # DNSKEY, DS, RRSIG
        suspicious = suspicious || query_len > 30;
    }
    
    local rec: CovertDNS::Info = [
        $ts = network_time(),
        $uid = c$uid,
        $id = c$id,
        $query = query,
        $entropy = entropy,
        $suspicious = suspicious,
        $query_length = query_len,
        $has_base64 = has_b64
    ];
    
    Log::write(CovertDNS::LOG, rec);
    
    if (suspicious) {
        event CovertDNS::log_covert_dns(rec);
    }
}
'''
        
        script_file = scripts_dir / 'covert_dns.zeek'
        with open(script_file, 'w') as f:
            f.write(dns_analysis_script)
        
        self.logger.info(f"Setup Zeek covert channel analysis scripts in {script_file}")
        return str(script_file)

    def start_ids_monitoring(self) -> bool:
        """Start IDS monitoring processes"""
        try:
            if self._check_ids_availability():
                self.simulation_mode = False
                self.logger.info("Starting real IDS monitoring...")
                
                if self.config['suricata']['enabled']:
                    self._start_suricata()
                
                if self.config['zeek']['enabled']:
                    self._start_zeek()
                else:
                    self.logger.info("Zeek disabled - using Suricata-only detection")
            else:
                self.logger.info("No IDS tools available, using simulation mode")
                self.simulation_mode = True
                self._start_simulation_mode()
            
            # Wait for IDS systems to initialize
            time.sleep(2)
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start IDS monitoring: {e}")
            return False
    
    def _check_ids_availability(self) -> bool:
        """Check if IDS tools are available on the system"""
        try:
            # Check for Suricata
            subprocess.run(['which', 'suricata'], check=True, capture_output=True)
            suricata_available = True
            self.logger.info("Suricata detected and available")
        except (subprocess.CalledProcessError, FileNotFoundError):
            suricata_available = False
            self.logger.warning("Suricata not found")
        
        try:
            # Check for Zeek
            subprocess.run(['which', 'zeek'], check=True, capture_output=True)
            zeek_available = True
            self.logger.info("Zeek detected and available")
        except (subprocess.CalledProcessError, FileNotFoundError):
            zeek_available = False
            self.logger.warning("Zeek not found")
        
        self.config['suricata']['enabled'] = suricata_available
        self.config['zeek']['enabled'] = zeek_available
        
        if suricata_available and not zeek_available:
            self.logger.info("Running in Suricata-only mode")
        elif zeek_available and not suricata_available:
            self.logger.info("Running in Zeek-only mode")
        elif suricata_available and zeek_available:
            self.logger.info("Running with both Suricata and Zeek")
        
        return suricata_available or zeek_available
    
    def _start_simulation_mode(self):
        """Start IDS simulation mode"""
        self.logger.info("Starting IDS simulation mode...")
        
        # Create simulation log files
        suricata_log_dir = Path(self.config['suricata']['log_path'])
        zeek_log_dir = Path(self.config['zeek']['log_path'])
        
        # Create empty log files for simulation
        (suricata_log_dir / 'fast.log').touch()
        (suricata_log_dir / 'eve.json').touch()
        (zeek_log_dir / 'covert_dns.log').touch()
        
        self.logger.info("IDS simulation mode active")
    
    def _start_suricata(self):
        """Start Suricata IDS"""
        cmd = [
            'suricata',
            '-c', self.config['suricata']['config_path'],
            '-i', self.config['suricata']['interface'],
            '-l', self.config['suricata']['log_path'],
            '--init-errors-fatal'
        ]
        
        self.suricata_process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.logger.info("Started Suricata IDS")
    
    def _start_zeek(self):
        """Start Zeek network analyzer"""
        cmd = ['zeek', '-i', self.config['suricata']['interface'], 'local']
        
        self.zeek_process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=self.config['zeek']['scripts_path']
        )
        self.logger.info("Started Zeek network analyzer")

    def run_test_scenario(self, scenario_name: str, covert_channel, payload: bytes) -> Dict:
        """Run a specific test scenario"""
        self.logger.info(f"Running test scenario: {scenario_name}")
        
        start_time = datetime.now()
        
        # Clear previous logs
        self._clear_ids_logs()
        
        # Execute covert channel operation
        if scenario_name == 'baseline_traffic':
            result = self._test_baseline_traffic()
        elif scenario_name == 'covert_channel_detection':
            result = self._test_covert_channel_detection(covert_channel, payload)
        elif scenario_name == 'evasion_techniques':
            result = self._test_evasion_techniques(covert_channel, payload)
        elif scenario_name == 'performance_impact':
            result = self._test_performance_impact(covert_channel, payload)
        else:
            raise ValueError(f"Unknown test scenario: {scenario_name}")
        
        # Wait for IDS processing
        time.sleep(10)
        
        # Analyze IDS logs
        detection_results = self._analyze_ids_logs()
        
        end_time = datetime.now()
        
        test_result = {
            'scenario': scenario_name,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration': (end_time - start_time).total_seconds(),
            'covert_operation': result,
            'ids_detection': detection_results,
            'detected': detection_results['alerts_count'] > 0,
            'stealth_score': self._calculate_stealth_score(detection_results)
        }
        
        self.test_results.append(test_result)
        return test_result
    
    def _test_baseline_traffic(self) -> Dict:
        """Generate baseline DNS traffic for comparison"""
        import random
        import socket
        
        domains = ['google.com', 'facebook.com', 'amazon.com', 'microsoft.com']
        queries_sent = 0
        
        for _ in range(50):
            domain = random.choice(domains)
            try:
                socket.gethostbyname(domain)
                queries_sent += 1
                time.sleep(random.uniform(0.1, 2.0))
            except:
                pass
        
        return {
            'type': 'baseline',
            'queries_sent': queries_sent,
            'success': True
        }
    
    def _test_covert_channel_detection(self, covert_channel, payload: bytes) -> Dict:
        """Test basic covert channel detection"""
        try:
            # Send payload through covert channel
            covert_channel.send_data(payload)
            
            return {
                'type': 'covert_channel',
                'payload_size': len(payload),
                'success': True,
                'method': 'dnssec_dnskey'
            }
        except Exception as e:
            return {
                'type': 'covert_channel',
                'payload_size': len(payload),
                'success': False,
                'error': str(e)
            }
    
    def _test_evasion_techniques(self, covert_channel, payload: bytes) -> Dict:
        """Test evasion techniques against IDS"""
        try:
            # Enable traffic shaping and timing randomization
            covert_channel.enable_stealth_mode()
            covert_channel.set_timing_profile('random')
            
            # Send payload with evasion
            covert_channel.send_data(payload)
            
            return {
                'type': 'evasion',
                'payload_size': len(payload),
                'success': True,
                'techniques': ['traffic_shaping', 'timing_randomization']
            }
        except Exception as e:
            return {
                'type': 'evasion',
                'payload_size': len(payload),
                'success': False,
                'error': str(e)
            }
    
    def _test_performance_impact(self, covert_channel, payload: bytes) -> Dict:
        """Test performance impact of covert channel"""
        import psutil
        
        # Measure system resources before
        cpu_before = psutil.cpu_percent(interval=1)
        memory_before = psutil.virtual_memory().percent
        
        start_time = time.time()
        
        try:
            covert_channel.send_data(payload)
            success = True
            error = None
        except Exception as e:
            success = False
            error = str(e)
        
        end_time = time.time()
        
        # Measure system resources after
        cpu_after = psutil.cpu_percent(interval=1)
        memory_after = psutil.virtual_memory().percent
        
        return {
            'type': 'performance',
            'payload_size': len(payload),
            'success': success,
            'error': error,
            'duration': end_time - start_time,
            'cpu_usage': {
                'before': cpu_before,
                'after': cpu_after,
                'delta': cpu_after - cpu_before
            },
            'memory_usage': {
                'before': memory_before,
                'after': memory_after,
                'delta': memory_after - memory_before
            }
        }
    
    def _clear_ids_logs(self):
        """Clear IDS log files"""
        try:
            # Clear Suricata logs
            suricata_logs = Path(self.config['suricata']['log_path'])
            for log_file in suricata_logs.glob('*.log'):
                log_file.unlink(missing_ok=True)
            
            # Clear Zeek logs
            zeek_logs = Path(self.config['zeek']['log_path'])
            for log_file in zeek_logs.glob('*.log'):
                log_file.unlink(missing_ok=True)
                
        except Exception as e:
            self.logger.warning(f"Failed to clear some log files: {e}")
    
    def _analyze_ids_logs(self) -> Dict:
        """Analyze IDS logs for detections"""
        results = {
            'suricata_alerts': [],
            'zeek_alerts': [],
            'alerts_count': 0,
            'suspicious_patterns': []
        }
        
        if self.simulation_mode:
            return self._simulate_detection_analysis()
        
        # Analyze Suricata alerts
        try:
            alert_file = Path(self.config['suricata']['log_path']) / 'fast.log'
            if alert_file.exists():
                with open(alert_file, 'r') as f:
                    for line in f:
                        if 'Possible DNS Covert Channel' in line or 'DNSSEC Anomaly' in line:
                            results['suricata_alerts'].append(line.strip())
                            results['alerts_count'] += 1
        except Exception as e:
            self.logger.warning(f"Failed to analyze Suricata logs: {e}")
        
        # Analyze Zeek logs
        try:
            covert_dns_log = Path(self.config['zeek']['log_path']) / 'covert_dns.log'
            if covert_dns_log.exists():
                with open(covert_dns_log, 'r') as f:
                    for line in f:
                        if 'suspicious=T' in line:
                            results['zeek_alerts'].append(line.strip())
                            results['alerts_count'] += 1
        except Exception as e:
            self.logger.warning(f"Failed to analyze Zeek logs: {e}")
        
        return results
    
    def _simulate_detection_analysis(self) -> Dict:
        """Simulate IDS detection analysis"""
        import random
        
        # Simulate realistic detection patterns
        base_detection_rate = 0.3  # 30% base detection rate
        
        # Check recent DNS activity for simulation
        dns_activity = self._check_recent_dns_activity()
        
        results = {
            'suricata_alerts': [],
            'zeek_alerts': [],
            'alerts_count': 0,
            'suspicious_patterns': [],
            'simulation_mode': True
        }
        
        if dns_activity['covert_patterns'] > 0:
            # Simulate Suricata alerts
            if random.random() < base_detection_rate:
                alert = f"[SIMULATION] DNSSEC Covert Channel - Sequential DNSKEY detected: {dns_activity['covert_patterns']} patterns"
                results['suricata_alerts'].append(alert)
                results['alerts_count'] += 1
            
            if dns_activity['high_entropy_queries'] > 5:
                if random.random() < 0.4:
                    alert = f"[SIMULATION] High entropy DNS queries detected: {dns_activity['high_entropy_queries']} queries"
                    results['suricata_alerts'].append(alert)
                    results['alerts_count'] += 1
            
            # Simulate Zeek analysis
            if dns_activity['suspicious_timing'] and random.random() < 0.25:
                alert = f"[SIMULATION] Suspicious DNS timing patterns detected"
                results['zeek_alerts'].append(alert)
                results['alerts_count'] += 1
        
        return results
    
    def _check_recent_dns_activity(self) -> Dict:
        """Check recent DNS activity for simulation"""
        # This would normally analyze actual network traffic
        # For simulation, we'll check if there are recent zone files or logs
        
        activity = {
            'covert_patterns': 0,
            'high_entropy_queries': 0,
            'suspicious_timing': False,
            'total_queries': 0
        }
        
        try:
            # Check for recent zone file modifications
            zone_files = list(Path('.').glob('**/*.zone'))
            recent_zones = [f for f in zone_files if f.stat().st_mtime > time.time() - 300]  # Last 5 minutes
            
            if recent_zones:
                activity['covert_patterns'] = len(recent_zones) * 10  # Simulate pattern detection
                activity['high_entropy_queries'] = len(recent_zones) * 15
                activity['suspicious_timing'] = len(recent_zones) > 1
                activity['total_queries'] = len(recent_zones) * 50
            
            # Check for recent log activity
            log_files = list(Path('logs').glob('**/*.log')) if Path('logs').exists() else []
            recent_logs = [f for f in log_files if f.stat().st_mtime > time.time() - 300]
            
            if recent_logs:
                activity['total_queries'] += len(recent_logs) * 20
                
        except Exception as e:
            self.logger.debug(f"Error checking DNS activity: {e}")
        
        return activity

    def stop_ids_monitoring(self):
        """Stop IDS monitoring processes"""
        if self.suricata_process:
            self.suricata_process.terminate()
            self.suricata_process.wait()
            self.logger.info("Stopped Suricata IDS")
        
        if self.zeek_process:
            self.zeek_process.terminate()
            self.zeek_process.wait()
            self.logger.info("Stopped Zeek network analyzer")
    
    def generate_test_report(self, output_file: str = None) -> Dict:
        """Generate comprehensive test report"""
        if not self.test_results:
            return {'error': 'No test results available'}
        
        report = {
            'test_summary': {
                'total_tests': len(self.test_results),
                'successful_tests': sum(1 for r in self.test_results if r['covert_operation']['success']),
                'detected_tests': sum(1 for r in self.test_results if r['detected']),
                'average_stealth_score': sum(r['stealth_score'] for r in self.test_results) / len(self.test_results)
            },
            'test_results': self.test_results,
            'recommendations': self._generate_recommendations()
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            self.logger.info(f"Test report saved to {output_file}")
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results"""
        recommendations = []
        
        detected_count = sum(1 for r in self.test_results if r['detected'])
        total_count = len(self.test_results)
        
        if detected_count > total_count * 0.5:
            recommendations.append("High detection rate - consider implementing additional evasion techniques")
        
        avg_stealth = sum(r['stealth_score'] for r in self.test_results) / total_count
        if avg_stealth < 50:
            recommendations.append("Low stealth scores - review traffic patterns and timing")
        
        # Check for specific patterns
        for result in self.test_results:
            if result['scenario'] == 'evasion_techniques' and result['detected']:
                recommendations.append("Evasion techniques ineffective - consider alternative approaches")
        
        if not recommendations:
            recommendations.append("Covert channel shows good stealth characteristics")
        
        return recommendations
    
    def _calculate_stealth_score(self, detection_results: Dict) -> float:
        """Calculate stealth score based on detection results (0-100, higher is better)"""
        base_score = 100.0
        
        # Penalize for alerts
        alerts_penalty = detection_results['alerts_count'] * 15
        base_score -= alerts_penalty
        
        # Additional penalties for specific detection patterns
        if 'suricata_alerts' in detection_results:
            for alert in detection_results['suricata_alerts']:
                if 'High Entropy' in alert:
                    base_score -= 10
                if 'Sequential DNSKEY' in alert:
                    base_score -= 20
                if 'Timing Anomaly' in alert:
                    base_score -= 15
        
        if 'zeek_alerts' in detection_results:
            for alert in detection_results['zeek_alerts']:
                if 'suspicious=T' in alert:
                    base_score -= 12
        
        # Bonus for successful evasion in simulation mode
        if detection_results.get('simulation_mode', False):
            if detection_results['alerts_count'] == 0:
                base_score += 10  # Bonus for clean simulation
        
        # Ensure score is within bounds
        return max(0.0, min(100.0, base_score))

# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Initialize IDS tester
    ids_tester = IDSTester()
    
    # Setup environment
    if ids_tester.setup_ids_environment():
        print("IDS testing environment ready")
    else:
        print("Failed to setup IDS environment")
