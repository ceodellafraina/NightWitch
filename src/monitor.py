"""
Monitor
Handles monitoring of scenarios and collection of metrics
"""

import json
import logging
import threading
import time
from pathlib import Path
from typing import Dict, Any
from datetime import datetime

class Monitor:
    """Monitors covert channel scenarios and collects metrics"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.monitoring_threads: Dict[str, threading.Thread] = {}
        self.stop_flags: Dict[str, threading.Event] = {}
        
    def start_monitoring(self, scenario_name: str):
        """Start monitoring a scenario"""
        if scenario_name in self.monitoring_threads:
            raise ValueError(f"Already monitoring scenario '{scenario_name}'")
        
        # Create stop flag for this scenario
        stop_flag = threading.Event()
        self.stop_flags[scenario_name] = stop_flag
        
        # Start monitoring thread
        monitor_thread = threading.Thread(
            target=self._monitor_scenario,
            args=(scenario_name, stop_flag),
            daemon=True
        )
        
        self.monitoring_threads[scenario_name] = monitor_thread
        monitor_thread.start()
        
        logging.info(f"Started monitoring scenario '{scenario_name}'")
    
    def stop_monitoring(self, scenario_name: str):
        """Stop monitoring a scenario"""
        if scenario_name not in self.monitoring_threads:
            raise ValueError(f"Not monitoring scenario '{scenario_name}'")
        
        # Signal stop
        self.stop_flags[scenario_name].set()
        
        # Wait for thread to finish
        self.monitoring_threads[scenario_name].join(timeout=10)
        
        # Clean up
        del self.monitoring_threads[scenario_name]
        del self.stop_flags[scenario_name]
        
        logging.info(f"Stopped monitoring scenario '{scenario_name}'")
    
    def _monitor_scenario(self, scenario_name: str, stop_flag: threading.Event):
        """Monitor a scenario in a separate thread"""
        metrics_file = self.output_dir / f"{scenario_name}_metrics.json"
        start_time = datetime.now()
        
        metrics = {
            "scenario": scenario_name,
            "start_time": start_time.isoformat(),
            "metrics": []
        }
        
        while not stop_flag.is_set():
            try:
                # Collect current metrics
                current_metrics = self._collect_metrics(scenario_name)
                current_metrics["timestamp"] = datetime.now().isoformat()
                
                metrics["metrics"].append(current_metrics)
                
                # Save metrics to file
                with open(metrics_file, 'w') as f:
                    json.dump(metrics, f, indent=2)
                
                # Wait before next collection
                time.sleep(10)  # Collect metrics every 10 seconds
                
            except Exception as e:
                logging.error(f"Error collecting metrics for {scenario_name}: {e}")
                time.sleep(5)
        
        # Final metrics collection
        metrics["end_time"] = datetime.now().isoformat()
        metrics["duration_seconds"] = (datetime.now() - start_time).total_seconds()
        
        with open(metrics_file, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        logging.info(f"Monitoring completed for scenario '{scenario_name}'")
    
    def _collect_metrics(self, scenario_name: str) -> Dict[str, Any]:
        """Collect current metrics for a scenario"""
        metrics = {
            "dns_queries": self._count_dns_queries(),
            "network_traffic": self._measure_network_traffic(),
            "ids_alerts": self._count_ids_alerts(),
            "system_resources": self._get_system_resources()
        }
        
        return metrics
    
    def _count_dns_queries(self) -> int:
        """Count DNS queries (placeholder implementation)"""
        # In a real implementation, this would parse DNS logs or use packet capture
        return 0
    
    def _measure_network_traffic(self) -> Dict[str, int]:
        """Measure network traffic (placeholder implementation)"""
        # In a real implementation, this would measure actual network traffic
        return {
            "bytes_sent": 0,
            "bytes_received": 0,
            "packets_sent": 0,
            "packets_received": 0
        }
    
    def _count_ids_alerts(self) -> int:
        """Count IDS alerts (placeholder implementation)"""
        # In a real implementation, this would parse Suricata/Zeek logs
        return 0
    
    def _get_system_resources(self) -> Dict[str, float]:
        """Get system resource usage (placeholder implementation)"""
        # In a real implementation, this would get actual system metrics
        return {
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "disk_io": 0.0,
            "network_io": 0.0
        }
    
    def generate_report(self, scenario_name: str) -> Dict[str, Any]:
        """Generate a comprehensive report for a scenario"""
        metrics_file = self.output_dir / f"{scenario_name}_metrics.json"
        
        if not metrics_file.exists():
            raise FileNotFoundError(f"No metrics found for scenario '{scenario_name}'")
        
        with open(metrics_file, 'r') as f:
            metrics_data = json.load(f)
        
        # Analyze metrics and generate report
        report = {
            "scenario": scenario_name,
            "summary": self._analyze_metrics(metrics_data),
            "raw_metrics": metrics_data
        }
        
        # Save report
        report_file = self.output_dir / f"{scenario_name}_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
    
    def _analyze_metrics(self, metrics_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze collected metrics and generate summary"""
        if not metrics_data.get("metrics"):
            return {"error": "No metrics data available"}
        
        # Calculate basic statistics
        total_queries = sum(m.get("dns_queries", 0) for m in metrics_data["metrics"])
        total_alerts = sum(m.get("ids_alerts", 0) for m in metrics_data["metrics"])
        
        duration = metrics_data.get("duration_seconds", 0)
        
        return {
            "duration_seconds": duration,
            "total_dns_queries": total_queries,
            "total_ids_alerts": total_alerts,
            "queries_per_second": total_queries / duration if duration > 0 else 0,
            "alert_rate": total_alerts / total_queries if total_queries > 0 else 0,
            "stealth_score": self._calculate_stealth_score(total_alerts, total_queries)
        }
    
    def _calculate_stealth_score(self, alerts: int, queries: int) -> float:
        """Calculate a stealth score based on alert rate"""
        if queries == 0:
            return 0.0
        
        alert_rate = alerts / queries
        
        # Higher score = more stealthy (fewer alerts per query)
        if alert_rate == 0:
            return 100.0
        elif alert_rate < 0.01:  # Less than 1% alert rate
            return 90.0
        elif alert_rate < 0.05:  # Less than 5% alert rate
            return 70.0
        elif alert_rate < 0.1:   # Less than 10% alert rate
            return 50.0
        else:
            return 20.0
