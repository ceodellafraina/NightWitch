"""
Traffic Shaping Module
Enforces timing/size distributions and applies jitter/noise to match baseline traffic
"""

import time
import random
import logging
import numpy as np
from typing import Dict, Any, List, Optional
from scipy import stats
from datetime import datetime, timedelta

class TrafficShaper:
    """Shapes covert channel traffic to match baseline patterns"""
    
    def __init__(self):
        self.baseline_stats: Dict[str, Any] = {}
        self.current_profile: Dict[str, Any] = {}
        self.last_transmission: Optional[datetime] = None
        
    def configure(self, frequency: str, domain: str, profile: str = "normal"):
        """Configure traffic shaping parameters"""
        self.current_profile = {
            'frequency': frequency,
            'domain': domain,
            'profile': profile,
            'configured_at': datetime.now().isoformat()
        }
        
        # Parse frequency string (e.g., "5s", "30s", "2m")
        self.base_interval = self._parse_frequency(frequency)
        
        # Load or generate baseline statistics
        self._load_baseline_stats(domain, profile)
        
        logging.info(f"Traffic shaper configured: {frequency} interval, {profile} profile")
    
    def _parse_frequency(self, frequency: str) -> float:
        """Parse frequency string to seconds"""
        if frequency.endswith('s'):
            return float(frequency[:-1])
        elif frequency.endswith('m'):
            return float(frequency[:-1]) * 60
        elif frequency.endswith('h'):
            return float(frequency[:-1]) * 3600
        else:
            # Assume seconds if no unit
            return float(frequency)
    
    def _load_baseline_stats(self, domain: str, profile: str):
        """Load or generate baseline traffic statistics"""
        # In a real implementation, this would load actual baseline data
        # For PoC, we'll generate realistic statistical parameters
        
        if profile == "normal":
            self.baseline_stats = {
                'inter_arrival_mean': self.base_interval,
                'inter_arrival_std': self.base_interval * 0.2,
                'query_size_mean': 64,
                'query_size_std': 16,
                'response_size_mean': 128,
                'response_size_std': 32,
                'distribution': 'gaussian'
            }
        elif profile == "bursty":
            self.baseline_stats = {
                'inter_arrival_mean': self.base_interval,
                'inter_arrival_std': self.base_interval * 0.5,
                'query_size_mean': 64,
                'query_size_std': 24,
                'response_size_mean': 128,
                'response_size_std': 48,
                'distribution': 'exponential'
            }
        elif profile == "stealth":
            self.baseline_stats = {
                'inter_arrival_mean': self.base_interval * 2,  # Slower
                'inter_arrival_std': self.base_interval * 0.1,  # More consistent
                'query_size_mean': 64,
                'query_size_std': 8,
                'response_size_mean': 128,
                'response_size_std': 16,
                'distribution': 'gaussian'
            }
        
        logging.info(f"Loaded baseline stats for {profile} profile")
    
    def apply_delay(self):
        """Apply traffic shaping delay before next transmission"""
        if self.last_transmission is None:
            self.last_transmission = datetime.now()
            return
        
        # Calculate time since last transmission
        now = datetime.now()
        elapsed = (now - self.last_transmission).total_seconds()
        
        # Generate next interval based on baseline statistics
        next_interval = self._generate_interval()
        
        # Calculate required delay
        required_delay = max(0, next_interval - elapsed)
        
        if required_delay > 0:
            logging.debug(f"Applying traffic shaping delay: {required_delay:.2f}s")
            time.sleep(required_delay)
        
        self.last_transmission = datetime.now()
    
    def _generate_interval(self) -> float:
        """Generate next transmission interval based on baseline statistics"""
        distribution = self.baseline_stats.get('distribution', 'gaussian')
        mean = self.baseline_stats['inter_arrival_mean']
        std = self.baseline_stats['inter_arrival_std']
        
        if distribution == 'gaussian':
            # Normal distribution with minimum bound
            interval = max(0.1, np.random.normal(mean, std))
        elif distribution == 'exponential':
            # Exponential distribution
            interval = np.random.exponential(mean)
        else:
            # Fallback to uniform distribution
            interval = np.random.uniform(mean * 0.5, mean * 1.5)
        
        return interval
    
    def add_jitter(self, base_delay: float, jitter_percent: float = 10.0) -> float:
        """Add random jitter to a base delay"""
        jitter_amount = base_delay * (jitter_percent / 100.0)
        jitter = random.uniform(-jitter_amount, jitter_amount)
        return max(0.1, base_delay + jitter)
    
    def calculate_ks_statistic(self, observed_intervals: List[float]) -> float:
        """Calculate Kolmogorov-Smirnov statistic against baseline"""
        if not observed_intervals or len(observed_intervals) < 10:
            return 1.0  # Poor score for insufficient data
        
        # Generate expected distribution
        mean = self.baseline_stats['inter_arrival_mean']
        std = self.baseline_stats['inter_arrival_std']
        
        # Perform KS test
        ks_statistic, p_value = stats.kstest(
            observed_intervals,
            lambda x: stats.norm.cdf(x, loc=mean, scale=std)
        )
        
        logging.info(f"KS statistic: {ks_statistic:.4f}, p-value: {p_value:.4f}")
        return ks_statistic
    
    def adapt_profile(self, detection_level: str):
        """Adapt traffic profile based on detection feedback"""
        if detection_level == "high":
            # Switch to stealth mode
            self._load_baseline_stats(self.current_profile['domain'], "stealth")
            logging.warning("High detection - switching to stealth profile")
        elif detection_level == "medium":
            # Reduce frequency
            self.base_interval *= 1.5
            self.baseline_stats['inter_arrival_mean'] = self.base_interval
            logging.warning("Medium detection - reducing transmission frequency")
        elif detection_level == "low":
            # Slightly increase jitter
            self.baseline_stats['inter_arrival_std'] *= 1.2
            logging.info("Low detection - increasing timing jitter")
        
        self.current_profile['adapted_at'] = datetime.now().isoformat()
        self.current_profile['adaptation_reason'] = detection_level
    
    def get_timing_stats(self) -> Dict[str, Any]:
        """Get current timing statistics"""
        return {
            'baseline_stats': self.baseline_stats.copy(),
            'current_profile': self.current_profile.copy(),
            'last_transmission': self.last_transmission.isoformat() if self.last_transmission else None
        }
    
    def validate_timing_pattern(self, intervals: List[float], threshold: float = 0.1) -> bool:
        """Validate that timing pattern matches baseline within threshold"""
        if not intervals:
            return False
        
        ks_stat = self.calculate_ks_statistic(intervals)
        return ks_stat < threshold
    
    def generate_baseline_traffic(self, duration_minutes: int = 60) -> List[Dict[str, Any]]:
        """Generate baseline traffic pattern for comparison"""
        baseline_events = []
        current_time = datetime.now()
        end_time = current_time + timedelta(minutes=duration_minutes)
        
        while current_time < end_time:
            # Generate next event time
            interval = self._generate_interval()
            current_time += timedelta(seconds=interval)
            
            # Generate event properties
            event = {
                'timestamp': current_time.isoformat(),
                'interval': interval,
                'query_size': max(32, int(np.random.normal(
                    self.baseline_stats['query_size_mean'],
                    self.baseline_stats['query_size_std']
                ))),
                'response_size': max(64, int(np.random.normal(
                    self.baseline_stats['response_size_mean'],
                    self.baseline_stats['response_size_std']
                )))
            }
            
            baseline_events.append(event)
        
        logging.info(f"Generated {len(baseline_events)} baseline events over {duration_minutes} minutes")
        return baseline_events
