#!/usr/bin/env python3
"""
Advanced Reporting Module
Generates comprehensive reports with visualizations and recommendations
"""

import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from jinja2 import Template
from pathlib import Path
from datetime import datetime
from typing import Dict, List
import logging

class AdvancedReportGenerator:
    """Advanced report generator with multiple output formats"""
    
    def __init__(self, analytics_engine):
        self.analytics = analytics_engine
        self.logger = logging.getLogger(__name__)
        self.report_templates = self._load_templates()
    
    def _load_templates(self) -> Dict[str, str]:
        """Load report templates"""
        return {
            'executive': """
# Covert Channel Operations - Executive Summary

**Report Period:** {{ report_period }}  
**Generated:** {{ generated_at }}

## Key Performance Indicators

| Metric | Value | Status |
|--------|-------|--------|
| Total Operations | {{ metrics.total_operations }} | ✓ |
| Success Rate | {{ "%.1f"|format(metrics.success_rate) }}% | {{ success_status }} |
| Average Stealth Score | {{ "%.1f"|format(metrics.average_stealth_score) }} | {{ stealth_status }} |
| Detection Rate | {{ "%.1f"|format(metrics.detection_rate) }}% | {{ detection_status }} |

## Security Assessment

**Risk Level:** {{ security.risk_level|upper }}

### Recommendations:
{% for rec in security.recommendations %}
- {{ rec }}
{% endfor %}

## Channel Performance Summary

{% for channel, stats in channel_breakdown.items() %}
### {{ channel|title }}
- Operations: {{ stats.success }}
- Avg Stealth Score: {{ "%.1f"|format(stats.stealth_score) }}
{% endfor %}
            """,
            
            'technical': """
# Technical Analysis Report

## Detailed Statistics

### Payload Analysis
- **Size Range:** {{ detailed_stats.payload_size.min }} - {{ detailed_stats.payload_size.max }} bytes
- **Average Size:** {{ "%.0f"|format(detailed_stats.payload_size.mean) }} bytes
- **Standard Deviation:** {{ "%.0f"|format(detailed_stats.payload_size.std) }} bytes

### Performance Metrics
- **Transmission Time:** {{ "%.2f"|format(detailed_stats.transmission_time.mean) }}s average
- **Compression Ratio:** {{ "%.2f"|format(detailed_stats.compression_ratio.mean) }}:1

### Error Analysis
- **Operations with Errors:** {{ error_analysis.operations_with_errors }}
- **Average Error Rate:** {{ "%.3f"|format(error_analysis.average_error_rate) }}%
- **Error-Detection Correlation:** {{ "%.3f"|format(error_analysis.error_correlation) }}

## Anomaly Detection

{% if anomalies %}
### Detected Anomalies:
{% for anomaly in anomalies %}
- **{{ anomaly.operation_id }}** ({{ anomaly.timestamp }}): {{ anomaly.metric }} anomaly (Z-score: {{ "%.2f"|format(anomaly.z_score) }})
{% endfor %}
{% else %}
No significant anomalies detected.
{% endif %}
            """
        }
    
    def generate_markdown_report(self, report_type: str = 'executive', days: int = 30) -> str:
        """Generate markdown report"""
        if report_type == 'executive':
            data = self.analytics.generate_executive_summary(days)
        else:
            data = self.analytics.generate_technical_report(days)
        
        template = Template(self.report_templates[report_type])
        
        # Add status indicators
        if 'key_metrics' in data:
            metrics = data['key_metrics']
            data['success_status'] = '✅' if metrics['success_rate'] > 80 else '⚠️'
            data['stealth_status'] = '✅' if metrics['average_stealth_score'] > 70 else '⚠️'
            data['detection_status'] = '⚠️' if metrics['detection_rate'] > 20 else '✅'
        
        return template.render(**data)
    
    def save_markdown_report(self, report_type: str = 'executive', 
                           days: int = 30, filename: str = None) -> str:
        """Save markdown report to file"""
        content = self.generate_markdown_report(report_type, days)
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"reports/{report_type}_report_{timestamp}.md"
        
        output_path = Path(filename)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            f.write(content)
        
        self.logger.info(f"Markdown report saved to {output_path}")
        return str(output_path)

# Integration with main controller
def integrate_analytics_with_controller():
    """Integration function for main controller"""
    from .analytics import AnalyticsEngine, ReportGenerator
    from .reporting import AdvancedReportGenerator
    
    analytics = AnalyticsEngine()
    report_gen = ReportGenerator(analytics)
    advanced_reports = AdvancedReportGenerator(analytics)
    
    return {
        'analytics': analytics,
        'reports': report_gen,
        'advanced_reports': advanced_reports
    }
