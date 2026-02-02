#!/usr/bin/env python3
"""
Analytics and Reporting System
Comprehensive analysis and reporting for covert channel operations
"""

import json
import sqlite3
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging
from dataclasses import dataclass, asdict
import hashlib

@dataclass
class OperationMetrics:
    """Metrics for a single covert channel operation"""
    timestamp: datetime
    operation_id: str
    channel_type: str
    payload_size: int
    encoded_size: int
    transmission_time: float
    success: bool
    detection_score: float
    stealth_score: float
    bandwidth_used: int
    error_rate: float
    latency: float

class AnalyticsEngine:
    """Advanced analytics engine for covert channel operations"""
    
    def __init__(self, db_path: str = "data/analytics.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
        self._init_database()
        
    def _init_database(self):
        """Initialize SQLite database for analytics storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Operations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                operation_id TEXT UNIQUE NOT NULL,
                channel_type TEXT NOT NULL,
                payload_size INTEGER NOT NULL,
                encoded_size INTEGER NOT NULL,
                transmission_time REAL NOT NULL,
                success BOOLEAN NOT NULL,
                detection_score REAL NOT NULL,
                stealth_score REAL NOT NULL,
                bandwidth_used INTEGER NOT NULL,
                error_rate REAL NOT NULL,
                latency REAL NOT NULL
            )
        ''')
        
        # IDS alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ids_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                ids_type TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity INTEGER NOT NULL,
                message TEXT NOT NULL,
                FOREIGN KEY (operation_id) REFERENCES operations (operation_id)
            )
        ''')
        
        # Performance metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                cpu_usage REAL NOT NULL,
                memory_usage REAL NOT NULL,
                network_io INTEGER NOT NULL,
                disk_io INTEGER NOT NULL,
                FOREIGN KEY (operation_id) REFERENCES operations (operation_id)
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def record_operation(self, metrics: OperationMetrics):
        """Record operation metrics in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO operations 
                (timestamp, operation_id, channel_type, payload_size, encoded_size,
                 transmission_time, success, detection_score, stealth_score,
                 bandwidth_used, error_rate, latency)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                metrics.timestamp.isoformat(),
                metrics.operation_id,
                metrics.channel_type,
                metrics.payload_size,
                metrics.encoded_size,
                metrics.transmission_time,
                metrics.success,
                metrics.detection_score,
                metrics.stealth_score,
                metrics.bandwidth_used,
                metrics.error_rate,
                metrics.latency
            ))
            
            conn.commit()
            self.logger.info(f"Recorded operation metrics: {metrics.operation_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to record operation metrics: {e}")
            conn.rollback()
        finally:
            conn.close()
    
    def record_ids_alert(self, operation_id: str, ids_type: str, 
                        alert_type: str, severity: int, message: str):
        """Record IDS alert"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO ids_alerts 
                (timestamp, operation_id, ids_type, alert_type, severity, message)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                operation_id,
                ids_type,
                alert_type,
                severity,
                message
            ))
            
            conn.commit()
            
        except Exception as e:
            self.logger.error(f"Failed to record IDS alert: {e}")
            conn.rollback()
        finally:
            conn.close()
    
    def get_operations_dataframe(self, days: int = 30) -> pd.DataFrame:
        """Get operations data as pandas DataFrame"""
        conn = sqlite3.connect(self.db_path)
        
        query = '''
            SELECT * FROM operations 
            WHERE timestamp >= datetime('now', '-{} days')
            ORDER BY timestamp DESC
        '''.format(days)
        
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        return df
    
    def calculate_success_rate(self, channel_type: str = None, days: int = 7) -> float:
        """Calculate success rate for operations"""
        df = self.get_operations_dataframe(days)
        
        if df.empty:
            return 0.0
        
        if channel_type:
            df = df[df['channel_type'] == channel_type]
        
        if df.empty:
            return 0.0
        
        return df['success'].mean() * 100
    
    def calculate_detection_rate(self, channel_type: str = None, days: int = 7) -> float:
        """Calculate detection rate (operations with detection_score > 0.5)"""
        df = self.get_operations_dataframe(days)
        
        if df.empty:
            return 0.0
        
        if channel_type:
            df = df[df['channel_type'] == channel_type]
        
        if df.empty:
            return 0.0
        
        detected = df['detection_score'] > 0.5
        return detected.mean() * 100
    
    def calculate_average_stealth_score(self, channel_type: str = None, days: int = 7) -> float:
        """Calculate average stealth score"""
        df = self.get_operations_dataframe(days)
        
        if df.empty:
            return 0.0
        
        if channel_type:
            df = df[df['channel_type'] == channel_type]
        
        if df.empty:
            return 0.0
        
        return df['stealth_score'].mean()
    
    def analyze_performance_trends(self, days: int = 30) -> Dict:
        """Analyze performance trends over time"""
        df = self.get_operations_dataframe(days)
        
        if df.empty:
            return {'error': 'No data available'}
        
        # Group by day
        df['date'] = df['timestamp'].dt.date
        daily_stats = df.groupby('date').agg({
            'success': 'mean',
            'detection_score': 'mean',
            'stealth_score': 'mean',
            'transmission_time': 'mean',
            'bandwidth_used': 'sum',
            'error_rate': 'mean'
        }).reset_index()
        
        # Calculate trends
        trends = {}
        for column in ['success', 'detection_score', 'stealth_score', 'transmission_time']:
            if len(daily_stats) > 1:
                correlation = np.corrcoef(range(len(daily_stats)), daily_stats[column])[0, 1]
                trends[column] = {
                    'trend': 'improving' if correlation > 0.1 else 'declining' if correlation < -0.1 else 'stable',
                    'correlation': correlation
                }
            else:
                trends[column] = {'trend': 'insufficient_data', 'correlation': 0}
        
        return {
            'daily_stats': daily_stats.to_dict('records'),
            'trends': trends,
            'summary': {
                'total_operations': len(df),
                'avg_success_rate': df['success'].mean() * 100,
                'avg_stealth_score': df['stealth_score'].mean(),
                'total_bandwidth': df['bandwidth_used'].sum()
            }
        }
    
    def generate_channel_comparison(self) -> Dict:
        """Compare performance across different channel types"""
        df = self.get_operations_dataframe(30)
        
        if df.empty:
            return {'error': 'No data available'}
        
        comparison = df.groupby('channel_type').agg({
            'success': ['count', 'mean'],
            'detection_score': 'mean',
            'stealth_score': 'mean',
            'transmission_time': 'mean',
            'bandwidth_used': 'mean',
            'error_rate': 'mean'
        }).round(3)
        
        # Flatten column names
        comparison.columns = ['_'.join(col).strip() for col in comparison.columns]
        
        return {
            'channel_comparison': comparison.to_dict('index'),
            'best_stealth': comparison['stealth_score_mean'].idxmax(),
            'most_reliable': comparison['success_mean'].idxmax(),
            'fastest': comparison['transmission_time_mean'].idxmin()
        }
    
    def detect_anomalies(self, threshold: float = 2.0) -> List[Dict]:
        """Detect anomalous operations using statistical analysis"""
        df = self.get_operations_dataframe(30)
        
        if df.empty or len(df) < 10:
            return []
        
        anomalies = []
        
        # Check for anomalies in key metrics
        metrics = ['transmission_time', 'detection_score', 'bandwidth_used', 'error_rate']
        
        for metric in metrics:
            mean_val = df[metric].mean()
            std_val = df[metric].std()
            
            if std_val > 0:
                z_scores = np.abs((df[metric] - mean_val) / std_val)
                anomalous_ops = df[z_scores > threshold]
                
                for _, op in anomalous_ops.iterrows():
                    anomalies.append({
                        'operation_id': op['operation_id'],
                        'timestamp': op['timestamp'].isoformat(),
                        'metric': metric,
                        'value': op[metric],
                        'z_score': z_scores[op.name],
                        'severity': 'high' if z_scores[op.name] > 3.0 else 'medium'
                    })
        
        return sorted(anomalies, key=lambda x: x['z_score'], reverse=True)
    
    def generate_security_assessment(self) -> Dict:
        """Generate comprehensive security assessment"""
        df = self.get_operations_dataframe(30)
        
        if df.empty:
            return {'error': 'No data available'}
        
        # Calculate security metrics
        detection_rate = (df['detection_score'] > 0.5).mean() * 100
        avg_stealth = df['stealth_score'].mean()
        success_rate = df['success'].mean() * 100
        
        # Risk assessment
        risk_level = 'low'
        if detection_rate > 30:
            risk_level = 'high'
        elif detection_rate > 15:
            risk_level = 'medium'
        
        # Get IDS alerts
        conn = sqlite3.connect(self.db_path)
        alerts_df = pd.read_sql_query('''
            SELECT ids_type, alert_type, COUNT(*) as count
            FROM ids_alerts 
            WHERE timestamp >= datetime('now', '-30 days')
            GROUP BY ids_type, alert_type
            ORDER BY count DESC
        ''', conn)
        conn.close()
        
        return {
            'risk_level': risk_level,
            'detection_rate': detection_rate,
            'average_stealth_score': avg_stealth,
            'success_rate': success_rate,
            'total_operations': len(df),
            'ids_alerts': alerts_df.to_dict('records') if not alerts_df.empty else [],
            'recommendations': self._generate_security_recommendations(detection_rate, avg_stealth, success_rate)
        }
    
    def _generate_security_recommendations(self, detection_rate: float, 
                                         avg_stealth: float, success_rate: float) -> List[str]:
        """Generate security recommendations based on metrics"""
        recommendations = []
        
        if detection_rate > 20:
            recommendations.append("High detection rate detected - implement additional evasion techniques")
        
        if avg_stealth < 60:
            recommendations.append("Low stealth scores - review traffic patterns and timing strategies")
        
        if success_rate < 80:
            recommendations.append("Low success rate - check network conditions and payload encoding")
        
        if detection_rate < 5 and avg_stealth > 80:
            recommendations.append("Excellent stealth performance - current configuration is optimal")
        
        return recommendations
    
    def create_visualization_dashboard(self, output_dir: str = "reports/visualizations"):
        """Create comprehensive visualization dashboard"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        df = self.get_operations_dataframe(30)
        
        if df.empty:
            self.logger.warning("No data available for visualization")
            return
        
        # Set style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
        # 1. Success Rate Over Time
        fig, ax = plt.subplots(figsize=(12, 6))
        df['date'] = df['timestamp'].dt.date
        daily_success = df.groupby('date')['success'].mean() * 100
        daily_success.plot(kind='line', ax=ax, marker='o')
        ax.set_title('Success Rate Over Time')
        ax.set_ylabel('Success Rate (%)')
        ax.set_xlabel('Date')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(output_path / 'success_rate_trend.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 2. Stealth Score Distribution
        fig, ax = plt.subplots(figsize=(10, 6))
        df['stealth_score'].hist(bins=20, ax=ax, alpha=0.7)
        ax.axvline(df['stealth_score'].mean(), color='red', linestyle='--', 
                  label=f'Mean: {df["stealth_score"].mean():.1f}')
        ax.set_title('Stealth Score Distribution')
        ax.set_xlabel('Stealth Score')
        ax.set_ylabel('Frequency')
        ax.legend()
        plt.tight_layout()
        plt.savefig(output_path / 'stealth_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 3. Channel Type Performance Comparison
        if len(df['channel_type'].unique()) > 1:
            fig, axes = plt.subplots(2, 2, figsize=(15, 10))
            
            # Success rate by channel
            channel_success = df.groupby('channel_type')['success'].mean() * 100
            channel_success.plot(kind='bar', ax=axes[0,0])
            axes[0,0].set_title('Success Rate by Channel Type')
            axes[0,0].set_ylabel('Success Rate (%)')
            
            # Stealth score by channel
            df.boxplot(column='stealth_score', by='channel_type', ax=axes[0,1])
            axes[0,1].set_title('Stealth Score by Channel Type')
            
            # Transmission time by channel
            df.boxplot(column='transmission_time', by='channel_type', ax=axes[1,0])
            axes[1,0].set_title('Transmission Time by Channel Type')
            
            # Detection score by channel
            df.boxplot(column='detection_score', by='channel_type', ax=axes[1,1])
            axes[1,1].set_title('Detection Score by Channel Type')
            
            plt.tight_layout()
            plt.savefig(output_path / 'channel_comparison.png', dpi=300, bbox_inches='tight')
            plt.close()
        
        # 4. Performance Correlation Matrix
        numeric_cols = ['payload_size', 'encoded_size', 'transmission_time', 
                       'detection_score', 'stealth_score', 'bandwidth_used', 'error_rate']
        correlation_matrix = df[numeric_cols].corr()
        
        fig, ax = plt.subplots(figsize=(10, 8))
        sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', center=0, ax=ax)
        ax.set_title('Performance Metrics Correlation Matrix')
        plt.tight_layout()
        plt.savefig(output_path / 'correlation_matrix.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info(f"Visualization dashboard created in {output_path}")
    
    def export_data(self, format: str = 'json', output_file: str = None) -> str:
        """Export analytics data in various formats"""
        df = self.get_operations_dataframe(30)
        
        if df.empty:
            return "No data to export"
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"reports/analytics_export_{timestamp}.{format}"
        
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if format.lower() == 'json':
            df.to_json(output_path, orient='records', date_format='iso', indent=2)
        elif format.lower() == 'csv':
            df.to_csv(output_path, index=False)
        elif format.lower() == 'excel':
            df.to_excel(output_path, index=False)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        self.logger.info(f"Data exported to {output_path}")
        return str(output_path)

class ReportGenerator:
    """Generate comprehensive reports for covert channel operations"""
    
    def __init__(self, analytics_engine: AnalyticsEngine):
        self.analytics = analytics_engine
        self.logger = logging.getLogger(__name__)
    
    def generate_executive_summary(self, days: int = 30) -> Dict:
        """Generate executive summary report"""
        df = self.analytics.get_operations_dataframe(days)
        
        if df.empty:
            return {'error': 'No data available for report generation'}
        
        # Key metrics
        total_operations = len(df)
        success_rate = df['success'].mean() * 100
        avg_stealth_score = df['stealth_score'].mean()
        detection_rate = (df['detection_score'] > 0.5).mean() * 100
        total_bandwidth = df['bandwidth_used'].sum()
        
        # Channel breakdown
        channel_stats = df.groupby('channel_type').agg({
            'success': 'count',
            'stealth_score': 'mean'
        }).to_dict('index')
        
        # Trends
        trends = self.analytics.analyze_performance_trends(days)
        
        # Security assessment
        security = self.analytics.generate_security_assessment()
        
        return {
            'report_period': f"Last {days} days",
            'generated_at': datetime.now().isoformat(),
            'key_metrics': {
                'total_operations': total_operations,
                'success_rate': round(success_rate, 2),
                'average_stealth_score': round(avg_stealth_score, 2),
                'detection_rate': round(detection_rate, 2),
                'total_bandwidth_mb': round(total_bandwidth / (1024*1024), 2)
            },
            'channel_breakdown': channel_stats,
            'performance_trends': trends,
            'security_assessment': security,
            'anomalies': self.analytics.detect_anomalies()[:5]  # Top 5 anomalies
        }
    
    def generate_technical_report(self, days: int = 30) -> Dict:
        """Generate detailed technical report"""
        summary = self.generate_executive_summary(days)
        df = self.analytics.get_operations_dataframe(days)
        
        if df.empty:
            return summary
        
        # Detailed statistics
        detailed_stats = {
            'payload_size': {
                'min': df['payload_size'].min(),
                'max': df['payload_size'].max(),
                'mean': df['payload_size'].mean(),
                'std': df['payload_size'].std()
            },
            'transmission_time': {
                'min': df['transmission_time'].min(),
                'max': df['transmission_time'].max(),
                'mean': df['transmission_time'].mean(),
                'std': df['transmission_time'].std()
            },
            'compression_ratio': {
                'mean': (df['payload_size'] / df['encoded_size']).mean(),
                'std': (df['payload_size'] / df['encoded_size']).std()
            }
        }
        
        # Error analysis
        error_analysis = {
            'operations_with_errors': (df['error_rate'] > 0).sum(),
            'average_error_rate': df['error_rate'].mean(),
            'max_error_rate': df['error_rate'].max(),
            'error_correlation': df[['error_rate', 'detection_score']].corr().iloc[0, 1]
        }
        
        summary.update({
            'detailed_statistics': detailed_stats,
            'error_analysis': error_analysis,
            'raw_data_sample': df.head(10).to_dict('records')
        })
        
        return summary
    
    def save_report(self, report: Dict, filename: str = None, format: str = 'json'):
        """Save report to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"reports/covert_channel_report_{timestamp}.{format}"
        
        output_path = Path(filename)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if format.lower() == 'json':
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        elif format.lower() == 'html':
            self._generate_html_report(report, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        self.logger.info(f"Report saved to {output_path}")
        return str(output_path)
    
    def _generate_html_report(self, report: Dict, output_path: Path):
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Covert Channel Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
                .metric { display: inline-block; margin: 10px; padding: 15px; 
                         background-color: #e8f4f8; border-radius: 5px; }
                .section { margin: 20px 0; }
                .warning { color: #d9534f; font-weight: bold; }
                .success { color: #5cb85c; font-weight: bold; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Covert Channel Analysis Report</h1>
                <p>Generated: {generated_at}</p>
                <p>Period: {report_period}</p>
            </div>
            
            <div class="section">
                <h2>Key Metrics</h2>
                <div class="metric">
                    <h3>Total Operations</h3>
                    <p>{total_operations}</p>
                </div>
                <div class="metric">
                    <h3>Success Rate</h3>
                    <p class="{success_class}">{success_rate}%</p>
                </div>
                <div class="metric">
                    <h3>Stealth Score</h3>
                    <p class="{stealth_class}">{stealth_score}</p>
                </div>
                <div class="metric">
                    <h3>Detection Rate</h3>
                    <p class="{detection_class}">{detection_rate}%</p>
                </div>
            </div>
            
            <div class="section">
                <h2>Security Assessment</h2>
                <p><strong>Risk Level:</strong> <span class="{risk_class}">{risk_level}</span></p>
                <h3>Recommendations:</h3>
                <ul>
                    {recommendations}
                </ul>
            </div>
        </body>
        </html>
        """
        
        # Format data for HTML
        metrics = report['key_metrics']
        security = report['security_assessment']
        
        success_class = 'success' if metrics['success_rate'] > 80 else 'warning'
        stealth_class = 'success' if metrics['average_stealth_score'] > 70 else 'warning'
        detection_class = 'warning' if metrics['detection_rate'] > 20 else 'success'
        risk_class = 'warning' if security['risk_level'] == 'high' else 'success'
        
        recommendations_html = ''.join([f'<li>{rec}</li>' for rec in security['recommendations']])
        
        html_content = html_template.format(
            generated_at=report['generated_at'],
            report_period=report['report_period'],
            total_operations=metrics['total_operations'],
            success_rate=metrics['success_rate'],
            stealth_score=metrics['average_stealth_score'],
            detection_rate=metrics['detection_rate'],
            success_class=success_class,
            stealth_class=stealth_class,
            detection_class=detection_class,
            risk_level=security['risk_level'].upper(),
            risk_class=risk_class,
            recommendations=recommendations_html
        )
        
        with open(output_path, 'w') as f:
            f.write(html_content)

class Analytics:
    """Simplified analytics interface for CLI integration"""
    
    def __init__(self):
        self.engine = AnalyticsEngine()
        self.report_generator = ReportGenerator(self.engine)
        self.logger = logging.getLogger(__name__)
    
    def analyze_scenario_stealth(self, scenario_name: str) -> Dict:
        """Analyze stealth characteristics for a specific scenario"""
        try:
            # Get recent operations for the scenario
            df = self.engine.get_operations_dataframe(7)  # Last 7 days
            
            if df.empty:
                return {
                    'scenario': scenario_name,
                    'status': 'no_data',
                    'message': 'No recent operations found for analysis'
                }
            
            # Filter by scenario if possible (assuming operation_id contains scenario name)
            scenario_ops = df[df['operation_id'].str.contains(scenario_name, case=False, na=False)]
            
            if scenario_ops.empty:
                # Use all operations if no scenario-specific data
                scenario_ops = df
            
            # Calculate key metrics
            stealth_score = scenario_ops['stealth_score'].mean()
            detection_rate = (scenario_ops['detection_score'] > 0.5).mean() * 100
            success_rate = scenario_ops['success'].mean() * 100
            avg_transmission_time = scenario_ops['transmission_time'].mean()
            
            # Determine risk level
            if detection_rate > 30:
                risk_level = 'high'
            elif detection_rate > 15:
                risk_level = 'medium'
            else:
                risk_level = 'low'
            
            return {
                'scenario': scenario_name,
                'stealth_score': round(stealth_score, 2),
                'detection_rate': round(detection_rate, 2),
                'success_rate': round(success_rate, 2),
                'avg_transmission_time': round(avg_transmission_time, 2),
                'risk_level': risk_level,
                'total_operations': len(scenario_ops),
                'analysis_period': '7 days'
            }
            
        except Exception as e:
            self.logger.error(f"Failed to analyze scenario stealth: {e}")
            return {
                'scenario': scenario_name,
                'status': 'error',
                'error': str(e)
            }
    
    def analyze_log_file(self, log_file_path: str) -> Dict:
        """Analyze a specific log file for stealth characteristics"""
        try:
            with open(log_file_path, 'r') as f:
                log_data = []
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        log_data.append(log_entry)
                    except json.JSONDecodeError:
                        continue
            
            if not log_data:
                return {
                    'status': 'no_data',
                    'message': 'No valid JSON log entries found'
                }
            
            # Analyze log entries
            push_operations = [entry for entry in log_data if entry.get('event') == 'file_push']
            pull_operations = [entry for entry in log_data if entry.get('event') == 'file_pull']
            
            total_operations = len(push_operations) + len(pull_operations)
            successful_operations = len([op for op in push_operations + pull_operations 
                                       if op.get('status') == 'success'])
            
            success_rate = (successful_operations / total_operations * 100) if total_operations > 0 else 0
            
            # Estimate stealth score based on operation patterns
            stealth_score = self._estimate_stealth_from_logs(log_data)
            
            return {
                'log_file': log_file_path,
                'total_operations': total_operations,
                'push_operations': len(push_operations),
                'pull_operations': len(pull_operations),
                'success_rate': round(success_rate, 2),
                'estimated_stealth_score': round(stealth_score, 2),
                'analysis_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to analyze log file: {e}")
            return {
                'log_file': log_file_path,
                'status': 'error',
                'error': str(e)
            }
    
    def _estimate_stealth_from_logs(self, log_data: List[Dict]) -> float:
        """Estimate stealth score from log patterns"""
        base_score = 80.0  # Base stealth score
        
        # Analyze timing patterns
        timestamps = []
        for entry in log_data:
            if 'timestamp' in entry:
                try:
                    timestamps.append(datetime.fromisoformat(entry['timestamp']))
                except:
                    continue
        
        if len(timestamps) > 1:
            # Calculate time intervals
            timestamps.sort()
            intervals = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                        for i in range(len(timestamps)-1)]
            
            # Penalize very regular patterns (suspicious)
            if len(intervals) > 2:
                interval_std = np.std(intervals)
                interval_mean = np.mean(intervals)
                
                # Regular patterns are more detectable
                if interval_std < interval_mean * 0.1:  # Very regular
                    base_score -= 20
                elif interval_std < interval_mean * 0.3:  # Somewhat regular
                    base_score -= 10
        
        # Check for error patterns
        error_count = len([entry for entry in log_data if entry.get('status') == 'error'])
        total_count = len(log_data)
        
        if total_count > 0:
            error_rate = error_count / total_count
            base_score -= error_rate * 30  # Errors can indicate detection
        
        return max(0.0, min(100.0, base_score))
    
    def generate_stealth_report(self, analysis_result: Dict) -> Dict:
        """Generate a comprehensive stealth report"""
        try:
            report = {
                'generated_at': datetime.now().isoformat(),
                'analysis_input': analysis_result,
                'stealth_assessment': {},
                'key_findings': [],
                'recommendations': [],
                'risk_factors': []
            }
            
            # Extract key metrics
            if 'stealth_score' in analysis_result:
                stealth_score = analysis_result['stealth_score']
                detection_rate = analysis_result.get('detection_rate', 0)
                success_rate = analysis_result.get('success_rate', 100)
                
                # Stealth assessment
                if stealth_score >= 80:
                    stealth_level = 'excellent'
                elif stealth_score >= 60:
                    stealth_level = 'good'
                elif stealth_score >= 40:
                    stealth_level = 'moderate'
                else:
                    stealth_level = 'poor'
                
                report['stealth_assessment'] = {
                    'stealth_score': stealth_score,
                    'stealth_level': stealth_level,
                    'detection_rate': detection_rate,
                    'success_rate': success_rate
                }
                
                # Key findings
                if stealth_score >= 80 and detection_rate < 10:
                    report['key_findings'].append("Excellent stealth characteristics maintained")
                
                if detection_rate > 20:
                    report['key_findings'].append("High detection rate indicates potential security risk")
                    report['risk_factors'].append("Detection rate exceeds safe threshold")
                
                if success_rate < 80:
                    report['key_findings'].append("Low success rate may indicate operational issues")
                    report['risk_factors'].append("Operational reliability concerns")
                
                # Recommendations
                if detection_rate > 15:
                    report['recommendations'].extend([
                        "Implement additional traffic obfuscation techniques",
                        "Increase randomization in timing patterns",
                        "Consider switching to alternative carrier methods"
                    ])
                
                if stealth_score < 60:
                    report['recommendations'].extend([
                        "Review and optimize traffic shaping parameters",
                        "Analyze network patterns for anomalies",
                        "Implement more sophisticated evasion techniques"
                    ])
                
                if success_rate < 80:
                    report['recommendations'].extend([
                        "Check network connectivity and stability",
                        "Review payload encoding and error correction",
                        "Optimize chunk size and transmission parameters"
                    ])
                
                if not report['recommendations']:
                    report['recommendations'].append("Current stealth configuration appears optimal")
            
            elif 'estimated_stealth_score' in analysis_result:
                # Handle log file analysis
                stealth_score = analysis_result['estimated_stealth_score']
                success_rate = analysis_result.get('success_rate', 100)
                
                report['stealth_assessment'] = {
                    'estimated_stealth_score': stealth_score,
                    'success_rate': success_rate,
                    'total_operations': analysis_result.get('total_operations', 0)
                }
                
                if stealth_score < 60:
                    report['key_findings'].append("Log analysis suggests potential stealth issues")
                    report['recommendations'].append("Review operational patterns for optimization")
                
                if success_rate < 80:
                    report['key_findings'].append("Success rate indicates operational challenges")
            
            return report
            
        except Exception as e:
            self.logger.error(f"Failed to generate stealth report: {e}")
            return {
                'generated_at': datetime.now().isoformat(),
                'status': 'error',
                'error': str(e)
            }

# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Initialize analytics engine
    analytics = AnalyticsEngine()
    
    # Example: Record some test metrics
    test_metrics = OperationMetrics(
        timestamp=datetime.now(),
        operation_id="test_001",
        channel_type="dnssec_dnskey",
        payload_size=1024,
        encoded_size=1536,
        transmission_time=2.5,
        success=True,
        detection_score=0.2,
        stealth_score=85.0,
        bandwidth_used=2048,
        error_rate=0.0,
        latency=0.15
    )
    
    analytics.record_operation(test_metrics)
    
    # Generate reports
    report_gen = ReportGenerator(analytics)
    executive_report = report_gen.generate_executive_summary()
    
    print("Analytics system initialized and ready!")
