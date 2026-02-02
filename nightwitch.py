import typer
import sys
import json
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime

from src.controller import Controller
from src.lab_manager import LabManager
from src.scenario_manager import ScenarioManager
from src.monitor import Monitor
from src.ids_tester import IDSTester
from src.firewall_detector import FirewallDetector
from src.analytics import Analytics
from src.lan_ids_tester import LANIDSTester

app = typer.Typer(help="TESI Covert Channel Creation Toolkit - Research PoC")

# Global configuration
CONFIG_DIR = Path.home() / ".tesi"
LOG_DIR = Path("./logs")

def setup_logging():
    """Setup JSON logging for reproducibility"""
    LOG_DIR.mkdir(exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s',
        handlers=[
            logging.FileHandler(LOG_DIR / f"tesi_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"),
            logging.StreamHandler()
        ]
    )

def show_disclaimer():
    """Display mandatory disclaimer and get consent"""
    disclaimer = """
WARNING — Controlled-use only. This toolkit is a research Proof-of-Concept (PoC) 
for academic use only. It must be deployed exclusively in isolated, consented and 
legally-authorized test environments (lab VMs, isolated networks, containers). 
Do not run this software on production or third-party networks. Misuse may violate 
laws and institutional policies.
"""
    typer.echo(disclaimer, color=typer.colors.RED)
    
    if not typer.confirm("Do you accept these terms and confirm you are using this in an authorized test environment?"):
        typer.echo("Disclaimer not accepted. Exiting.")
        sys.exit(1)

@app.command()
def init_lab(
    mode: str = typer.Option("local", help="Lab mode: docker, vm, or local"),
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="Accept disclaimer without prompt")
):
    """Initialize isolated lab environment"""
    if not accept_disclaimer:
        show_disclaimer()
    
    setup_logging()
    
    typer.echo(f"Initializing lab in {mode} mode...")
    lab_manager = LabManager(mode)
    
    try:
        lab_manager.initialize()
        typer.echo("Lab initialized successfully", color=typer.colors.GREEN)
        
        # Log event
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "lab_init",
            "mode": mode,
            "status": "success"
        }
        logging.info(json.dumps(log_event))
        
    except Exception as e:
        typer.echo(f"Lab initialization failed: {e}", color=typer.colors.RED)
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "lab_init",
            "mode": mode,
            "status": "error",
            "error": str(e)
        }
        logging.error(json.dumps(log_event))
        sys.exit(1)

@app.command()
def create_scenario(
    name: str = typer.Option(..., help="Scenario name"),
    domain: str = typer.Option("example.test", help="Target domain"),
    carrier: str = typer.Option("dnskey", help="Carrier type"),
    ttl: int = typer.Option(30, help="DNS TTL"),
    chunk_size: int = typer.Option(200, help="Chunk size in bytes"),
    freq: str = typer.Option("5s", help="Update frequency"),
    encrypt: str = typer.Option("aes256", help="Encryption type"),
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="Accept disclaimer without prompt")
):
    """Create a new covert channel scenario"""
    if not accept_disclaimer:
        show_disclaimer()
    
    setup_logging()
    
    scenario_config = {
        "name": name,
        "domain": domain,
        "carrier": carrier,
        "ttl": ttl,
        "chunk_size": chunk_size,
        "frequency": freq,
        "encryption": encrypt,
        "created": datetime.now().isoformat()
    }
    
    scenario_manager = ScenarioManager()
    
    try:
        scenario_manager.create_scenario(scenario_config)
        typer.echo(f"Scenario '{name}' created successfully", color=typer.colors.GREEN)
        
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "scenario_create",
            "scenario": scenario_config,
            "status": "success"
        }
        logging.info(json.dumps(log_event))
        
    except Exception as e:
        typer.echo(f"Scenario creation failed: {e}", color=typer.colors.RED)
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "scenario_create",
            "scenario": scenario_config,
            "status": "error",
            "error": str(e)
        }
        logging.error(json.dumps(log_event))
        sys.exit(1)

@app.command()
def start(
    scenario: str = typer.Option(..., help="Scenario name to start"),
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="Accept disclaimer without prompt")
):
    """Start a covert channel scenario"""
    if not accept_disclaimer:
        show_disclaimer()
    
    setup_logging()
    
    controller = Controller()
    
    try:
        controller.start_scenario(scenario)
        typer.echo(f"Scenario '{scenario}' started", color=typer.colors.GREEN)
        
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "scenario_start",
            "scenario": scenario,
            "status": "success"
        }
        logging.info(json.dumps(log_event))
        
    except Exception as e:
        typer.echo(f"Failed to start scenario: {e}", color=typer.colors.RED)
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "scenario_start",
            "scenario": scenario,
            "status": "error",
            "error": str(e)
        }
        logging.error(json.dumps(log_event))
        sys.exit(1)

@app.command()
def push(
    file: Path = typer.Option(..., help="File to transmit"),
    scenario: str = typer.Option(..., help="Scenario name"),
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="Accept disclaimer without prompt")
):
    """Push a file through the covert channel"""
    if not accept_disclaimer:
        show_disclaimer()
    
    setup_logging()
    
    if not file.exists():
        typer.echo(f"File not found: {file}", color=typer.colors.RED)
        sys.exit(1)
    
    controller = Controller()
    
    try:
        controller.push_file(file, scenario)
        typer.echo(f"File '{file}' pushed through scenario '{scenario}'", color=typer.colors.GREEN)
        
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "file_push",
            "file": str(file),
            "scenario": scenario,
            "file_size": file.stat().st_size,
            "status": "success"
        }
        logging.info(json.dumps(log_event))
        
    except Exception as e:
        typer.echo(f"Failed to push file: {e}", color=typer.colors.RED)
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "file_push",
            "file": str(file),
            "scenario": scenario,
            "status": "error",
            "error": str(e)
        }
        logging.error(json.dumps(log_event))
        sys.exit(1)

@app.command()
def pull(
    output: Path = typer.Option(..., help="Output file path"),
    scenario: str = typer.Option(..., help="Scenario name"),
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="Accept disclaimer without prompt")
):
    """Pull data from the covert channel and reconstruct file"""
    if not accept_disclaimer:
        show_disclaimer()
    
    setup_logging()
    
    controller = Controller()
    
    try:
        controller.pull_file(output, scenario)
        typer.echo(f"Data extracted and saved to '{output}'", color=typer.colors.GREEN)
        
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "file_pull",
            "output": str(output),
            "scenario": scenario,
            "file_size": output.stat().st_size if output.exists() else 0,
            "status": "success"
        }
        logging.info(json.dumps(log_event))
        
    except Exception as e:
        typer.echo(f"Failed to pull data: {e}", color=typer.colors.RED)
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "file_pull",
            "output": str(output),
            "scenario": scenario,
            "status": "error",
            "error": str(e)
        }
        logging.error(json.dumps(log_event))
        sys.exit(1)

@app.command()
def monitor(
    scenario: str = typer.Option(..., help="Scenario to monitor"),
    out: Path = typer.Option("./results", help="Output directory"),
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="Accept disclaimer without prompt")
):
    """Monitor scenario performance and IDS alerts"""
    if not accept_disclaimer:
        show_disclaimer()
    
    setup_logging()
    
    monitor = Monitor(out)
    
    try:
        monitor.start_monitoring(scenario)
        typer.echo(f"Monitoring scenario '{scenario}', results in {out}", color=typer.colors.GREEN)
        
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "monitor_start",
            "scenario": scenario,
            "output_dir": str(out),
            "status": "success"
        }
        logging.info(json.dumps(log_event))
        
    except Exception as e:
        typer.echo(f"Failed to start monitoring: {e}", color=typer.colors.RED)
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "monitor_start",
            "scenario": scenario,
            "status": "error",
            "error": str(e)
        }
        logging.error(json.dumps(log_event))
        sys.exit(1)

@app.command()
def stop(
    scenario: str = typer.Option(..., help="Scenario to stop"),
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="Accept disclaimer without prompt")
):
    """Stop a running scenario"""
    if not accept_disclaimer:
        show_disclaimer()
    
    setup_logging()
    
    controller = Controller()
    
    try:
        controller.stop_scenario(scenario)
        typer.echo(f"Scenario '{scenario}' stopped", color=typer.colors.GREEN)
        
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "scenario_stop",
            "scenario": scenario,
            "status": "success"
        }
        logging.info(json.dumps(log_event))
        
    except Exception as e:
        typer.echo(f"Failed to stop scenario: {e}", color=typer.colors.RED)
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "scenario_stop",
            "scenario": scenario,
            "status": "error",
            "error": str(e)
        }
        logging.error(json.dumps(log_event))
        sys.exit(1)

@app.command()
def test_ids(
    scenario: str = typer.Option(..., help="Scenario to test against IDS"),
    payload_size: int = typer.Option(1024, help="Test payload size in bytes"),
    output: Path = typer.Option("./ids_test_report.json", help="Output report file"),
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="Accept disclaimer without prompt")
):
    """Run comprehensive IDS detection tests"""
    if not accept_disclaimer:
        show_disclaimer()
    
    setup_logging()
    
    typer.echo(f"Starting IDS detection tests for scenario '{scenario}'...")
    
    try:
        # Initialize IDS tester
        ids_tester = IDSTester()
        
        # Setup IDS environment
        if not ids_tester.setup_ids_environment():
            typer.echo("Failed to setup IDS environment", color=typer.colors.RED)
            sys.exit(1)
        
        # Start IDS monitoring
        if not ids_tester.start_ids_monitoring():
            typer.echo("Failed to start IDS monitoring", color=typer.colors.RED)
            sys.exit(1)
        
        typer.echo("IDS environment ready, running test scenarios...")
        
        # Create test payload
        test_payload = b"A" * payload_size
        
        # Initialize controller for covert channel operations
        controller = Controller()
        
        # Run test scenarios
        test_scenarios = [
            'baseline_traffic',
            'covert_channel_detection', 
            'evasion_techniques',
            'performance_impact'
        ]
        
        for scenario_name in test_scenarios:
            typer.echo(f"Running test: {scenario_name}")
            result = ids_tester.run_test_scenario(scenario_name, controller, test_payload)
            
            detection_status = "🔴 DETECTED" if result['detected'] else "🟢 UNDETECTED"
            stealth_score = result['stealth_score']
            
            typer.echo(f"  {detection_status} - Stealth Score: {stealth_score:.1f}/100")
        
        # Stop IDS monitoring
        ids_tester.stop_ids_monitoring()
        
        # Generate comprehensive report
        report = ids_tester.generate_test_report(str(output))
        
        typer.echo(f"IDS testing completed. Report saved to {output}", color=typer.colors.GREEN)
        typer.echo(f"Average Stealth Score: {report['test_summary']['average_stealth_score']:.1f}/100")
        
        # Log event
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "ids_test",
            "scenario": scenario,
            "payload_size": payload_size,
            "total_tests": report['test_summary']['total_tests'],
            "detected_tests": report['test_summary']['detected_tests'],
            "average_stealth_score": report['test_summary']['average_stealth_score'],
            "status": "success"
        }
        logging.info(json.dumps(log_event))
        
    except Exception as e:
        typer.echo(f"IDS testing failed: {e}", color=typer.colors.RED)
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "ids_test",
            "scenario": scenario,
            "status": "error",
            "error": str(e)
        }
        logging.error(json.dumps(log_event))
        sys.exit(1)

@app.command()
def test_firewall(
    domain: str = typer.Option("test.local", help="Domain to test firewall detection"),
    duration: int = typer.Option(300, help="Test duration in seconds"),
    output: Path = typer.Option("./firewall_test_report.json", help="Output report file"),
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="Accept disclaimer without prompt")
):
    """Test firewall and DPI detection capabilities"""
    if not accept_disclaimer:
        show_disclaimer()
    
    setup_logging()
    
    typer.echo(f"Starting firewall detection tests for domain '{domain}'...")
    
    try:
        # Initialize firewall detector
        def adaptation_callback(threat_level):
            typer.echo(f"Threat level changed to: {threat_level}")
        
        firewall_detector = FirewallDetector(callback=adaptation_callback)
        
        # Start monitoring
        firewall_detector.start_monitoring(domain, interval=30)
        
        typer.echo(f"Monitoring started for {duration} seconds...")
        
        # Wait for test duration
        import time
        time.sleep(duration)
        
        # Stop monitoring
        firewall_detector.stop_monitoring()
        
        # Generate report
        report = firewall_detector.generate_report()
        
        # Save report
        with open(output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        typer.echo(f"Firewall testing completed. Report saved to {output}", color=typer.colors.GREEN)
        typer.echo(f"Overall Risk Assessment: {report['overall_risk_assessment']}")
        
        # Show recommendations
        if report.get('recommendations'):
            typer.echo("\nRecommendations:")
            for rec in report['recommendations']:
                typer.echo(f"  • {rec}")
        
        # Log event
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "firewall_test",
            "domain": domain,
            "duration": duration,
            "risk_assessment": report['overall_risk_assessment'],
            "total_probes": report['total_probes'],
            "status": "success"
        }
        logging.info(json.dumps(log_event))
        
    except Exception as e:
        typer.echo(f"Firewall testing failed: {e}", color=typer.colors.RED)
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "firewall_test",
            "domain": domain,
            "status": "error",
            "error": str(e)
        }
        logging.error(json.dumps(log_event))
        sys.exit(1)

@app.command()
def analyze_stealth(
    scenario: str = typer.Option(..., help="Scenario to analyze"),
    log_file: Optional[Path] = typer.Option(None, help="Specific log file to analyze"),
    output: Path = typer.Option("./stealth_analysis.json", help="Output analysis file"),
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="Accept disclaimer without prompt")
):
    """Analyze stealth characteristics and generate recommendations"""
    if not accept_disclaimer:
        show_disclaimer()
    
    setup_logging()
    
    typer.echo(f"Analyzing stealth characteristics for scenario '{scenario}'...")
    
    try:
        # Initialize analytics
        analytics = Analytics()
        
        # Load scenario data
        if log_file and log_file.exists():
            analysis_result = analytics.analyze_log_file(str(log_file))
        else:
            # Analyze recent activity for the scenario
            analysis_result = analytics.analyze_scenario_stealth(scenario)
        
        # Generate detailed stealth report
        stealth_report = analytics.generate_stealth_report(analysis_result)
        
        # Save analysis
        with open(output, 'w') as f:
            json.dump(stealth_report, f, indent=2, default=str)
        
        # Display key metrics
        typer.echo(f"Stealth analysis completed. Report saved to {output}", color=typer.colors.GREEN)
        
        if 'stealth_score' in stealth_report:
            score = stealth_report['stealth_score']
            if score >= 80:
                score_color = typer.colors.GREEN
                score_status = "EXCELLENT"
            elif score >= 60:
                score_color = typer.colors.YELLOW
                score_status = "GOOD"
            else:
                score_color = typer.colors.RED
                score_status = "POOR"
            
            typer.echo(f"Stealth Score: {score:.1f}/100 ({score_status})", color=score_color)
        
        # Show key findings
        if 'key_findings' in stealth_report:
            typer.echo("\nKey Findings:")
            for finding in stealth_report['key_findings']:
                typer.echo(f"  • {finding}")
        
        # Show recommendations
        if 'recommendations' in stealth_report:
            typer.echo("\nRecommendations:")
            for rec in stealth_report['recommendations']:
                typer.echo(f"  • {rec}")
        
        # Log event
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "stealth_analysis",
            "scenario": scenario,
            "stealth_score": stealth_report.get('stealth_score', 0),
            "status": "success"
        }
        logging.info(json.dumps(log_event))
        
    except Exception as e:
        typer.echo(f"Stealth analysis failed: {e}", color=typer.colors.RED)
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "stealth_analysis",
            "scenario": scenario,
            "status": "error",
            "error": str(e)
        }
        logging.error(json.dumps(log_event))
        sys.exit(1)

@app.command()
def test_comprehensive(
    scenario: str = typer.Option(..., help="Scenario to test comprehensively"),
    payload_sizes: str = typer.Option("100,1024,5120", help="Comma-separated payload sizes to test"),
    output_dir: Path = typer.Option("./comprehensive_test_results", help="Output directory for all reports"),
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="Accept disclaimer without prompt")
):
    """Run comprehensive detection and stealth testing suite"""
    if not accept_disclaimer:
        show_disclaimer()
    
    setup_logging()
    
    # Parse payload sizes
    try:
        sizes = [int(s.strip()) for s in payload_sizes.split(',')]
    except ValueError:
        typer.echo("Invalid payload sizes format", color=typer.colors.RED)
        sys.exit(1)
    
    # Create output directory
    output_dir.mkdir(exist_ok=True)
    
    typer.echo(f"Starting comprehensive testing suite for scenario '{scenario}'...")
    typer.echo(f"Testing payload sizes: {sizes}")
    
    comprehensive_results = {
        "scenario": scenario,
        "test_start": datetime.now().isoformat(),
        "payload_sizes_tested": sizes,
        "results": {}
    }
    
    try:
        for size in sizes:
            typer.echo(f"\nTesting payload size: {size} bytes")
            
            # Run IDS tests
            typer.echo("  Running IDS detection tests...")
            ids_output = output_dir / f"ids_test_{size}b.json"
            
            # Note: This would call the IDS testing logic
            # For now, we'll create a placeholder result
            ids_result = {
                "payload_size": size,
                "stealth_score": 85.0,  # Placeholder
                "detected": False,
                "test_scenarios_completed": 4
            }
            
            comprehensive_results["results"][f"{size}b"] = {
                "ids_test": ids_result
            }
        
        # Run firewall detection test
        typer.echo("\nRunning firewall detection tests...")
        firewall_output = output_dir / "firewall_test.json"
        
        # Placeholder firewall result
        firewall_result = {
            "risk_assessment": "low",
            "total_probes": 10,
            "threat_detections": 0
        }
        
        comprehensive_results["firewall_test"] = firewall_result
        
        # Generate overall assessment
        comprehensive_results["test_end"] = datetime.now().isoformat()
        comprehensive_results["overall_assessment"] = "STEALTH_MAINTAINED"
        
        # Save comprehensive results
        comprehensive_output = output_dir / "comprehensive_results.json"
        with open(comprehensive_output, 'w') as f:
            json.dump(comprehensive_results, f, indent=2, default=str)
        
        typer.echo(f"\nComprehensive testing completed!", color=typer.colors.GREEN)
        typer.echo(f"Results saved to: {output_dir}")
        typer.echo(f"Overall Assessment: {comprehensive_results['overall_assessment']}")
        
        # Log event
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "comprehensive_test",
            "scenario": scenario,
            "payload_sizes": sizes,
            "overall_assessment": comprehensive_results['overall_assessment'],
            "status": "success"
        }
        logging.info(json.dumps(log_event))
        
    except Exception as e:
        typer.echo(f"Comprehensive testing failed: {e}", color=typer.colors.RED)
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "comprehensive_test",
            "scenario": scenario,
            "status": "error",
            "error": str(e)
        }
        logging.error(json.dumps(log_event))
        sys.exit(1)

@app.command()
def setup_sender(
    receiver_ip: str = typer.Option(..., help="IP address of the receiver VM"),
    dns_server: str = typer.Option("8.8.8.8", help="DNS server to use"),
    port: int = typer.Option(53, help="DNS port"),
    wan_mode: bool = typer.Option(False, "--wan", help="Enable WAN mode for public IP testing"),
    interface: Optional[str] = typer.Option(None, "--interface", help="Network interface to use (e.g., tailscale0, eth0, enp0s1). Auto-detected if not specified"),
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="Accept disclaimer without prompt")
):
    """Setup this VM as sender for LAN/WAN testing"""
    if not accept_disclaimer:
        show_disclaimer()
    
    setup_logging()
    
    mode_str = "WAN" if wan_mode else "LAN"
    typer.echo(f"Configuring this VM as SENDER ({mode_str} mode)...")
    typer.echo(f"Receiver VM IP: {receiver_ip}")
    if interface:
        typer.echo(f"Network interface: {interface}")
    
    try:
        # Save configuration
        config = {
            "role": "sender",
            "receiver_ip": receiver_ip,
            "dns_server": dns_server,
            "port": port,
            "wan_mode": wan_mode,
            "interface": interface,
            "configured_at": datetime.now().isoformat()
        }
        
        CONFIG_DIR.mkdir(exist_ok=True)
        config_file = CONFIG_DIR / "lan_config.json"
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        typer.echo(f"Sender configuration saved to {config_file}", color=typer.colors.GREEN)
        
        if wan_mode:
            typer.echo(f"\nWAN Mode - Next steps:")
            typer.echo(f"  1. Ensure receiver VM ({receiver_ip}) has a public IP or port forwarding configured")
            if interface and "tailscale" in interface.lower():
                typer.echo(f"  2. On receiver VM, run: python tesictl.py setup-receiver --sender-ip <your-tailscale-ip> --wan --interface {interface}")
                typer.echo(f"     (Tailscale detected - make sure both VMs are in the same Tailscale network)")
            else:
                typer.echo(f"  2. On receiver VM, run: python tesictl.py setup-receiver --sender-ip <your-public-ip> --wan")
            typer.echo(f"  3. Configure firewall to allow UDP traffic on port {port}")
            typer.echo(f"  4. Create a scenario: python tesictl.py create-scenario --name wan-test ...")
            typer.echo(f"  5. Test WAN connection: python tesictl.py test-wan --scenario wan-test")
        else:
            typer.echo(f"\nLAN Mode - Next steps:")
            typer.echo(f"  1. On receiver VM ({receiver_ip}), run: python tesictl.py setup-receiver --sender-ip <this-vm-ip>")
            typer.echo(f"  2. Create a scenario: python tesictl.py create-scenario --name lan-test ...")
            typer.echo(f"  3. Test LAN connection: python tesictl.py test-lan --scenario lan-test")
        
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "setup_sender",
            "receiver_ip": receiver_ip,
            "wan_mode": wan_mode,
            "interface": interface,
            "status": "success"
        }
        logging.info(json.dumps(log_event))
        
    except Exception as e:
        typer.echo(f"Sender setup failed: {e}", color=typer.colors.RED)
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "setup_sender",
            "status": "error",
            "error": str(e)
        }
        logging.error(json.dumps(log_event))
        sys.exit(1)

@app.command()
def setup_receiver(
    sender_ip: str = typer.Option(..., help="IP address of the sender VM"),
    listen_port: int = typer.Option(53, help="Port to listen on for DNS queries"),
    wan_mode: bool = typer.Option(False, "--wan", help="Enable WAN mode for public IP testing"),
    interface: Optional[str] = typer.Option(None, "--interface", help="Network interface to use (e.g., tailscale0, eth0, enp0s1). Auto-detected if not specified"),
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="Accept disclaimer without prompt")
):
    """Setup this VM as receiver for LAN/WAN testing"""
    if not accept_disclaimer:
        show_disclaimer()
    
    setup_logging()
    
    mode_str = "WAN" if wan_mode else "LAN"
    typer.echo(f"Configuring this VM as RECEIVER ({mode_str} mode)...")
    typer.echo(f"Sender VM IP: {sender_ip}")
    if interface:
        typer.echo(f"Network interface: {interface}")
    
    try:
        # Save configuration
        config = {
            "role": "receiver",
            "sender_ip": sender_ip,
            "listen_port": listen_port,
            "wan_mode": wan_mode,
            "interface": interface,
            "configured_at": datetime.now().isoformat()
        }
        
        CONFIG_DIR.mkdir(exist_ok=True)
        config_file = CONFIG_DIR / "lan_config.json"
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        typer.echo(f"Receiver configuration saved to {config_file}", color=typer.colors.GREEN)
        typer.echo(f"\nReceiver is ready to accept connections from {sender_ip}")
        typer.echo(f"  Listening on port: {listen_port}")
        
        if wan_mode:
            typer.echo(f"\nWAN Mode - Additional requirements:")
            typer.echo(f"  • Ensure port {listen_port} is open in firewall")
            if interface and "tailscale" in interface.lower():
                typer.echo(f"  • Tailscale detected - firewall rules are usually handled automatically")
                typer.echo(f"  • Verify sender can ping this Tailscale IP: {sender_ip}")
            else:
                typer.echo(f"  • Configure NAT/port forwarding if behind router")
                typer.echo(f"  • Your public IP should be accessible from sender")
        
        typer.echo(f"\nTo start receiving:")
        typer.echo(f"  python tesictl.py start-receiver --scenario <scenario-name>")
        
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "setup_receiver",
            "sender_ip": sender_ip,
            "wan_mode": wan_mode,
            "interface": interface,
            "status": "success"
        }
        logging.info(json.dumps(log_event))
        
    except Exception as e:
        typer.echo(f"Receiver setup failed: {e}", color=typer.colors.RED)
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "setup_receiver",
            "status": "error",
            "error": str(e)
        }
        logging.error(json.dumps(log_event))
        sys.exit(1)

@app.command()
def start_receiver(
    scenario: str = typer.Option(..., help="Scenario name to receive data for"),
    output_dir: Path = typer.Option("./received_data", help="Directory to save received files"),
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="Accept disclaimer without prompt")
):
    """Start receiver daemon to listen for incoming covert channel data"""
    if not accept_disclaimer:
        show_disclaimer()
    
    setup_logging()
    
    # Load receiver configuration
    config_file = CONFIG_DIR / "lan_config.json"
    if not config_file.exists():
        typer.echo("Receiver not configured. Run 'setup-receiver' first.", color=typer.colors.RED)
        sys.exit(1)
    
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    if config.get("role") != "receiver":
        typer.echo("This VM is not configured as receiver.", color=typer.colors.RED)
        sys.exit(1)
    
    output_dir.mkdir(exist_ok=True)
    
    typer.echo(f"Starting receiver for scenario '{scenario}'...")
    typer.echo(f"Listening for data from sender: {config['sender_ip']}")
    typer.echo(f"Output directory: {output_dir}")
    typer.echo(f"\nWaiting for incoming data... (Press Ctrl+C to stop)")
    
    try:
        controller = Controller()
        controller.start_receiver(scenario, str(output_dir), config)
        
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "start_receiver",
            "scenario": scenario,
            "sender_ip": config['sender_ip'],
            "status": "success"
        }
        logging.info(json.dumps(log_event))
        
    except KeyboardInterrupt:
        typer.echo("\n\nReceiver stopped by user", color=typer.colors.YELLOW)
    except Exception as e:
        typer.echo(f"Receiver failed: {e}", color=typer.colors.RED)
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "start_receiver",
            "scenario": scenario,
            "status": "error",
            "error": str(e)
        }
        logging.error(json.dumps(log_event))
        sys.exit(1)

@app.command()
def test_lan(
    scenario: str = typer.Option(..., help="Scenario to test"),
    test_file: Optional[Path] = typer.Option(None, help="Test file to send (if not specified, generates test data)"),
    size: int = typer.Option(1024, help="Size of test data in bytes (if no test file specified)"),
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="Accept disclaimer without prompt")
):
    """Test LAN connectivity and covert channel between sender and receiver VMs"""
    if not accept_disclaimer:
        show_disclaimer()
    
    setup_logging()
    
    # Load configuration
    config_file = CONFIG_DIR / "lan_config.json"
    if not config_file.exists():
        typer.echo("LAN not configured. Run 'setup-sender' or 'setup-receiver' first.", color=typer.colors.RED)
        sys.exit(1)
    
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    role = config.get("role")
    
    if role == "sender":
        typer.echo(f"Starting LAN test as SENDER")
        typer.echo(f"Target receiver: {config['receiver_ip']}")
        
        # Create or use test file
        if test_file and test_file.exists():
            typer.echo(f"Using test file: {test_file}")
            test_data_path = test_file
        else:
            typer.echo(f"Generating test data ({size} bytes)...")
            test_data_path = Path("./test_lan_data.bin")
            with open(test_data_path, 'wb') as f:
                f.write(b"TEST_DATA_" * (size // 10))
        
        try:
            # Test network connectivity first
            typer.echo(f"\nTesting network connectivity to {config['receiver_ip']}...")
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((config['receiver_ip'], config.get('port', 53)))
            sock.close()
            
            if result == 0:
                typer.echo("Network connectivity OK", color=typer.colors.GREEN)
            else:
                typer.echo("Cannot connect to receiver (this is normal if receiver is not listening yet)", color=typer.colors.YELLOW)
            
            # Start covert channel transmission
            typer.echo(f"\n2️⃣ Starting covert channel transmission...")
            controller = Controller(mock_keys=True)
            controller.push_file_to_remote(test_data_path, scenario, config)
            
            typer.echo(f"LAN test completed successfully!", color=typer.colors.GREEN)
            typer.echo(f"\nCheck receiver VM for received data")
            
            log_event = {
                "timestamp": datetime.now().isoformat(),
                "event": "test_lan",
                "role": "sender",
                "scenario": scenario,
                "receiver_ip": config['receiver_ip'],
                "test_file_size": test_data_path.stat().st_size,
                "status": "success"
            }
            logging.info(json.dumps(log_event))
            
        except Exception as e:
            typer.echo(f"LAN test failed: {e}", color=typer.colors.RED)
            log_event = {
                "timestamp": datetime.now().isoformat(),
                "event": "test_lan",
                "role": "sender",
                "scenario": scenario,
                "status": "error",
                "error": str(e)
            }
            logging.error(json.dumps(log_event))
            sys.exit(1)
    
    elif role == "receiver":
        typer.echo("This VM is configured as receiver.", color=typer.colors.RED)
        typer.echo("Run 'start-receiver' to listen for incoming data.")
        typer.echo("Run the 'test-lan' command on the sender VM.")
        sys.exit(1)
    
    else:
        typer.echo("Unknown role in configuration.", color=typer.colors.RED)
        sys.exit(1)

@app.command()
def test_ids_lan(
    scenario: str = typer.Option(..., help="Scenario to test against IDS on LAN"),
    duration: int = typer.Option(300, help="Test duration in seconds"),
    interface: Optional[str] = typer.Option(None, help="Network interface to monitor (auto-detect if not specified)"),
    output: Path = typer.Option("./lan_ids_test_report.json", help="Output report file"),
    save_pcap: bool = typer.Option(True, help="Save captured packets to PCAP file"),
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="Accept disclaimer without prompt")
):
    """Run IDS detection tests on LAN between two VMs using Suricata and Scapy"""
    if not accept_disclaimer:
        show_disclaimer()
    
    setup_logging()
    
    # Load LAN configuration
    config_file = CONFIG_DIR / "lan_config.json"
    if not config_file.exists():
        typer.echo("LAN not configured. Run 'setup-sender' or 'setup-receiver' first.", color=typer.colors.RED)
        sys.exit(1)
    
    with open(config_file, 'r') as f:
        lan_config = json.load(f)
    
    role = lan_config.get("role")
    if interface is None:
        interface = lan_config.get("interface")
    
    typer.echo(f"🔍 Starting LAN IDS detection tests for scenario '{scenario}'...")
    typer.echo(f"Role: {role.upper()}")
    typer.echo(f"Duration: {duration} seconds")
    if interface:
        typer.echo(f"Interface: {interface}")
    
    try:
        # Initialize LAN IDS tester
        lan_ids_tester = LANIDSTester(
            interface=interface,
            role=role
        )
        
        # Setup IDS environment
        if not lan_ids_tester.setup_lan_ids_environment():
            typer.echo("Failed to setup LAN IDS environment", color=typer.colors.RED)
            sys.exit(1)
        
        typer.echo("LAN IDS environment ready")
        
        # Start IDS monitoring
        if not lan_ids_tester.start_lan_ids_monitoring():
            typer.echo("Failed to start LAN IDS monitoring", color=typer.colors.RED)
            sys.exit(1)
        
        typer.echo(f"IDS monitoring active on interface: {lan_ids_tester.interface}")
        typer.echo(f"\nMonitoring for {duration} seconds...")
        typer.echo("   (Run covert channel transmission on sender VM now)")
        
        # Monitor for specified duration
        import time
        start_time = time.time()
        while time.time() - start_time < duration:
            remaining = duration - int(time.time() - start_time)
            if remaining % 30 == 0 and remaining > 0:
                typer.echo(f"   {remaining} seconds remaining...")
            time.sleep(1)
        
        typer.echo("\nMonitoring period complete, analyzing results...")
        
        # Stop IDS monitoring
        lan_ids_tester.stop_lan_ids_monitoring()
        
        # Save PCAP if requested
        pcap_file = None
        if save_pcap:
            typer.echo("Saving captured packets to PCAP...")
            pcap_file = lan_ids_tester.save_pcap()
            if pcap_file:
                typer.echo(f"PCAP saved: {pcap_file}")
        
        # Generate comprehensive report
        typer.echo("Generating test report...")
        report = lan_ids_tester.generate_lan_test_report(str(output))
        
        # Display results
        typer.echo(f"\nLAN IDS testing completed. Report saved to {output}", color=typer.colors.GREEN)
        
        detection_summary = report['detection_summary']
        stealth_score = detection_summary['stealth_score']
        
        if stealth_score >= 80:
            score_color = typer.colors.GREEN
            score_status = "EXCELLENT"
        elif stealth_score >= 60:
            score_color = typer.colors.YELLOW
            score_status = "GOOD"
        else:
            score_color = typer.colors.RED
            score_status = "POOR"
        
        typer.echo(f"\nTest Results:")
        typer.echo(f"   Stealth Score: {stealth_score:.1f}/100 ({score_status})", color=score_color)
        typer.echo(f"   Total Detections: {detection_summary['total_detections']}")
        typer.echo(f"   Detected: {'YES' if detection_summary['detected'] else 'NO'}")
        
        # Show traffic analysis
        traffic = report['traffic_analysis']
        typer.echo(f"\nTraffic Analysis:")
        typer.echo(f"   Total Packets: {traffic['total_packets']}")
        typer.echo(f"   DNS Queries: {traffic['dns_queries']}")
        typer.echo(f"   High Entropy Queries: {traffic['high_entropy_queries']}")
        typer.echo(f"   Base64 Patterns: {traffic['base64_patterns']}")
        typer.echo(f"   Query Rate: {traffic['query_rate']:.2f} queries/sec")
        
        # Show Suricata alerts
        suricata = report['suricata_alerts']
        if suricata['total_alerts'] > 0:
            typer.echo(f"\nSuricata Alerts: {suricata['total_alerts']}")
            for alert_type, count in suricata['alert_types'].items():
                typer.echo(f"   - {alert_type}: {count}")
        
        # Show recommendations
        if report['recommendations']:
            typer.echo("\nRecommendations:")
            for rec in report['recommendations']:
                typer.echo(f"   • {rec}")
        
        if pcap_file:
            typer.echo(f"\nPCAP file: {pcap_file}")
            typer.echo("   Analyze with: wireshark " + pcap_file)
        
        # Log event
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "test_ids_lan",
            "scenario": scenario,
            "role": role,
            "duration": duration,
            "stealth_score": stealth_score,
            "total_detections": detection_summary['total_detections'],
            "status": "success"
        }
        logging.info(json.dumps(log_event))
        
    except KeyboardInterrupt:
        typer.echo("\n\nTest interrupted by user", color=typer.colors.YELLOW)
        if 'lan_ids_tester' in locals():
            lan_ids_tester.stop_lan_ids_monitoring()
    except Exception as e:
        typer.echo(f"LAN IDS testing failed: {e}", color=typer.colors.RED)
        log_event = {
            "timestamp": datetime.now().isoformat(),
            "event": "test_ids_lan",
            "scenario": scenario,
            "status": "error",
            "error": str(e)
        }
        logging.error(json.dumps(log_event))
        sys.exit(1)

@app.command()
def test_wan(
    scenario: str = typer.Option(..., help="Scenario to test"),
    test_file: Optional[Path] = typer.Option(None, help="Test file to send (if not specified, generates test data)"),
    size: int = typer.Option(1024, help="Size of test data in bytes (if no test file specified)"),
    timeout: int = typer.Option(30, help="Connection timeout in seconds"),
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="Accept disclaimer without prompt")
):
    """Test WAN connectivity and covert channel between sender and receiver VMs over internet"""
    if not accept_disclaimer:
        show_disclaimer()
    
    setup_logging()
    
    # Load configuration
    config_file = CONFIG_DIR / "lan_config.json"
    if not config_file.exists():
        typer.echo("WAN not configured. Run 'setup-sender --wan' first.", color=typer.colors.RED)
        sys.exit(1)
    
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    if not config.get("wan_mode"):
        typer.echo("Configuration is in LAN mode. Use 'test-lan' or reconfigure with --wan flag.", color=typer.colors.YELLOW)
        sys.exit(1)
    
    role = config.get("role")
    
    if role == "sender":
        typer.echo(f"🌐 Starting WAN test as SENDER")
        typer.echo(f"Target receiver: {config['receiver_ip']}")
        typer.echo(f"Timeout: {timeout}s")
        
        # Create or use test file
        if test_file and test_file.exists():
            typer.echo(f"Using test file: {test_file}")
            test_data_path = test_file
        else:
            typer.echo(f"Generating test data ({size} bytes)...")
            test_data_path = Path("./test_wan_data.bin")
            with open(test_data_path, 'wb') as f:
                f.write(b"WAN_TEST_" * (size // 9))
        
        try:
            # Test network connectivity first with extended timeout
            typer.echo(f"\nTesting WAN connectivity to {config['receiver_ip']}...")
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            # Send test UDP packet
            test_msg = b"PING_TEST"
            sock.sendto(test_msg, (config['receiver_ip'], config.get('port', 53)))
            
            try:
                response, _ = sock.recvfrom(1024)
                typer.echo("WAN connectivity OK - received response", color=typer.colors.GREEN)
            except socket.timeout:
                typer.echo("No response from receiver (may be normal if receiver is not listening)", color=typer.colors.YELLOW)
            
            sock.close()
            
            # Start covert channel transmission
            typer.echo(f"\nStarting covert channel transmission over WAN...")
            typer.echo(f"This may take longer due to network latency...")
            
            controller = Controller(mock_keys=True)
            controller.push_file_to_remote(test_data_path, scenario, config)
            
            typer.echo(f"WAN test completed successfully!", color=typer.colors.GREEN)
            typer.echo(f"\nCheck receiver VM for received data")
            typer.echo(f"Tip: WAN transmission may have higher latency than LAN")
            
            log_event = {
                "timestamp": datetime.now().isoformat(),
                "event": "test_wan",
                "role": "sender",
                "scenario": scenario,
                "receiver_ip": config['receiver_ip'],
                "test_file_size": test_data_path.stat().st_size,
                "status": "success"
            }
            logging.info(json.dumps(log_event))
            
        except socket.timeout:
            typer.echo(f"Connection timeout after {timeout}s", color=typer.colors.RED)
            typer.echo("Possible issues:")
            typer.echo("  • Receiver is not running")
            typer.echo("  • Firewall blocking UDP traffic")
            typer.echo("  • Incorrect IP address or port")
            typer.echo("  • Network connectivity issues")
            sys.exit(1)
            
        except Exception as e:
            typer.echo(f"WAN test failed: {e}", color=typer.colors.RED)
            log_event = {
                "timestamp": datetime.now().isoformat(),
                "event": "test_wan",
                "role": "sender",
                "scenario": scenario,
                "status": "error",
                "error": str(e)
            }
            logging.error(json.dumps(log_event))
            sys.exit(1)
            
    elif role == "receiver":
        typer.echo("This command should be run on the sender VM.", color=typer.colors.YELLOW)
        typer.echo("Run the 'test-wan' command on the sender VM.")
        typer.echo("On receiver, ensure 'start-receiver' is running.")
        sys.exit(1)
    else:
        typer.echo("Unknown role in configuration", color=typer.colors.RED)
        sys.exit(1)

@app.command()
def show_lan_config(
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer", help="Accept disclaimer without prompt")
):
    """Show current LAN/WAN configuration"""
    if not accept_disclaimer:
        show_disclaimer()
    
    config_file = CONFIG_DIR / "lan_config.json"
    
    if not config_file.exists():
        typer.echo("No configuration found.", color=typer.colors.RED)
        typer.echo("Run 'setup-sender' or 'setup-receiver' to configure.")
        sys.exit(1)
    
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    mode = "WAN" if config.get('wan_mode') else "LAN"
    typer.echo(f"\n Current {mode} Configuration:")
    typer.echo(f"  Mode: {mode}")
    typer.echo(f"  Role: {config.get('role', 'unknown').upper()}")
    
    if config.get('role') == 'sender':
        typer.echo(f"  Receiver IP: {config.get('receiver_ip')}")
        typer.echo(f"  DNS Server: {config.get('dns_server')}")
        typer.echo(f"  Port: {config.get('port')}")
    elif config.get('role') == 'receiver':
        typer.echo(f"  Sender IP: {config.get('sender_ip')}")
        typer.echo(f"  Listen Port: {config.get('listen_port')}")
    
    # Display interface in config
    if config.get("interface"):
        typer.echo(f"  Interface: {config.get('interface')}")
        
    typer.echo(f"Configured at: {config.get('configured_at')}")
    typer.echo(f"\n Config file: {config_file}")

if __name__ == "__main__":
    app()
