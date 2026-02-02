"""
Lab Manager
Handles initialization of isolated lab environments
"""

import subprocess
import logging
import time
from pathlib import Path
from typing import Dict, Any

class LabManager:
    """Manages lab environment setup and teardown"""
    
    def __init__(self, mode: str = "docker"):
        self.mode = mode
        self.lab_dir = Path("docker")
        
    def initialize(self):
        """Initialize the lab environment"""
        if self.mode == "docker":
            self._initialize_docker_lab()
        elif self.mode == "vm":
            self._initialize_vm_lab()
        elif self.mode == "local":
            self._initialize_local_lab()
        else:
            raise ValueError(f"Unsupported lab mode: {self.mode}")
    
    def _initialize_local_lab(self):
        """Initialize local testing environment without Docker"""
        logging.info("Initializing local lab environment...")
        
        print("🔍 Setting up local test environment...")
        
        # Create necessary directories
        directories = [
            Path("./test_data"),
            Path("./test_results"),
            Path("./logs"),
            Path("./scenarios")
        ]
        
        for directory in directories:
            directory.mkdir(exist_ok=True)
            print(f"✅ Created directory: {directory}")
        
        # Check Python dependencies
        print("🔍 Checking Python dependencies...")
        try:
            import dns.resolver
            import cryptography
            import scapy
            print("✅ Core dependencies available")
        except ImportError as e:
            print(f"⚠️  Missing dependency: {e}")
            print("   Install with: pip install -r requirements.txt")
        
        # Create test DNS configuration
        print("🔍 Setting up local DNS test configuration...")
        test_config = {
            "dns_server": "8.8.8.8",  # Use public DNS for testing
            "test_domain": "example.test",
            "local_mode": True,
            "skip_ids": True  # Skip IDS testing in local mode
        }
        
        config_file = Path("./test_data/local_config.json")
        import json
        with open(config_file, 'w') as f:
            json.dump(test_config, f, indent=2)
        
        print(f"✅ Created test configuration: {config_file}")
        
        # Create sample test file
        sample_file = Path("./test_data/sample.txt")
        with open(sample_file, 'w') as f:
            f.write("This is a sample file for testing the TESI covert channel toolkit.\n")
            f.write("Local mode allows testing without Docker containers.\n")
        
        print(f"✅ Created sample test file: {sample_file}")
        
        print("🎉 Local lab environment initialized successfully!")
        print("\nNext steps:")
        print("1. Create a scenario: python tesictl.py create-scenario --name test-local")
        print("2. Test encoding: python -c \"from src.encoder_decoder import EncoderDecoder; ed = EncoderDecoder(); print('Encoder test:', ed.encode('test'))\"")
        print("3. Monitor logs in: ./logs/")
        
        logging.info("Local lab environment initialized successfully")

    def _initialize_docker_lab(self):
        """Initialize Docker-based lab"""
        logging.info("Initializing Docker lab environment...")
        
        print("🔍 Checking Docker installation...")
        
        # Check if Docker is available
        try:
            subprocess.run(["docker", "--version"], check=True, capture_output=True, timeout=10)
        except FileNotFoundError:
            raise RuntimeError(
                "Docker is not installed. Please install Docker first:\n"
                "- On Ubuntu/Debian: sudo apt-get install docker.io docker-compose\n"
                "- On macOS: Install Docker Desktop from https://docker.com\n"
                "- On Windows: Install Docker Desktop from https://docker.com"
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Docker is installed but not working properly: {e}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Docker command timed out - Docker may be unresponsive")
        
        print("✅ Docker found")
        print("🔍 Checking Docker daemon...")
        
        # Check if Docker daemon is running
        try:
            subprocess.run(["docker", "info"], check=True, capture_output=True, timeout=10)
        except subprocess.CalledProcessError:
            raise RuntimeError(
                "Docker daemon is not running. Please start Docker:\n"
                "- On Linux: sudo systemctl start docker\n"
                "- On macOS/Windows: Start Docker Desktop application"
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Docker daemon check timed out - Docker may be starting up")
        
        print("✅ Docker daemon running")
        print("🔍 Checking docker-compose...")
        
        # Check if docker-compose is available
        try:
            subprocess.run(["docker-compose", "--version"], check=True, capture_output=True, timeout=10)
        except FileNotFoundError:
            raise RuntimeError(
                "docker-compose is not installed. Please install docker-compose:\n"
                "- On Ubuntu/Debian: sudo apt-get install docker-compose\n"
                "- On macOS/Windows: It's included with Docker Desktop"
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("docker-compose command timed out")
        
        print("✅ docker-compose found")
        
        # Build and start lab containers
        project_root = Path(__file__).parent.parent  # Go up from src/ to project root
        compose_file = project_root / "docker" / "docker-compose.yml"
        docker_dir = project_root / "docker"
        
        if not compose_file.exists():
            raise FileNotFoundError(f"Docker compose file not found: {compose_file}")
        
        print("🛑 Stopping any existing lab containers...")
        # Stop any existing lab
        subprocess.run([
            "docker-compose", 
            "-f", "docker-compose.yml", "down"
        ], cwd=str(docker_dir), capture_output=True, timeout=30)
        
        print("🏗️  Building and starting lab containers...")
        print("   📥 This may take several minutes for first-time setup")
        print("   🔨 Progress will be shown below:")
        print()
        
        # Start lab with real-time output and progress monitoring
        process = subprocess.Popen([
            "docker-compose", 
            "-f", "docker-compose.yml", "up", 
            "-d", "--build"
        ], cwd=str(docker_dir), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
           text=True, universal_newlines=True)
        
        # Monitor progress in real-time
        import threading
        import sys
        
        def monitor_progress():
            step_count = 0
            last_line = ""
            
            while process.poll() is None:
                try:
                    # Check container status
                    status_result = subprocess.run([
                        "docker-compose", "-f", "docker-compose.yml", "ps", "--format", "table"
                    ], cwd=str(docker_dir), capture_output=True, text=True, timeout=5)
                    
                    if status_result.returncode == 0:
                        lines = status_result.stdout.strip().split('\n')
                        if len(lines) > 1:  # Skip header
                            running_count = 0
                            total_count = len(lines) - 1
                            
                            for line in lines[1:]:
                                if 'Up' in line or 'running' in line:
                                    running_count += 1
                            
                            if total_count > 0:
                                progress = (running_count / total_count) * 100
                                print(f"\r   📊 Progress: {progress:.0f}% ({running_count}/{total_count} services ready)", end="", flush=True)
                            
                            if running_count == total_count and total_count > 0:
                                print(f"\n   ✅ All {total_count} services are ready!")
                                break
                    
                    # Show activity indicator
                    step_count += 1
                    indicators = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
                    if step_count % 10 == 0:  # Update less frequently
                        print(f"\r   {indicators[step_count % len(indicators)]} Working...", end="", flush=True)
                    
                    time.sleep(2)
                    
                except subprocess.TimeoutExpired:
                    continue
                except Exception:
                    # Fallback to simple dots
                    print(".", end="", flush=True)
                    time.sleep(3)
        
        progress_thread = threading.Thread(target=monitor_progress)
        progress_thread.daemon = True
        progress_thread.start()
        
        try:
            stdout, stderr = process.communicate()  # No timeout
            
            if process.returncode != 0:
                print(f"\n❌ Failed to start Docker lab:")
                print(f"Output: {stdout}")
                if stderr:
                    print(f"Error: {stderr}")
                raise RuntimeError(f"Failed to start Docker lab: {stdout}")
            
            print(f"\n✅ Docker containers started successfully")
            
        except KeyboardInterrupt:
            print(f"\n⚠️  Interrupted by user. Cleaning up...")
            process.terminate()
            subprocess.run([
                "docker-compose", "-f", "docker-compose.yml", "down"
            ], cwd=str(docker_dir), capture_output=True)
            raise RuntimeError("Docker lab startup interrupted by user")
        
        # Wait for services to be ready
        print("⏳ Waiting for services to initialize...")
        self._wait_for_services()
        
        print("🎉 Docker lab environment initialized successfully!")
        logging.info("Docker lab environment initialized successfully")
    
    def _initialize_vm_lab(self):
        """Initialize VM-based lab (placeholder)"""
        logging.info("VM lab initialization not yet implemented")
        raise NotImplementedError("VM lab mode is not yet implemented")
    
    def _wait_for_services(self):
        """Wait for lab services to be ready"""
        logging.info("Waiting for lab services to be ready...")
        
        print("🔍 Checking DNS server readiness...")
        
        # Wait for DNS server
        max_retries = 15  # Reduced from 30 for faster feedback
        for i in range(max_retries):
            try:
                result = subprocess.run([
                    "docker", "exec", "tesi-dns-server", "dig", "@localhost", "example.test", "SOA"
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and "ANSWER SECTION" in result.stdout:
                    print("✅ DNS server is ready")
                    logging.info("DNS server is ready")
                    break
            except subprocess.TimeoutExpired:
                pass
            except subprocess.CalledProcessError:
                pass  # Container might still be starting
            
            if i == max_retries - 1:
                print("⚠️  DNS server check timed out, but continuing...")
                print("   You can manually check with: docker-compose -f docker/docker-compose.yml logs")
                logging.warning("DNS server failed to respond within timeout, continuing anyway")
                break
            
            print(".", end="", flush=True)
            time.sleep(4)  # Increased sleep time
        
        # Additional service checks can be added here
        print("\n⏳ Final initialization...")
        time.sleep(3)  # Reduced final wait time
    
    def teardown(self):
        """Teardown the lab environment"""
        if self.mode == "docker":
            self._teardown_docker_lab()
        elif self.mode == "vm":
            self._teardown_vm_lab()
        elif self.mode == "local":
            self._teardown_local_lab()
    
    def _teardown_docker_lab(self):
        """Teardown Docker lab"""
        logging.info("Tearing down Docker lab environment...")
        
        project_root = Path(__file__).parent.parent
        docker_dir = project_root / "docker"
        
        subprocess.run([
            "docker-compose", "-f", "docker-compose.yml", "down", "-v"
        ], cwd=str(docker_dir), capture_output=True)
        
        logging.info("Docker lab environment torn down")

    def _teardown_vm_lab(self):
        """Teardown VM lab (placeholder)"""
        logging.info("VM lab teardown not yet implemented")
    
    def _teardown_local_lab(self):
        """Teardown local lab environment"""
        logging.info("Tearing down local lab environment...")
        print("🧹 Cleaning up local test environment...")
        
        # Optional cleanup - user might want to keep test data
        import shutil
        cleanup_dirs = ["./test_results"]  # Don't delete test_data by default
        
        for directory in cleanup_dirs:
            if Path(directory).exists():
                shutil.rmtree(directory)
                print(f"✅ Cleaned up: {directory}")
        
        print("✅ Local lab environment cleaned up")
        logging.info("Local lab environment torn down")

    def get_lab_status(self) -> Dict[str, Any]:
        """Get current lab status"""
        if self.mode == "docker":
            return self._get_docker_lab_status()
        elif self.mode == "vm":
            return self._get_vm_lab_status()
        elif self.mode == "local":
            return self._get_local_lab_status()
        
        return {"status": "unknown"}
    
    def _get_docker_lab_status(self) -> Dict[str, Any]:
        """Get Docker lab status"""
        try:
            project_root = Path(__file__).parent.parent
            docker_dir = project_root / "docker"
            
            result = subprocess.run([
                "docker-compose", "-f", "docker-compose.yml", "ps"
            ], capture_output=True, text=True, cwd=str(docker_dir))
            
            return {
                "mode": "docker",
                "status": "running" if result.returncode == 0 else "stopped",
                "services": result.stdout
            }
        except Exception as e:
            return {
                "mode": "docker", 
                "status": "error",
                "error": str(e)
            }
    
    def _get_vm_lab_status(self) -> Dict[str, Any]:
        """Get VM lab status (placeholder)"""
        return {
            "mode": "vm",
            "status": "not_implemented"
        }
    
    def _get_local_lab_status(self) -> Dict[str, Any]:
        """Get local lab status"""
        config_file = Path("./test_data/local_config.json")
        
        return {
            "mode": "local",
            "status": "ready" if config_file.exists() else "not_initialized",
            "config_file": str(config_file),
            "test_directories": [
                str(d) for d in [Path("./test_data"), Path("./test_results"), Path("./logs")]
                if d.exists()
            ]
        }
