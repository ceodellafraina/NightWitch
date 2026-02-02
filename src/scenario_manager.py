"""
Scenario Manager
Handles creation, storage and retrieval of scenario configurations
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

class ScenarioManager:
    """Manages covert channel scenarios"""
    
    def __init__(self, config_dir: Path = None):
        self.config_dir = config_dir or Path("scenarios")
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
    def create_scenario(self, config: Dict[str, Any]):
        """Create and save a new scenario"""
        scenario_name = config['name']
        scenario_file = self.config_dir / f"{scenario_name}.json"
        
        if scenario_file.exists():
            raise ValueError(f"Scenario '{scenario_name}' already exists")
        
        # Validate configuration
        self._validate_config(config)
        
        # Save scenario
        with open(scenario_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        logging.info(f"Scenario '{scenario_name}' created and saved")
        
    def get_scenario(self, scenario_name: str) -> Optional[Dict[str, Any]]:
        """Retrieve a scenario configuration"""
        scenario_file = self.config_dir / f"{scenario_name}.json"
        
        if not scenario_file.exists():
            return None
        
        with open(scenario_file, 'r') as f:
            return json.load(f)
    
    def list_scenarios(self) -> list:
        """List all available scenarios"""
        scenarios = []
        for scenario_file in self.config_dir.glob("*.json"):
            with open(scenario_file, 'r') as f:
                config = json.load(f)
                scenarios.append({
                    'name': config['name'],
                    'domain': config['domain'],
                    'carrier': config['carrier'],
                    'created': config['created']
                })
        return scenarios
    
    def delete_scenario(self, scenario_name: str):
        """Delete a scenario"""
        scenario_file = self.config_dir / f"{scenario_name}.json"
        
        if not scenario_file.exists():
            raise ValueError(f"Scenario '{scenario_name}' not found")
        
        scenario_file.unlink()
        logging.info(f"Scenario '{scenario_name}' deleted")
    
    def _validate_config(self, config: Dict[str, Any]):
        """Validate scenario configuration"""
        required_fields = ['name', 'domain', 'carrier', 'ttl', 'chunk_size', 'frequency', 'encryption']
        
        for field in required_fields:
            if field not in config:
                raise ValueError(f"Missing required field: {field}")
        
        # Validate carrier type
        if config['carrier'] not in ['dnskey', 'txt', 'timing']:
            raise ValueError(f"Unsupported carrier type: {config['carrier']}")
        
        # Validate encryption
        if config['encryption'] not in ['none', 'aes256']:
            raise ValueError(f"Unsupported encryption type: {config['encryption']}")
        
        # Validate numeric values
        if config['ttl'] <= 0:
            raise ValueError("TTL must be positive")
        
        if config['chunk_size'] <= 0:
            raise ValueError("Chunk size must be positive")
