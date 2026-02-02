"""
Multi-Channel Orchestrator
Splits payloads across channels, applies FEC (Reed-Solomon) for robustness
"""

import logging
import threading
import time
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from .encoder_decoder import EncoderDecoder
from .zone_manager import ZoneManager
from .traffic_shaper import TrafficShaper

class MultiChannelOrchestrator:
    """Orchestrates multiple covert channels for improved robustness"""
    
    def __init__(self):
        self.channels: Dict[str, Dict[str, Any]] = {}
        self.active_transmissions: Dict[str, Dict[str, Any]] = {}
        self.encoder_decoder = EncoderDecoder()
        
        # Channel types and their capabilities
        self.channel_types = {
            'dnskey': {
                'max_chunk_size': 2048,
                'reliability': 0.95,
                'stealth_level': 'high',
                'latency': 'medium'
            },
            'txt': {
                'max_chunk_size': 255,
                'reliability': 0.98,
                'stealth_level': 'medium',
                'latency': 'low'
            },
            'timing': {
                'max_chunk_size': 1,
                'reliability': 0.85,
                'stealth_level': 'very_high',
                'latency': 'high'
            }
        }
    
    def register_channel(self, channel_id: str, channel_type: str, config: Dict[str, Any]):
        """Register a new covert channel"""
        if channel_type not in self.channel_types:
            raise ValueError(f"Unsupported channel type: {channel_type}")
        
        self.channels[channel_id] = {
            'type': channel_type,
            'config': config,
            'capabilities': self.channel_types[channel_type].copy(),
            'status': 'ready',
            'zone_manager': ZoneManager(),
            'traffic_shaper': TrafficShaper(),
            'registered_at': datetime.now().isoformat(),
            'bytes_transmitted': 0,
            'chunks_transmitted': 0,
            'errors': 0
        }
        
        # Initialize channel components
        channel = self.channels[channel_id]
        channel['zone_manager'].initialize_zone(config['domain'], config.get('ttl', 300))
        channel['traffic_shaper'].configure(
            frequency=config.get('frequency', '30s'),
            domain=config['domain'],
            profile=config.get('profile', 'normal')
        )
        
        logging.info(f"Registered {channel_type} channel: {channel_id}")
    
    def unregister_channel(self, channel_id: str):
        """Unregister a covert channel"""
        if channel_id not in self.channels:
            raise ValueError(f"Channel not found: {channel_id}")
        
        # Clean up channel resources
        channel = self.channels[channel_id]
        channel['zone_manager'].cleanup_zone(channel['config']['domain'])
        
        del self.channels[channel_id]
        logging.info(f"Unregistered channel: {channel_id}")
    
    def transmit_payload(self, payload: bytes, strategy: str = "round_robin", 
                        redundancy_level: int = 1) -> str:
        """Transmit payload across multiple channels"""
        if not self.channels:
            raise ValueError("No channels registered")
        
        transmission_id = f"tx_{int(time.time())}"
        
        # Select channels based on strategy
        selected_channels = self._select_channels(strategy, redundancy_level)
        
        if not selected_channels:
            raise ValueError("No suitable channels available")
        
        # Split payload across channels
        channel_payloads = self._split_payload(payload, selected_channels, strategy)
        
        # Start transmission
        self.active_transmissions[transmission_id] = {
            'payload_size': len(payload),
            'channels': selected_channels,
            'strategy': strategy,
            'redundancy_level': redundancy_level,
            'started_at': datetime.now().isoformat(),
            'status': 'transmitting',
            'progress': {}
        }
        
        # Execute transmission in parallel
        self._execute_parallel_transmission(transmission_id, channel_payloads)
        
        logging.info(f"Started multi-channel transmission: {transmission_id}")
        return transmission_id
    
    def _select_channels(self, strategy: str, redundancy_level: int) -> List[str]:
        """Select channels based on strategy"""
        available_channels = [cid for cid, ch in self.channels.items() if ch['status'] == 'ready']
        
        if not available_channels:
            return []
        
        if strategy == "round_robin":
            # Use all available channels
            return available_channels
        elif strategy == "reliability_first":
            # Sort by reliability, take top N
            sorted_channels = sorted(
                available_channels,
                key=lambda cid: self.channels[cid]['capabilities']['reliability'],
                reverse=True
            )
            return sorted_channels[:redundancy_level]
        elif strategy == "stealth_first":
            # Prioritize stealth level
            stealth_order = {'very_high': 4, 'high': 3, 'medium': 2, 'low': 1}
            sorted_channels = sorted(
                available_channels,
                key=lambda cid: stealth_order.get(
                    self.channels[cid]['capabilities']['stealth_level'], 0
                ),
                reverse=True
            )
            return sorted_channels[:redundancy_level]
        elif strategy == "speed_first":
            # Prioritize low latency
            latency_order = {'low': 3, 'medium': 2, 'high': 1}
            sorted_channels = sorted(
                available_channels,
                key=lambda cid: latency_order.get(
                    self.channels[cid]['capabilities']['latency'], 0
                ),
                reverse=True
            )
            return sorted_channels[:redundancy_level]
        else:
            # Default to first available
            return available_channels[:1]
    
    def _split_payload(self, payload: bytes, channels: List[str], strategy: str) -> Dict[str, bytes]:
        """Split payload across selected channels"""
        channel_payloads = {}
        
        if strategy == "round_robin":
            # Split payload into chunks and distribute round-robin
            total_channels = len(channels)
            chunk_size = max(1, len(payload) // total_channels)
            
            for i, channel_id in enumerate(channels):
                start_idx = i * chunk_size
                if i == total_channels - 1:  # Last channel gets remainder
                    end_idx = len(payload)
                else:
                    end_idx = (i + 1) * chunk_size
                
                channel_payloads[channel_id] = payload[start_idx:end_idx]
        
        elif strategy in ["reliability_first", "stealth_first", "speed_first"]:
            # Primary channel gets full payload, others get redundant copies
            primary_channel = channels[0]
            channel_payloads[primary_channel] = payload
            
            # Add redundant copies to other channels
            for channel_id in channels[1:]:
                channel_payloads[channel_id] = payload
        
        else:
            # Single channel transmission
            channel_payloads[channels[0]] = payload
        
        return channel_payloads
    
    def _execute_parallel_transmission(self, transmission_id: str, channel_payloads: Dict[str, bytes]):
        """Execute transmission across multiple channels in parallel"""
        def transmit_on_channel(channel_id: str, payload: bytes) -> Tuple[str, bool, str]:
            try:
                channel = self.channels[channel_id]
                config = channel['config']
                
                # Encode payload for this channel
                encoded_chunks = self.encoder_decoder.encode(
                    payload=payload,
                    chunk_size=config.get('chunk_size', 200),
                    encryption=config.get('encryption', 'aes256')
                )
                
                # Transmit chunks
                for i, chunk in enumerate(encoded_chunks):
                    # Apply traffic shaping
                    channel['traffic_shaper'].apply_delay()
                    
                    # Publish chunk
                    channel['zone_manager'].publish_chunk(
                        domain=config['domain'],
                        chunk=chunk,
                        sequence=i
                    )
                    
                    # Update progress
                    self.active_transmissions[transmission_id]['progress'][channel_id] = {
                        'chunks_sent': i + 1,
                        'total_chunks': len(encoded_chunks),
                        'progress_percent': ((i + 1) / len(encoded_chunks)) * 100
                    }
                
                # Update channel statistics
                channel['bytes_transmitted'] += len(payload)
                channel['chunks_transmitted'] += len(encoded_chunks)
                
                return channel_id, True, "Success"
                
            except Exception as e:
                logging.error(f"Transmission failed on channel {channel_id}: {e}")
                self.channels[channel_id]['errors'] += 1
                return channel_id, False, str(e)
        
        # Execute transmissions in parallel
        with ThreadPoolExecutor(max_workers=len(channel_payloads)) as executor:
            future_to_channel = {
                executor.submit(transmit_on_channel, cid, payload): cid
                for cid, payload in channel_payloads.items()
            }
            
            results = {}
            for future in as_completed(future_to_channel):
                channel_id, success, message = future.result()
                results[channel_id] = {'success': success, 'message': message}
        
        # Update transmission status
        successful_channels = sum(1 for r in results.values() if r['success'])
        total_channels = len(results)
        
        transmission = self.active_transmissions[transmission_id]
        transmission['completed_at'] = datetime.now().isoformat()
        transmission['results'] = results
        transmission['success_rate'] = successful_channels / total_channels
        
        if successful_channels > 0:
            transmission['status'] = 'completed'
        else:
            transmission['status'] = 'failed'
        
        logging.info(f"Multi-channel transmission {transmission_id} completed: {successful_channels}/{total_channels} channels successful")
    
    def receive_payload(self, transmission_id: str, timeout: int = 300) -> Optional[bytes]:
        """Receive and reconstruct payload from multiple channels"""
        if transmission_id not in self.active_transmissions:
            raise ValueError(f"Transmission not found: {transmission_id}")
        
        transmission = self.active_transmissions[transmission_id]
        channels = transmission['channels']
        strategy = transmission['strategy']
        
        # Collect chunks from all channels
        channel_chunks = {}
        
        for channel_id in channels:
            try:
                channel = self.channels[channel_id]
                config = channel['config']
                
                # Retrieve chunks from this channel
                chunks = channel['zone_manager'].retrieve_chunks(
                    domain=config['domain'],
                    max_chunks=100
                )
                
                if chunks:
                    channel_chunks[channel_id] = chunks
                    logging.info(f"Retrieved {len(chunks)} chunks from channel {channel_id}")
                
            except Exception as e:
                logging.error(f"Failed to retrieve from channel {channel_id}: {e}")
        
        if not channel_chunks:
            logging.error("No chunks retrieved from any channel")
            return None
        
        # Reconstruct payload based on strategy
        if strategy == "round_robin":
            return self._reconstruct_split_payload(channel_chunks, channels)
        else:
            return self._reconstruct_redundant_payload(channel_chunks)
    
    def _reconstruct_split_payload(self, channel_chunks: Dict[str, Dict[int, str]], 
                                 channel_order: List[str]) -> Optional[bytes]:
        """Reconstruct payload that was split across channels"""
        channel_payloads = {}
        
        # Decode chunks from each channel
        for channel_id, chunks in channel_chunks.items():
            try:
                # Sort chunks by sequence number
                sorted_chunks = [chunks[i] for i in sorted(chunks.keys())]
                
                # Decode payload
                config = self.channels[channel_id]['config']
                payload = self.encoder_decoder.decode(
                    encoded_chunks=sorted_chunks,
                    encryption=config.get('encryption', 'aes256')
                )
                
                channel_payloads[channel_id] = payload
                
            except Exception as e:
                logging.error(f"Failed to decode chunks from channel {channel_id}: {e}")
        
        # Reconstruct original payload by concatenating in order
        reconstructed = b""
        for channel_id in channel_order:
            if channel_id in channel_payloads:
                reconstructed += channel_payloads[channel_id]
        
        return reconstructed if reconstructed else None
    
    def _reconstruct_redundant_payload(self, channel_chunks: Dict[str, Dict[int, str]]) -> Optional[bytes]:
        """Reconstruct payload from redundant channels (choose best)"""
        decoded_payloads = []
        
        # Try to decode from each channel
        for channel_id, chunks in channel_chunks.items():
            try:
                # Sort chunks by sequence number
                sorted_chunks = [chunks[i] for i in sorted(chunks.keys())]
                
                # Decode payload
                config = self.channels[channel_id]['config']
                payload = self.encoder_decoder.decode(
                    encoded_chunks=sorted_chunks,
                    encryption=config.get('encryption', 'aes256')
                )
                
                decoded_payloads.append((channel_id, payload))
                
            except Exception as e:
                logging.warning(f"Failed to decode from channel {channel_id}: {e}")
        
        if not decoded_payloads:
            return None
        
        # Return payload from most reliable channel
        if len(decoded_payloads) == 1:
            return decoded_payloads[0][1]
        
        # If multiple payloads, choose from most reliable channel
        best_channel = max(
            decoded_payloads,
            key=lambda x: self.channels[x[0]]['capabilities']['reliability']
        )
        
        return best_channel[1]
    
    def get_transmission_status(self, transmission_id: str) -> Dict[str, Any]:
        """Get status of a transmission"""
        return self.active_transmissions.get(transmission_id, {})
    
    def list_channels(self) -> Dict[str, Dict[str, Any]]:
        """List all registered channels"""
        return {cid: {
            'type': ch['type'],
            'domain': ch['config']['domain'],
            'status': ch['status'],
            'bytes_transmitted': ch['bytes_transmitted'],
            'chunks_transmitted': ch['chunks_transmitted'],
            'errors': ch['errors']
        } for cid, ch in self.channels.items()}
    
    def get_channel_statistics(self) -> Dict[str, Any]:
        """Get aggregated channel statistics"""
        total_channels = len(self.channels)
        active_channels = sum(1 for ch in self.channels.values() if ch['status'] == 'ready')
        total_bytes = sum(ch['bytes_transmitted'] for ch in self.channels.values())
        total_chunks = sum(ch['chunks_transmitted'] for ch in self.channels.values())
        total_errors = sum(ch['errors'] for ch in self.channels.values())
        
        return {
            'total_channels': total_channels,
            'active_channels': active_channels,
            'total_bytes_transmitted': total_bytes,
            'total_chunks_transmitted': total_chunks,
            'total_errors': total_errors,
            'error_rate': total_errors / max(1, total_chunks),
            'active_transmissions': len([t for t in self.active_transmissions.values() if t['status'] == 'transmitting'])
        }
