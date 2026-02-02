"""
Encoder / Decoder Engine
Encodes payloads into carrier format and decodes on receiver
Pipeline: compress → encrypt (AES-GCM) → chunk → sequence + CRC → Reed-Solomon → Base64
"""

import zlib
import base64
import struct
import hashlib
import logging
from typing import List, Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import reedsolo

class EncoderDecoder:
    """Handles encoding and decoding of payloads for covert channels"""
    
    def __init__(self):
        self.rs_codec = reedsolo.RSCodec(10)  # Reed-Solomon with 10 error correction symbols
        
    def encode(self, payload: bytes, chunk_size: int, encryption: str = "aes256", 
               password: Optional[str] = None) -> List[str]:
        """
        Encode payload through the complete pipeline
        Returns list of Base64-encoded chunks ready for transmission
        """
        logging.info(f"Starting encoding pipeline for {len(payload)} bytes")
        
        # Step 1: Compress payload
        compressed = self._compress(payload)
        logging.info(f"Compressed: {len(payload)} → {len(compressed)} bytes")
        
        # Step 2: Encrypt if requested
        if encryption != "none":
            encrypted = self._encrypt(compressed, encryption, password)
            logging.info(f"Encrypted: {len(compressed)} → {len(encrypted)} bytes")
        else:
            encrypted = compressed
        
        # Step 3: Add metadata header
        header = self._create_header(len(payload), len(encrypted), encryption)
        data_with_header = header + encrypted
        
        # Step 4: Split into chunks
        chunks = self._chunk_data(data_with_header, chunk_size)
        logging.info(f"Split into {len(chunks)} chunks")
        
        # Step 5: Add sequence numbers and CRC to each chunk
        sequenced_chunks = []
        for i, chunk in enumerate(chunks):
            sequenced_chunk = self._add_sequence_and_crc(chunk, i, len(chunks))
            sequenced_chunks.append(sequenced_chunk)
        
        # Step 6: Apply Reed-Solomon error correction
        rs_chunks = []
        for chunk in sequenced_chunks:
            rs_chunk = self._apply_reed_solomon(chunk)
            rs_chunks.append(rs_chunk)
        
        # Step 7: Base64 encode for transmission
        encoded_chunks = []
        for chunk in rs_chunks:
            b64_chunk = base64.b64encode(chunk).decode('ascii')
            encoded_chunks.append(b64_chunk)
        
        logging.info(f"Encoding complete: {len(encoded_chunks)} Base64 chunks ready")
        return encoded_chunks
    
    def decode(self, encoded_chunks: List[str], encryption: str = "aes256", 
               password: Optional[str] = None) -> bytes:
        """
        Decode chunks through the reverse pipeline
        Returns original payload
        """
        logging.info(f"Starting decoding pipeline for {len(encoded_chunks)} chunks")
        
        # Step 1: Base64 decode
        raw_chunks = []
        for chunk in encoded_chunks:
            try:
                raw_chunk = base64.b64decode(chunk.encode('ascii'))
                raw_chunks.append(raw_chunk)
            except Exception as e:
                logging.warning(f"Failed to decode Base64 chunk: {e}")
                continue
        
        # Step 2: Apply Reed-Solomon error correction
        corrected_chunks = []
        for chunk in raw_chunks:
            try:
                corrected_chunk = self._correct_reed_solomon(chunk)
                corrected_chunks.append(corrected_chunk)
            except Exception as e:
                logging.warning(f"Reed-Solomon correction failed: {e}")
                continue
        
        # Step 3: Verify sequence and CRC, extract data
        chunk_data = {}
        total_chunks = 0
        
        for chunk in corrected_chunks:
            try:
                data, seq_num, total = self._extract_sequence_and_verify_crc(chunk)
                chunk_data[seq_num] = data
                total_chunks = max(total_chunks, total)
            except Exception as e:
                logging.warning(f"Sequence/CRC verification failed: {e}")
                continue
        
        # Step 4: Reassemble chunks in order
        reassembled = b""
        missing_chunks = []
        
        for i in range(total_chunks):
            if i in chunk_data:
                reassembled += chunk_data[i]
            else:
                missing_chunks.append(i)
        
        if missing_chunks:
            logging.warning(f"Missing chunks: {missing_chunks}")
        
        # Step 5: Extract header and validate
        try:
            header, encrypted_data = self._extract_header(reassembled)
            original_size = header['original_size']
            encrypted_size = header['encrypted_size']
            encryption_type = header['encryption']
            
            if len(encrypted_data) != encrypted_size:
                logging.warning(f"Size mismatch: expected {encrypted_size}, got {len(encrypted_data)}")
        
        except Exception as e:
            logging.error(f"Header extraction failed: {e}")
            raise ValueError("Invalid or corrupted header")
        
        # Step 6: Decrypt if needed
        if encryption_type != "none":
            decrypted = self._decrypt(encrypted_data, encryption_type, password)
        else:
            decrypted = encrypted_data
        
        # Step 7: Decompress
        try:
            decompressed = self._decompress(decrypted)
        except Exception as e:
            logging.error(f"Decompression failed: {e}")
            raise ValueError("Decompression failed - data may be corrupted")
        
        # Verify final size
        if len(decompressed) != original_size:
            logging.warning(f"Final size mismatch: expected {original_size}, got {len(decompressed)}")
        
        logging.info(f"Decoding complete: recovered {len(decompressed)} bytes")
        return decompressed
    
    def _compress(self, data: bytes) -> bytes:
        """Compress data using zlib"""
        return zlib.compress(data, level=6)
    
    def _decompress(self, data: bytes) -> bytes:
        """Decompress data using zlib"""
        return zlib.decompress(data)
    
    def _encrypt(self, data: bytes, encryption: str, password: Optional[str] = None) -> bytes:
        """Encrypt data using AES-GCM"""
        if encryption == "none":
            return data
        
        if encryption != "aes256":
            raise ValueError(f"Unsupported encryption type: {encryption}")
        
        # Generate key from password or use default
        if password is None:
            password = "tesi_default_key_2024"
        
        # Derive key using PBKDF2
        salt = b"tesi_salt_2024_dnssec_covert"  # Fixed salt for reproducibility in PoC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        
        # Encrypt with AES-GCM
        aesgcm = AESGCM(key)
        nonce = b"tesi_nonce12"  # Exactly 12 bytes for AES-GCM
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        # Return nonce + ciphertext
        return nonce + ciphertext
    
    def _decrypt(self, data: bytes, encryption: str, password: Optional[str] = None) -> bytes:
        """Decrypt data using AES-GCM"""
        if encryption == "none":
            return data
        
        if encryption != "aes256":
            raise ValueError(f"Unsupported encryption type: {encryption}")
        
        if len(data) < 12:
            raise ValueError("Encrypted data too short - missing nonce")
        
        # Generate same key
        if password is None:
            password = "tesi_default_key_2024"
        
        salt = b"tesi_salt_2024_dnssec_covert"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        
        # Extract nonce and ciphertext
        nonce = data[:12]
        ciphertext = data[12:]
        
        if len(ciphertext) == 0:
            raise ValueError("No ciphertext found after nonce")
        
        # Decrypt
        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception as e:
            logging.error(f"AES-GCM decryption failed: {e}")
            raise ValueError(f"Decryption failed: {e}")
    
    def _create_header(self, original_size: int, encrypted_size: int, encryption: str) -> bytes:
        """Create metadata header"""
        # Header format: magic(4) + version(1) + encryption_len(1) + encryption + original_size(4) + encrypted_size(4)
        magic = b"TESI"
        version = 1
        encryption_bytes = encryption.encode('ascii')
        encryption_len = len(encryption_bytes)
        
        header = struct.pack(
            f"!4sBB{encryption_len}sII",
            magic,
            version,
            encryption_len,
            encryption_bytes,
            original_size,
            encrypted_size
        )
        
        return header
    
    def _extract_header(self, data: bytes) -> Tuple[dict, bytes]:
        """Extract and parse header"""
        if len(data) < 10:  # Minimum header size
            raise ValueError("Data too short for header")
        
        # Parse fixed part
        magic, version, encryption_len = struct.unpack("!4sBB", data[:6])
        
        if magic != b"TESI":
            raise ValueError("Invalid magic number")
        
        if version != 1:
            raise ValueError(f"Unsupported version: {version}")
        
        # Parse variable part
        header_size = 6 + encryption_len + 8  # Fixed + encryption + sizes
        if len(data) < header_size:
            raise ValueError("Data too short for complete header")
        
        encryption_bytes, original_size, encrypted_size = struct.unpack(
            f"!{encryption_len}sII",
            data[6:header_size]
        )
        
        header = {
            'version': version,
            'encryption': encryption_bytes.decode('ascii'),
            'original_size': original_size,
            'encrypted_size': encrypted_size
        }
        
        return header, data[header_size:]
    
    def _chunk_data(self, data: bytes, chunk_size: int) -> List[bytes]:
        """Split data into chunks"""
        chunks = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            chunks.append(chunk)
        return chunks
    
    def _add_sequence_and_crc(self, chunk: bytes, seq_num: int, total_chunks: int) -> bytes:
        """Add sequence number and CRC32 to chunk"""
        # Calculate CRC32 of the chunk data
        crc = zlib.crc32(chunk) & 0xffffffff
        
        # Format: seq_num(4) + total_chunks(4) + crc(4) + data
        header = struct.pack("!III", seq_num, total_chunks, crc)
        return header + chunk
    
    def _extract_sequence_and_verify_crc(self, chunk: bytes) -> Tuple[bytes, int, int]:
        """Extract sequence info and verify CRC"""
        if len(chunk) < 12:  # 3 * 4 bytes for header
            raise ValueError("Chunk too short for sequence header")
        
        # Extract header
        seq_num, total_chunks, expected_crc = struct.unpack("!III", chunk[:12])
        data = chunk[12:]
        
        # Verify CRC
        actual_crc = zlib.crc32(data) & 0xffffffff
        if actual_crc != expected_crc:
            raise ValueError(f"CRC mismatch: expected {expected_crc:08x}, got {actual_crc:08x}")
        
        return data, seq_num, total_chunks
    
    def _apply_reed_solomon(self, data: bytes) -> bytes:
        """Apply Reed-Solomon error correction"""
        try:
            return self.rs_codec.encode(data)
        except Exception as e:
            logging.error(f"Reed-Solomon encoding failed: {e}")
            # Return original data if RS encoding fails
            return data
    
    def _correct_reed_solomon(self, data: bytes) -> bytes:
        """Apply Reed-Solomon error correction"""
        try:
            corrected, corrected_ecc, errata_pos = self.rs_codec.decode(data)
            if errata_pos:
                logging.info(f"Reed-Solomon corrected {len(errata_pos)} errors")
            return corrected
        except Exception as e:
            logging.warning(f"Reed-Solomon correction failed: {e}")
            # Try to extract original data (remove ECC symbols)
            try:
                # RS codec adds 10 symbols, so try to get original data
                return data[:-10]
            except:
                return data
    
    def estimate_overhead(self, payload_size: int, chunk_size: int, encryption: str = "aes256") -> dict:
        """Estimate encoding overhead"""
        # Compression ratio estimate (varies by data type)
        compression_ratio = 0.7  # Assume 30% compression
        compressed_size = int(payload_size * compression_ratio)
        
        # Encryption overhead
        if encryption == "aes256":
            encrypted_size = compressed_size + 12 + 16  # nonce + auth tag
        else:
            encrypted_size = compressed_size
        
        # Header overhead
        header_size = 20  # Approximate header size
        data_with_header = encrypted_size + header_size
        
        # Chunking overhead
        num_chunks = (data_with_header + chunk_size - 1) // chunk_size
        sequence_overhead = num_chunks * 12  # 12 bytes per chunk for sequence info
        
        # Reed-Solomon overhead (10 symbols per chunk)
        rs_overhead = num_chunks * 10
        
        # Base64 overhead (4/3 expansion)
        total_before_b64 = data_with_header + sequence_overhead + rs_overhead
        total_after_b64 = int(total_before_b64 * 4 / 3)
        
        return {
            'original_size': payload_size,
            'compressed_size': compressed_size,
            'encrypted_size': encrypted_size,
            'total_chunks': num_chunks,
            'total_encoded_size': total_after_b64,
            'overhead_ratio': total_after_b64 / payload_size,
            'compression_ratio': compression_ratio
        }
    
    def validate_encoding(self, original: bytes, chunk_size: int, encryption: str = "aes256") -> bool:
        """Validate encoding/decoding pipeline"""
        try:
            # Encode
            encoded_chunks = self.encode(original, chunk_size, encryption)
            
            # Decode
            decoded = self.decode(encoded_chunks, encryption)
            
            # Compare
            return original == decoded
            
        except Exception as e:
            logging.error(f"Validation failed: {e}")
            return False
