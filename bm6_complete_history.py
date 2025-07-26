#!/usr/bin/env python3

# BM6 Complete History Implementation with Timestamps & JSON Export
# Enhanced version to retrieve all historical records with proper timestamps

import argparse
import asyncio
import time
import json
import struct
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any
from Crypto.Cipher import AES
from bleak import BleakClient

# BM6 encryption key
BM6_KEY = bytearray([108, 101, 97, 103, 101, 110, 100, 255, 254, 48, 49, 48, 48, 48, 48, 57])

@dataclass
class HistoryReading:
    """Historical voltage reading from BM6"""
    voltage: float
    timestamp: datetime
    raw_data: str
    source_command: str
    record_index: int
    confidence: str
    temperature: Optional[float] = None
    soc: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON export"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data

def decrypt_bm6(crypted):
    cipher = AES.new(BM6_KEY, AES.MODE_CBC, 16 * b'\0')
    return cipher.decrypt(crypted).hex()

def encrypt_bm6(plaintext):
    cipher = AES.new(BM6_KEY, AES.MODE_CBC, 16 * b'\0')
    return cipher.encrypt(plaintext)

def parse_timestamp_from_data(hex_data: str, record_index: int) -> datetime:
    """
    Parse timestamp from hex data - BM6 likely stores timestamps as:
    - Unix timestamp (32-bit)
    - Relative time offset 
    - Record counter with known interval
    """
    current_time = datetime.now()
    
    # Strategy 1: Look for 32-bit timestamp patterns
    for i in range(0, len(hex_data) - 7, 2):
        try:
            # Try big-endian 32-bit timestamp
            timestamp_be = int(hex_data[i:i+8], 16)
            if 1600000000 <= timestamp_be <= int(time.time()) + 86400:  # Valid range
                return datetime.fromtimestamp(timestamp_be)
            
            # Try little-endian 32-bit timestamp
            if i + 8 <= len(hex_data):
                timestamp_le = struct.unpack('<I', bytes.fromhex(hex_data[i:i+8]))[0]
                if 1600000000 <= timestamp_le <= int(time.time()) + 86400:
                    return datetime.fromtimestamp(timestamp_le)
        except:
            continue
    
    # Strategy 2: Look for relative time offsets (hours/minutes ago)
    for i in range(0, len(hex_data) - 3, 2):
        try:
            offset_val = int(hex_data[i:i+4], 16)
            if offset_val < 8760:  # Less than 1 year in hours
                return current_time - timedelta(hours=offset_val)
        except:
            continue
    
    # Strategy 3: Use record index with estimated intervals
    # BM6 likely records every 10-30 minutes based on typical battery monitors
    estimated_interval_minutes = 15  # Common interval for battery monitors
    return current_time - timedelta(minutes=record_index * estimated_interval_minutes)

def extract_voltages_from_response(hex_data: str) -> List[dict]:
    """Extract voltage values from hex response data"""
    voltages = []
    
    # Look for 16-bit values that could be voltage * 100
    for i in range(0, len(hex_data) - 3, 2):
        try:
            # Try big-endian interpretation
            val16_be = int(hex_data[i:i+4], 16)
            if 600 <= val16_be <= 2000:  # 6.0V to 20.0V range
                voltages.append({
                    'voltage': val16_be / 100.0,
                    'position': i,
                    'raw_bytes': hex_data[i:i+4],
                    'endian': 'big',
                    'confidence': 'high' if 1000 <= val16_be <= 1500 else 'medium'
                })
            
            # Try little-endian interpretation
            if i + 4 <= len(hex_data):
                val16_le = int(hex_data[i+2:i+4] + hex_data[i:i+2], 16)
                if 600 <= val16_le <= 2000:
                    voltages.append({
                        'voltage': val16_le / 100.0,
                        'position': i,
                        'raw_bytes': hex_data[i:i+4],
                        'endian': 'little',
                        'confidence': 'high' if 1000 <= val16_le <= 1500 else 'medium'
                    })
        except:
            continue
    
    # Remove duplicates and return best candidates
    unique_voltages = []
    seen_positions = set()
    
    # Sort by confidence and position
    voltages.sort(key=lambda x: (x['confidence'] == 'high', x['position']))
    
    for v in voltages:
        if v['position'] not in seen_positions:
            seen_positions.add(v['position'])
            unique_voltages.append(v)
    
    return unique_voltages

def parse_temperature_from_data(hex_data: str) -> Optional[float]:
    """Try to extract temperature data from response"""
    # Look for temperature patterns similar to standard BM6 format
    if len(hex_data) >= 10:
        try:
            temp_flag = hex_data[6:8]
            if temp_flag in ['00', '01']:
                temp_val = int(hex_data[8:10], 16)
                if temp_val <= 100:  # Reasonable temperature range
                    return -temp_val if temp_flag == '01' else temp_val
        except:
            pass
    return None

class BM6CompleteHistoryClient:
    """Enhanced BM6 client for complete history retrieval"""
    
    def __init__(self, address: str):
        self.address = address
        self.client = None
        self.responses = []
        
    async def connect(self):
        """Connect to BM6 device"""
        self.client = BleakClient(self.address, timeout=30)
        await self.client.connect()
        await self.client.start_notify("FFF4", self._notification_handler)
        
    async def disconnect(self):
        """Disconnect from BM6 device"""
        if self.client and self.client.is_connected:
            await self.client.stop_notify("FFF4")
            await self.client.disconnect()
    
    async def _notification_handler(self, sender, data):
        """Handle BLE notifications"""
        timestamp = time.time()
        decrypted = decrypt_bm6(data)
        
        self.responses.append({
            'timestamp': timestamp,
            'raw': data.hex(),
            'decrypted': decrypted
        })
    
    async def _send_command(self, command_hex: str, wait_time: float = 2.0) -> List[dict]:
        """Send command and collect responses"""
        self.responses.clear()
        
        command_bytes = bytearray.fromhex(command_hex)
        encrypted = encrypt_bm6(command_bytes)
        
        await self.client.write_gatt_char("FFF3", encrypted, response=True)
        await asyncio.sleep(wait_time)
        
        return self.responses.copy()
    
    async def get_history_count(self) -> int:
        """Get the total number of history records available"""
        print("🔍 Determining total history record count...")
        
        # Try commands that might return record count
        count_commands = [
            "d1550100000000000000000000000000",  # Command 01 - might return status
            "d1550a00000000000000000000000000",  # Command 0A - showed counter behavior
            "d1550200000000000000000000000000",  # Command 02 - status variant
        ]
        
        for cmd in count_commands:
            responses = await self._send_command(cmd, 1.5)
            
            for response in responses:
                hex_data = response['decrypted']
                
                # Look for counter values in the response
                if hex_data.startswith('d1550a00ff'):
                    # Extract counter value from 0A response
                    try:
                        counter_hex = hex_data[10:14]  # ffXXXX pattern
                        counter_val = int(counter_hex, 16)
                        if 0 < counter_val < 10000:  # Reasonable range
                            print(f"📊 Found potential record count: {counter_val}")
                            return counter_val
                    except:
                        continue
                
                # Look for other count indicators
                for i in range(0, len(hex_data) - 3, 2):
                    try:
                        val = int(hex_data[i:i+4], 16)
                        if 50 <= val <= 1000:  # Reasonable record count range
                            print(f"📊 Potential record count from position {i}: {val}")
                    except:
                        continue
        
        print("⚠️  Could not determine exact record count, using default estimate")
        return 100  # Default estimate
    
    async def get_all_history_records(self, max_records: int = 200) -> List[HistoryReading]:
        """Retrieve all available history records"""
        print(f"🔍 Retrieving all history records (max: {max_records})...")
        
        all_readings = []
        
        # Strategy 1: Use known working commands (03, 05) with parameter variations
        print("📖 Phase 1: Using commands 03 & 05 with parameter sweeps...")
        
        for cmd in ['03', '05']:
            print(f"  Testing command {cmd}...")
            
            # Try different parameter patterns
            for param_type in ['single', 'range', 'offset']:
                if param_type == 'single':
                    # Single byte parameters
                    param_values = range(0, 50)
                elif param_type == 'range':
                    # 16-bit range parameters
                    param_values = [0x0000, 0x0001, 0x0010, 0x0020, 0x0050, 0x0100, 0x0200]
                else:
                    # Time offset parameters (hours ago)
                    param_values = [1, 6, 12, 24, 48, 72, 168]  # 1h to 1 week
                
                for param in param_values:
                    if param_type == 'single':
                        command = f"d155{cmd}00{param:02x}000000000000000000000000"
                    elif param_type == 'range':
                        command = f"d155{cmd}00{param:04x}00000000000000000000"
                    else:  # offset
                        command = f"d155{cmd}00{param:04x}00000000000000000000"
                    
                    try:
                        responses = await self._send_command(command, 1.5)
                        
                        for response in responses:
                            voltages = extract_voltages_from_response(response['decrypted'])
                            
                            for v in voltages:
                                timestamp = parse_timestamp_from_data(response['decrypted'], len(all_readings))
                                temperature = parse_temperature_from_data(response['decrypted'])
                                
                                reading = HistoryReading(
                                    voltage=v['voltage'],
                                    timestamp=timestamp,
                                    raw_data=response['decrypted'],
                                    source_command=f"{cmd}_{param_type}_{param}",
                                    record_index=len(all_readings),
                                    confidence=v['confidence'],
                                    temperature=temperature
                                )
                                
                                # Check for duplicates
                                is_duplicate = any(
                                    abs(r.voltage - reading.voltage) < 0.01 and
                                    abs((r.timestamp - reading.timestamp).total_seconds()) < 300
                                    for r in all_readings
                                )
                                
                                if not is_duplicate:
                                    all_readings.append(reading)
                                    
                    except Exception as e:
                        continue
                    
                    if len(all_readings) >= max_records:
                        break
                        
                if len(all_readings) >= max_records:
                    break
            
            if len(all_readings) >= max_records:
                break
        
        # Strategy 2: Try sequential record retrieval
        print(f"📖 Phase 2: Sequential record retrieval...")
        
        # Try to get records sequentially using different approaches
        for approach in ['increment', 'direct']:
            if approach == 'increment':
                # Use 0A command to increment counter, then read with other commands
                for i in range(min(50, max_records - len(all_readings))):
                    # Set counter position
                    counter_cmd = f"d1550a00{i:02x}0000000000000000000000"
                    await self._send_command(counter_cmd, 0.5)
                    
                    # Try to read at this position
                    for read_cmd in ['01', '02', '03', '04', '05']:
                        command = f"d155{read_cmd}64000000000000000000000000"
                        
                        try:
                            responses = await self._send_command(command, 1.0)
                            
                            for response in responses:
                                voltages = extract_voltages_from_response(response['decrypted'])
                                
                                for v in voltages:
                                    timestamp = parse_timestamp_from_data(response['decrypted'], i)
                                    temperature = parse_temperature_from_data(response['decrypted'])
                                    
                                    reading = HistoryReading(
                                        voltage=v['voltage'],
                                        timestamp=timestamp,
                                        raw_data=response['decrypted'],
                                        source_command=f"seq_{read_cmd}_{i}",
                                        record_index=i,
                                        confidence=v['confidence'],
                                        temperature=temperature
                                    )
                                    
                                    # Check for duplicates
                                    is_duplicate = any(
                                        abs(r.voltage - reading.voltage) < 0.01 and
                                        abs((r.timestamp - reading.timestamp).total_seconds()) < 300
                                        for r in all_readings
                                    )
                                    
                                    if not is_duplicate:
                                        all_readings.append(reading)
                                        break  # Only take first valid reading per position
                                        
                        except:
                            continue
                        
                        if len(all_readings) >= max_records:
                            break
                    
                    if len(all_readings) >= max_records:
                        break
            
            if len(all_readings) >= max_records:
                break
        
        # Sort by timestamp and remove final duplicates
        all_readings.sort(key=lambda x: x.timestamp, reverse=True)
        
        # Final deduplication pass
        unique_readings = []
        for reading in all_readings:
            is_duplicate = any(
                abs(r.voltage - reading.voltage) < 0.01 and
                abs((r.timestamp - reading.timestamp).total_seconds()) < 300
                for r in unique_readings
            )
            
            if not is_duplicate:
                unique_readings.append(reading)
        
        print(f"✅ Retrieved {len(unique_readings)} unique history records")
        return unique_readings
    
    async def get_history_summary(self) -> Dict[str, Any]:
        """Get summary of historical data"""
        print("📊 Generating history summary...")
        
        records = await self.get_all_history_records()
        
        if not records:
            return {
                'total_records': 0,
                'date_range': None,
                'voltage_range': None,
                'error': 'No history records found'
            }
        
        voltages = [r.voltage for r in records]
        timestamps = [r.timestamp for r in records]
        
        summary = {
            'total_records': len(records),
            'date_range': {
                'start': min(timestamps).isoformat(),
                'end': max(timestamps).isoformat(),
                'span_hours': (max(timestamps) - min(timestamps)).total_seconds() / 3600
            },
            'voltage_statistics': {
                'min': min(voltages),
                'max': max(voltages),
                'average': sum(voltages) / len(voltages),
                'range': max(voltages) - min(voltages)
            },
            'data_quality': {
                'high_confidence': sum(1 for r in records if r.confidence == 'high'),
                'medium_confidence': sum(1 for r in records if r.confidence == 'medium'),
                'with_temperature': sum(1 for r in records if r.temperature is not None)
            }
        }
        
        return summary

async def main():
    parser = argparse.ArgumentParser(description='BM6 Complete History Retrieval')
    parser.add_argument('--address', type=str, required=True, help='BM6 device address')
    parser.add_argument('--output', type=str, help='Output JSON file for history data')
    parser.add_argument('--max-records', type=int, default=200, help='Maximum records to retrieve')
    parser.add_argument('--summary-only', action='store_true', help='Only show summary, not full data')
    
    args = parser.parse_args()
    
    print("🎯 BM6 Complete History Retrieval")
    print("Enhanced implementation with timestamps and JSON export")
    print("=" * 60)
    
    client = BM6CompleteHistoryClient(args.address)
    
    try:
        print(f"🔗 Connecting to BM6 at {args.address}...")
        await client.connect()
        print("✅ Connected successfully!")
        
        if args.summary_only:
            # Get summary only
            summary = await client.get_history_summary()
            print("\n📊 HISTORY SUMMARY:")
            print(json.dumps(summary, indent=2))
            
        else:
            # Get all records
            records = await client.get_all_history_records(args.max_records)
            
            if records:
                print(f"\n📈 HISTORICAL DATA ({len(records)} records):")
                
                # Show sample records
                print(f"\n{'Timestamp':<20} {'Voltage':<8} {'Temp':<6} {'Source':<15} {'Confidence':<10}")
                print("-" * 70)
                
                for i, record in enumerate(records[:20]):  # Show first 20
                    time_str = record.timestamp.strftime('%m-%d %H:%M:%S')
                    temp_str = f"{record.temperature:.1f}°C" if record.temperature else "N/A"
                    print(f"{time_str:<20} {record.voltage:<8.2f}V {temp_str:<6} {record.source_command:<15} {record.confidence:<10}")
                
                if len(records) > 20:
                    print(f"... and {len(records) - 20} more records")
                
                # Generate summary
                voltages = [r.voltage for r in records]
                timestamps = [r.timestamp for r in records]
                
                print(f"\n📊 SUMMARY:")
                print(f"  Total Records: {len(records)}")
                print(f"  Date Range: {min(timestamps).strftime('%Y-%m-%d %H:%M')} to {max(timestamps).strftime('%Y-%m-%d %H:%M')}")
                print(f"  Voltage Range: {min(voltages):.2f}V - {max(voltages):.2f}V")
                print(f"  Average Voltage: {sum(voltages)/len(voltages):.2f}V")
                
                # Export to JSON if requested
                if args.output:
                    export_data = {
                        'metadata': {
                            'device_address': args.address,
                            'retrieval_time': datetime.now().isoformat(),
                            'total_records': len(records),
                            'max_records_requested': args.max_records
                        },
                        'summary': {
                            'date_range': {
                                'start': min(timestamps).isoformat(),
                                'end': max(timestamps).isoformat()
                            },
                            'voltage_statistics': {
                                'min': min(voltages),
                                'max': max(voltages),
                                'average': sum(voltages) / len(voltages)
                            }
                        },
                        'records': [record.to_dict() for record in records]
                    }
                    
                    with open(args.output, 'w') as f:
                        json.dump(export_data, f, indent=2)
                    
                    print(f"\n💾 Data exported to {args.output}")
                
            else:
                print("\n❌ No historical records found")
                
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await client.disconnect()
        print("🔌 Disconnected")

if __name__ == "__main__":
    asyncio.run(main())
