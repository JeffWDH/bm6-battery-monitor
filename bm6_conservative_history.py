#!/usr/bin/env python3

# BM6 Conservative History Retrieval - Stable Version
# Focuses on proven working commands 03 and 05 with proper connection handling

import argparse
import asyncio
import time
import json
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
        except:
            continue
    
    # Remove duplicates and return unique voltages
    unique_voltages = []
    seen_voltages = set()
    
    for v in voltages:
        voltage_rounded = round(v['voltage'], 2)
        if voltage_rounded not in seen_voltages:
            seen_voltages.add(voltage_rounded)
            unique_voltages.append(v)
    
    return unique_voltages

class BM6ConservativeHistoryClient:
    """Conservative BM6 client focusing on proven commands"""
    
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
    
    async def _send_command_safe(self, command_hex: str, wait_time: float = 3.0) -> List[dict]:
        """Send command safely with error handling"""
        self.responses.clear()
        
        try:
            command_bytes = bytearray.fromhex(command_hex)
            encrypted = encrypt_bm6(command_bytes)
            
            await self.client.write_gatt_char("FFF3", encrypted, response=True)
            await asyncio.sleep(wait_time)
            
            return self.responses.copy()
            
        except Exception as e:
            print(f"⚠️  Command {command_hex[:12]}... failed: {e}")
            return []
    
    async def get_current_data(self) -> dict:
        """Get current voltage, temperature, and SoC"""
        print("📊 Getting current battery data...")
        command = "d1550700000000000000000000000000"
        responses = await self._send_command_safe(command, 2.0)
        
        for response in responses:
            decrypted = response['decrypted']
            if decrypted.startswith('d15507') and len(decrypted) >= 18:
                try:
                    voltage = int(decrypted[15:18], 16) / 100.0
                    temp_flag = decrypted[6:8]
                    temperature = -int(decrypted[8:10], 16) if temp_flag == "01" else int(decrypted[8:10], 16)
                    soc = int(decrypted[12:14], 16)
                    
                    return {
                        'voltage': voltage,
                        'temperature': temperature,
                        'soc': soc,
                        'timestamp': datetime.fromtimestamp(response['timestamp'])
                    }
                except:
                    continue
        
        return None
    
    async def get_history_records(self) -> List[HistoryReading]:
        """Get historical records using proven commands"""
        print("📖 Retrieving historical records...")
        
        all_readings = []
        current_time = datetime.now()
        
        # Command 03: Known to return 10.23V and 8.53V
        print("  📊 Command 03 (recent history)...")
        cmd03_responses = await self._send_command_safe("d1550300000000000000000000000000", 3.0)
        
        for response in cmd03_responses:
            voltages = extract_voltages_from_response(response['decrypted'])
            
            for i, v in enumerate(voltages):
                # Estimate timestamps (most recent first)
                estimated_time = current_time - timedelta(hours=i+1)
                
                reading = HistoryReading(
                    voltage=v['voltage'],
                    timestamp=estimated_time,
                    raw_data=response['decrypted'],
                    source_command='03',
                    record_index=len(all_readings),
                    confidence=v['confidence']
                )
                all_readings.append(reading)
                print(f"    Found: {v['voltage']}V (confidence: {v['confidence']})")
        
        # Wait between commands to avoid overwhelming the connection
        await asyncio.sleep(2.0)
        
        # Command 05: Known to return 12.8V and 13.65V with multiple responses
        print("  📊 Command 05 (extended history)...")
        cmd05_responses = await self._send_command_safe("d1550500000000000000000000000000", 4.0)
        
        for response in cmd05_responses:
            voltages = extract_voltages_from_response(response['decrypted'])
            
            for i, v in enumerate(voltages):
                # Estimate timestamps (older records)
                estimated_time = current_time - timedelta(hours=(len(all_readings) + i + 1))
                
                reading = HistoryReading(
                    voltage=v['voltage'],
                    timestamp=estimated_time,
                    raw_data=response['decrypted'],
                    source_command='05',
                    record_index=len(all_readings),
                    confidence=v['confidence']
                )
                all_readings.append(reading)
                print(f"    Found: {v['voltage']}V (confidence: {v['confidence']})")
        
        # Try a few parameter variations of command 03 (conservative approach)
        print("  📊 Command 03 variations...")
        for param in [0x01, 0x02, 0x05]:
            await asyncio.sleep(3.0)  # Longer wait between commands
            
            command = f"d155030{param:01x}000000000000000000000000"
            responses = await self._send_command_safe(command, 3.0)
            
            if responses:  # Only process if we got responses
                for response in responses:
                    voltages = extract_voltages_from_response(response['decrypted'])
                    
                    for i, v in enumerate(voltages):
                        # Check if this is a new voltage value
                        is_new = not any(abs(r.voltage - v['voltage']) < 0.01 for r in all_readings)
                        
                        if is_new:
                            estimated_time = current_time - timedelta(hours=(len(all_readings) + i + 1))
                            
                            reading = HistoryReading(
                                voltage=v['voltage'],
                                timestamp=estimated_time,
                                raw_data=response['decrypted'],
                                source_command=f'03_param_{param:02x}',
                                record_index=len(all_readings),
                                confidence=v['confidence']
                            )
                            all_readings.append(reading)
                            print(f"    New voltage: {v['voltage']}V (param {param:02x})")
            else:
                print(f"    No response for parameter {param:02x}")
                # Try to reconnect the service discovery if needed
                try:
                    await self.client.get_services()
                except:
                    pass
        
        # Sort by timestamp (newest first) and remove duplicates
        all_readings.sort(key=lambda x: x.timestamp, reverse=True)
        
        # Final deduplication
        unique_readings = []
        for reading in all_readings:
            is_duplicate = any(
                abs(r.voltage - reading.voltage) < 0.01 and
                abs((r.timestamp - reading.timestamp).total_seconds()) < 1800  # 30 minutes
                for r in unique_readings
            )
            
            if not is_duplicate:
                unique_readings.append(reading)
        
        print(f"✅ Retrieved {len(unique_readings)} unique historical readings")
        return unique_readings
    
    async def get_history_summary(self) -> Dict[str, Any]:
        """Get summary of historical data"""
        print("📊 Generating history summary...")
        
        current_data = await self.get_current_data()
        records = await self.get_history_records()
        
        if not records:
            return {
                'total_records': 0,
                'current_data': current_data,
                'error': 'No history records found'
            }
        
        voltages = [r.voltage for r in records]
        timestamps = [r.timestamp for r in records]
        
        summary = {
            'total_records': len(records),
            'current_data': {
                'voltage': current_data['voltage'],
                'temperature': current_data['temperature'],
                'soc': current_data['soc'],
                'timestamp': current_data['timestamp'].isoformat() if hasattr(current_data['timestamp'], 'isoformat') else str(current_data['timestamp'])
            } if current_data else None,
            'date_range': {
                'start': min(timestamps).isoformat(),
                'end': max(timestamps).isoformat(),
                'span_hours': (max(timestamps) - min(timestamps)).total_seconds() / 3600
            },
            'voltage_statistics': {
                'min': min(voltages),
                'max': max(voltages),
                'average': sum(voltages) / len(voltages),
                'range': max(voltages) - min(voltages),
                'current_vs_avg_diff': abs(current_data['voltage'] - sum(voltages) / len(voltages)) if current_data else None
            },
            'data_quality': {
                'high_confidence': sum(1 for r in records if r.confidence == 'high'),
                'medium_confidence': sum(1 for r in records if r.confidence == 'medium'),
                'command_03_records': sum(1 for r in records if r.source_command.startswith('03')),
                'command_05_records': sum(1 for r in records if r.source_command.startswith('05'))
            }
        }
        
        return summary

async def main():
    parser = argparse.ArgumentParser(description='BM6 Conservative History Retrieval')
    parser.add_argument('--address', type=str, required=True, help='BM6 device address')
    parser.add_argument('--output', type=str, help='Output JSON file for history data')
    parser.add_argument('--summary-only', action='store_true', help='Only show summary, not full data')
    
    args = parser.parse_args()
    
    print("🎯 BM6 Conservative History Retrieval")
    print("Stable implementation focusing on proven commands 03 & 05")
    print("=" * 60)
    
    client = BM6ConservativeHistoryClient(args.address)
    
    try:
        print(f"🔗 Connecting to BM6 at {args.address}...")
        await client.connect()
        print("✅ Connected successfully!")
        
        if args.summary_only:
            # Get summary only
            summary = await client.get_history_summary()
            
            # Convert datetime objects to strings for JSON serialization
            if summary.get('current_data') and summary['current_data'].get('timestamp'):
                if hasattr(summary['current_data']['timestamp'], 'isoformat'):
                    summary['current_data']['timestamp'] = summary['current_data']['timestamp'].isoformat()
            
            print("\n📊 HISTORY SUMMARY:")
            print(json.dumps(summary, indent=2))
            
        else:
            # Get current data first
            current = await client.get_current_data()
            if current:
                print(f"\n📊 CURRENT BATTERY STATUS:")
                print(f"  Voltage: {current['voltage']}V")
                print(f"  Temperature: {current['temperature']}°C")
                print(f"  State of Charge: {current['soc']}%")
                print(f"  Reading Time: {current['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Get historical records
            records = await client.get_history_records()
            
            if records:
                print(f"\n📈 HISTORICAL VOLTAGE DATA:")
                print(f"Found {len(records)} historical readings:")
                print(f"{'Time':<20} {'Voltage':<8} {'Source':<15} {'Confidence':<10}")
                print(f"{'-'*20} {'-'*8} {'-'*15} {'-'*10}")
                
                for reading in records:
                    time_str = reading.timestamp.strftime('%m-%d %H:%M:%S')
                    print(f"{time_str:<20} {reading.voltage:<8.2f}V {reading.source_command:<15} {reading.confidence:<10}")
                
                # Analysis
                voltages = [r.voltage for r in records]
                timestamps = [r.timestamp for r in records]
                
                print(f"\n📊 ANALYSIS:")
                print(f"  Total Records: {len(records)}")
                print(f"  Date Range: {min(timestamps).strftime('%Y-%m-%d %H:%M')} to {max(timestamps).strftime('%Y-%m-%d %H:%M')}")
                print(f"  Voltage Range: {min(voltages):.2f}V - {max(voltages):.2f}V")
                print(f"  Average Voltage: {sum(voltages)/len(voltages):.2f}V")
                
                if current:
                    avg_voltage = sum(voltages) / len(voltages)
                    print(f"  Current vs Average: {current['voltage']:.2f}V vs {avg_voltage:.2f}V ({current['voltage'] - avg_voltage:+.2f}V)")
                
                # Show voltage distribution
                cmd03_voltages = [r.voltage for r in records if r.source_command.startswith('03')]
                cmd05_voltages = [r.voltage for r in records if r.source_command.startswith('05')]
                
                if cmd03_voltages:
                    print(f"  Command 03 voltages: {', '.join(f'{v:.2f}V' for v in sorted(set(cmd03_voltages)))}")
                if cmd05_voltages:
                    print(f"  Command 05 voltages: {', '.join(f'{v:.2f}V' for v in sorted(set(cmd05_voltages)))}")
                
                # Export to JSON if requested
                if args.output:
                    export_data = {
                        'metadata': {
                            'device_address': args.address,
                            'retrieval_time': datetime.now().isoformat(),
                            'total_records': len(records),
                            'retrieval_method': 'conservative'
                        },
                        'current_data': current,
                        'summary': {
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
                            'command_breakdown': {
                                'command_03_count': len(cmd03_voltages),
                                'command_05_count': len(cmd05_voltages),
                                'command_03_voltages': sorted(set(cmd03_voltages)),
                                'command_05_voltages': sorted(set(cmd05_voltages))
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
