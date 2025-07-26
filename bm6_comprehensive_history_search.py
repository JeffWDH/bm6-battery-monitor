#!/usr/bin/env python3

# BM6 Comprehensive History Command Search
# Systematic search for complete history access commands
# Based on reverse engineering insights

import argparse
import asyncio
import time
import json
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from bleak import BleakClient

# BM6 encryption key
BM6_KEY = bytearray([108, 101, 97, 103, 101, 110, 100, 255, 254, 48, 49, 48, 48, 48, 48, 57])

def decrypt_bm6(crypted):
    cipher = AES.new(BM6_KEY, AES.MODE_CBC, 16 * b'\0')
    return cipher.decrypt(crypted).hex()

def encrypt_bm6(plaintext):
    cipher = AES.new(BM6_KEY, AES.MODE_CBC, 16 * b'\0')
    return cipher.encrypt(plaintext)

def analyze_for_timestamps(hex_data):
    """Look for timestamp patterns in the data"""
    timestamp_candidates = []
    current_time = int(time.time())
    
    # Look for various timestamp formats
    for i in range(0, len(hex_data) - 7, 2):
        try:
            # 32-bit timestamp (big endian)
            ts_be = int(hex_data[i:i+8], 16)
            if 1600000000 <= ts_be <= current_time + 86400:
                timestamp_candidates.append({
                    'position': i,
                    'value': ts_be,
                    'datetime': datetime.fromtimestamp(ts_be),
                    'format': '32bit_be'
                })
            
            # 32-bit timestamp (little endian)
            if i + 8 <= len(hex_data):
                ts_le_bytes = hex_data[i+6:i+8] + hex_data[i+4:i+6] + hex_data[i+2:i+4] + hex_data[i:i+2]
                ts_le = int(ts_le_bytes, 16)
                if 1600000000 <= ts_le <= current_time + 86400:
                    timestamp_candidates.append({
                        'position': i,
                        'value': ts_le,
                        'datetime': datetime.fromtimestamp(ts_le),
                        'format': '32bit_le'
                    })
        except:
            continue
    
    return timestamp_candidates

def analyze_for_record_structure(hex_data):
    """Analyze data for record structure patterns"""
    analysis = {
        'length': len(hex_data),
        'potential_record_count': 0,
        'voltage_count': 0,
        'timestamp_count': 0,
        'patterns': []
    }
    
    # Look for voltage patterns
    for i in range(0, len(hex_data) - 3, 2):
        try:
            val = int(hex_data[i:i+4], 16)
            if 600 <= val <= 2000:  # Voltage range
                analysis['voltage_count'] += 1
        except:
            continue
    
    # Look for timestamp patterns
    timestamps = analyze_for_timestamps(hex_data)
    analysis['timestamp_count'] = len(timestamps)
    
    # Look for repeating patterns
    if len(hex_data) >= 32:
        chunk_size = 16  # 8 bytes
        chunks = [hex_data[i:i+chunk_size] for i in range(0, len(hex_data) - chunk_size, chunk_size)]
        unique_chunks = len(set(chunks))
        if len(chunks) > unique_chunks:
            analysis['patterns'].append(f"Repeating {chunk_size//2}-byte patterns found")
    
    return analysis

class BM6HistorySearcher:
    def __init__(self, address):
        self.address = address
        self.client = None
        self.responses = []
        
    async def connect(self):
        self.client = BleakClient(self.address, timeout=30)
        await self.client.connect()
        await self.client.start_notify("FFF4", self._notification_handler)
        
    async def disconnect(self):
        if self.client and self.client.is_connected:
            await self.client.stop_notify("FFF4")
            await self.client.disconnect()
    
    async def _notification_handler(self, sender, data):
        timestamp = time.time()
        decrypted = decrypt_bm6(data)
        self.responses.append({
            'timestamp': timestamp,
            'raw': data.hex(),
            'decrypted': decrypted
        })
    
    async def send_command(self, command_hex, wait_time=3.0):
        self.responses.clear()
        try:
            command_bytes = bytearray.fromhex(command_hex)
            encrypted = encrypt_bm6(command_bytes)
            await self.client.write_gatt_char("FFF3", encrypted, response=True)
            await asyncio.sleep(wait_time)
            return self.responses.copy()
        except Exception as e:
            print(f"Command failed: {e}")
            return []
    
    async def search_history_commands(self):
        """Comprehensive search for history access commands"""
        
        print("🔍 COMPREHENSIVE HISTORY COMMAND SEARCH")
        print("=" * 60)
        
        findings = []
        
        # Test 1: Extended command range (beyond 03, 05)
        print("\n📋 Phase 1: Extended Command Range")
        
        for cmd in range(1, 32):  # Test commands 01-1F
            command = f"d155{cmd:02x}00000000000000000000000000"
            print(f"Testing command {cmd:02x}: ", end="")
            
            responses = await self.send_command(command, 2.0)
            
            if responses:
                total_responses = len(responses)
                unique_responses = len(set(r['decrypted'] for r in responses))
                
                # Analyze each response
                analysis_summary = []
                for resp in responses:
                    analysis = analyze_for_record_structure(resp['decrypted'])
                    if analysis['voltage_count'] > 0 or analysis['timestamp_count'] > 0:
                        analysis_summary.append(f"V:{analysis['voltage_count']},T:{analysis['timestamp_count']}")
                
                if analysis_summary:
                    print(f"✅ {total_responses} resp, {unique_responses} unique - {', '.join(analysis_summary)}")
                    findings.append({
                        'command': cmd,
                        'responses': total_responses,
                        'unique': unique_responses,
                        'analysis': analysis_summary
                    })
                else:
                    print(f"{total_responses} resp, {unique_responses} unique")
            else:
                print("No response")
        
        # Test 2: Parameter-based history requests
        print(f"\n📋 Phase 2: Parameter-Based History Requests")
        
        promising_commands = [cmd['command'] for cmd in findings if cmd['responses'] > 1]
        if not promising_commands:
            promising_commands = [3, 5]  # Fall back to known commands
        
        for cmd in promising_commands[:3]:  # Test top 3 promising commands
            print(f"\nTesting command {cmd:02x} with parameters:")
            
            # Test different parameter patterns
            parameter_tests = [
                # Record index/count patterns
                ("Record Index", [(i, f"{i:04x}0000000000000000000000") for i in range(0, 20, 5)]),
                
                # Time-based patterns (hours ago)
                ("Hours Ago", [(i, f"{i:04x}0000000000000000000000") for i in [1, 6, 12, 24, 48, 72]]),
                
                # Date patterns (days since epoch)
                ("Date Pattern", [(i, f"{i:08x}00000000000000000000") for i in [19000, 19001, 19002, 19003]]),  # Recent days
                
                # Range patterns (start, count)
                ("Range Pattern", [(f"{s},{c}", f"{s:02x}{c:02x}000000000000000000000000") for s in [0, 1, 10] for c in [1, 5, 10, 50]]),
            ]
            
            for test_name, params in parameter_tests:
                print(f"  {test_name}:")
                
                for param_desc, param_hex in params:
                    command = f"d155{cmd:02x}00{param_hex}"
                    responses = await self.send_command(command, 2.0)
                    
                    if responses:
                        # Quick analysis
                        voltage_total = 0
                        timestamp_total = 0
                        for resp in responses:
                            analysis = analyze_for_record_structure(resp['decrypted'])
                            voltage_total += analysis['voltage_count']
                            timestamp_total += analysis['timestamp_count']
                        
                        if voltage_total > 0 or timestamp_total > 0:
                            print(f"    {param_desc}: ✅ {len(responses)} resp, V:{voltage_total}, T:{timestamp_total}")
                        else:
                            print(f"    {param_desc}: {len(responses)} resp")
                    else:
                        print(f"    {param_desc}: No response")
        
        # Test 3: Multi-byte command variations
        print(f"\n📋 Phase 3: Multi-byte Command Variations")
        
        multi_byte_tests = [
            # History list commands
            ("d15506", "History List Variant 1"),
            ("d15507", "Standard Voltage (baseline)"),
            ("d15508", "History List Variant 2"),
            ("d15509", "History List Variant 3"),
            ("d1550a", "Counter Command (known)"),
            ("d1550b", "Next Counter Command"),
            ("d1550c", "History List Variant 4"),
            ("d1550d", "History List Variant 5"),
            ("d1550e", "History List Variant 6"),
            ("d1550f", "History List Variant 7"),
            
            # Extended history commands
            ("d15510", "Extended History 1"),
            ("d15520", "Extended History 2"),
            ("d15530", "Extended History 3"),
            ("d15540", "Extended History 4"),
            ("d15550", "Extended History 5"),
            
            # Different prefixes
            ("d15600", "Different Prefix 1"),
            ("d15700", "Different Prefix 2"),
            ("d15800", "Different Prefix 3"),
        ]
        
        for cmd_prefix, description in multi_byte_tests:
            command = f"{cmd_prefix}00000000000000000000000000"
            print(f"{description}: ", end="")
            
            responses = await self.send_command(command, 2.0)
            
            if responses:
                # Detailed analysis for promising responses
                total_analysis = {'voltage_count': 0, 'timestamp_count': 0, 'responses': len(responses)}
                
                for resp in responses:
                    analysis = analyze_for_record_structure(resp['decrypted'])
                    total_analysis['voltage_count'] += analysis['voltage_count']
                    total_analysis['timestamp_count'] += analysis['timestamp_count']
                    
                    # Check for timestamps
                    timestamps = analyze_for_timestamps(resp['decrypted'])
                    if timestamps:
                        print(f"\n  📅 Timestamps found: {[ts['datetime'].strftime('%Y-%m-%d %H:%M:%S') for ts in timestamps[:3]]}")
                
                if total_analysis['voltage_count'] > 0 or total_analysis['timestamp_count'] > 0:
                    print(f"✅ {total_analysis['responses']} resp, V:{total_analysis['voltage_count']}, T:{total_analysis['timestamp_count']}")
                else:
                    print(f"{total_analysis['responses']} resp")
            else:
                print("No response")
        
        return findings
    
    async def deep_dive_promising_commands(self, findings):
        """Deep dive into the most promising commands found"""
        
        if not findings:
            print("No promising commands found for deep dive")
            return
        
        print(f"\n🔬 DEEP DIVE: Most Promising Commands")
        print("=" * 60)
        
        # Sort by most responses and unique content
        sorted_findings = sorted(findings, key=lambda x: (x['responses'], x['unique']), reverse=True)
        
        for finding in sorted_findings[:3]:  # Top 3 commands
            cmd = finding['command']
            print(f"\n📊 Deep dive: Command {cmd:02x}")
            
            # Test with systematic parameters
            for base_param in [0x0000, 0x0001, 0x0010, 0x0100, 0x1000]:
                for offset in range(5):
                    param = base_param + offset
                    command = f"d155{cmd:02x}00{param:04x}00000000000000000000"
                    
                    responses = await self.send_command(command, 3.0)
                    
                    if responses:
                        print(f"  Param {param:04x}: {len(responses)} responses")
                        
                        for i, resp in enumerate(responses):
                            analysis = analyze_for_record_structure(resp['decrypted'])
                            timestamps = analyze_for_timestamps(resp['decrypted'])
                            
                            if timestamps:
                                print(f"    Response {i+1}: {timestamps[0]['datetime'].strftime('%Y-%m-%d %H:%M:%S')}")
                            elif analysis['voltage_count'] > 0:
                                print(f"    Response {i+1}: {analysis['voltage_count']} voltages")
                            
                            # Show first few bytes for pattern analysis
                            print(f"      Data: {resp['decrypted'][:32]}...")

async def main():
    parser = argparse.ArgumentParser(description='BM6 Comprehensive History Command Search')
    parser.add_argument('--address', type=str, required=True, help='BM6 device address')
    parser.add_argument('--output', type=str, help='Output file for results')
    
    args = parser.parse_args()
    
    searcher = BM6HistorySearcher(args.address)
    
    try:
        print("🔗 Connecting to BM6...")
        await searcher.connect()
        print("✅ Connected!")
        
        findings = await searcher.search_history_commands()
        
        if findings:
            await searcher.deep_dive_promising_commands(findings)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(findings, f, indent=2)
            print(f"\n💾 Results saved to {args.output}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await searcher.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
