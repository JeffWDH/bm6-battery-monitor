#!/usr/bin/env python3

# BM6 Targeted History Commands - Based on Traffic Analysis
# Test specific command patterns that are likely used for complete history access

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

def analyze_response_for_history(hex_data):
    """Analyze response for historical data patterns"""
    analysis = {
        'voltages': [],
        'timestamps': [],
        'record_count': 0,
        'data_structure': 'unknown'
    }
    
    # Look for voltage patterns
    for i in range(0, len(hex_data) - 3, 2):
        try:
            val = int(hex_data[i:i+4], 16)
            if 600 <= val <= 2000:  # 6.0V to 20.0V
                voltage = val / 100.0
                analysis['voltages'].append({
                    'voltage': voltage,
                    'position': i,
                    'raw': hex_data[i:i+4]
                })
        except:
            continue
    
    # Look for timestamp patterns (32-bit unix timestamps)
    current_time = int(time.time())
    for i in range(0, len(hex_data) - 7, 2):
        try:
            # Try big-endian 32-bit timestamp
            ts_be = int(hex_data[i:i+8], 16)
            if 1600000000 <= ts_be <= current_time + 86400:
                analysis['timestamps'].append({
                    'timestamp': ts_be,
                    'datetime': datetime.fromtimestamp(ts_be),
                    'position': i,
                    'format': 'be32'
                })
            
            # Try little-endian 32-bit timestamp
            ts_le_hex = hex_data[i+6:i+8] + hex_data[i+4:i+6] + hex_data[i+2:i+4] + hex_data[i:i+2]
            ts_le = int(ts_le_hex, 16)
            if 1600000000 <= ts_le <= current_time + 86400:
                analysis['timestamps'].append({
                    'timestamp': ts_le,
                    'datetime': datetime.fromtimestamp(ts_le),
                    'position': i,
                    'format': 'le32'
                })
        except:
            continue
    
    # Estimate record structure
    if len(analysis['voltages']) > 1:
        analysis['record_count'] = len(analysis['voltages'])
        analysis['data_structure'] = 'multi_voltage'
    elif len(analysis['timestamps']) > 0:
        analysis['data_structure'] = 'timestamped'
    
    return analysis

class BM6TargetedHistoryClient:
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
            print(f"⚠️  Command failed: {e}")
            return []
    
    async def test_comprehensive_history_commands(self):
        """Test comprehensive set of history-related commands"""
        
        print("🔍 TESTING COMPREHENSIVE HISTORY COMMANDS")
        print("Based on BLE traffic analysis and known patterns")
        print("=" * 70)
        
        all_findings = []
        
        # Phase 1: Extended command range with focus on likely history commands
        print("\n📋 Phase 1: Extended History Command Range")
        
        # Based on common embedded protocols, these command ranges often handle history
        history_command_ranges = [
            (0x06, 0x10, "Core History Range"),      # 06-0F
            (0x10, 0x20, "Extended History Range"),  # 10-1F  
            (0x20, 0x30, "Advanced History Range"),  # 20-2F
            (0x80, 0x90, "High Commands"),           # 80-8F (often used for bulk data)
            (0xF0, 0x100, "System Commands")         # F0-FF (system/status commands)
        ]
        
        for start, end, description in history_command_ranges:
            print(f"\n  {description} ({start:02x}-{end-1:02x}):")
            
            for cmd in range(start, min(end, 256)):
                command = f"d155{cmd:02x}00000000000000000000000000"
                print(f"    Testing {cmd:02x}: ", end="")
                
                responses = await self.send_command(command, 2.0)
                
                if responses:
                    # Analyze for history content
                    total_voltages = 0
                    total_timestamps = 0
                    
                    for resp in responses:
                        analysis = analyze_response_for_history(resp['decrypted'])
                        total_voltages += len(analysis['voltages'])
                        total_timestamps += len(analysis['timestamps'])
                    
                    if total_voltages > 0 or total_timestamps > 0:
                        print(f"✅ {len(responses)} resp, V:{total_voltages}, T:{total_timestamps}")
                        all_findings.append({
                            'command': cmd,
                            'base_command': command,
                            'responses': len(responses),
                            'voltages': total_voltages,
                            'timestamps': total_timestamps,
                            'priority': 'high' if total_voltages > 2 or total_timestamps > 0 else 'medium'
                        })
                    else:
                        print(f"{len(responses)} resp")
                else:
                    print("No response")
                
                # Small delay to avoid overwhelming
                await asyncio.sleep(0.3)
        
        # Phase 2: Parameter-based history retrieval for promising commands
        print(f"\n📋 Phase 2: Parameter-Based History Retrieval")
        
        promising_commands = [f['command'] for f in all_findings if f['priority'] == 'high']
        if not promising_commands:
            promising_commands = [f['command'] for f in all_findings if f['voltages'] > 0]
        if not promising_commands:
            promising_commands = [0x03, 0x05, 0x06, 0x08, 0x10]  # Fallback to likely candidates
        
        for cmd in promising_commands[:5]:  # Test top 5 promising commands
            print(f"\n  Command {cmd:02x} parameter variations:")
            
            # Test different parameter strategies
            parameter_strategies = [
                # Record index patterns
                ("Record Index", [i for i in range(0, 100, 10)]),
                
                # Time-based patterns (minutes/hours ago)
                ("Time Offset (min)", [15*i for i in range(1, 20)]),  # Every 15 minutes for ~5 hours
                
                # Date-based patterns (days since reference)
                ("Date Offset", [i for i in range(1, 8)]),  # Last 7 days
                
                # Record count requests
                ("Record Count", [1, 5, 10, 20, 50, 100]),
                
                # Range requests (start, count)
                ("Range Request", [(0, 10), (10, 10), (20, 10), (0, 50), (50, 50)]),
            ]
            
            for strategy_name, param_values in parameter_strategies:
                print(f"    {strategy_name}:")
                
                best_responses = []
                
                for param in param_values:
                    if strategy_name == "Range Request":
                        start, count = param
                        command = f"d155{cmd:02x}00{start:02x}{count:02x}000000000000000000"
                        param_desc = f"{start},{count}"
                    else:
                        if isinstance(param, int) and param <= 0xFFFF:
                            command = f"d155{cmd:02x}00{param:04x}00000000000000000000"
                        else:
                            command = f"d155{cmd:02x}00{param:08x}000000000000000000"
                        param_desc = str(param)
                    
                    responses = await self.send_command(command, 2.0)
                    
                    if responses:
                        # Quick analysis
                        total_voltages = sum(len(analyze_response_for_history(r['decrypted'])['voltages']) for r in responses)
                        total_timestamps = sum(len(analyze_response_for_history(r['decrypted'])['timestamps']) for r in responses)
                        
                        if total_voltages > 0 or total_timestamps > 0:
                            print(f"      {param_desc}: ✅ {len(responses)} resp, V:{total_voltages}, T:{total_timestamps}")
                            best_responses.append({
                                'param': param_desc,
                                'command': command,
                                'responses': responses,
                                'voltages': total_voltages,
                                'timestamps': total_timestamps
                            })
                        elif len(responses) > 1:
                            print(f"      {param_desc}: {len(responses)} resp")
                    
                    await asyncio.sleep(0.5)
                
                # Show best responses for this strategy
                if best_responses:
                    best = max(best_responses, key=lambda x: x['voltages'] + x['timestamps'])
                    print(f"      Best: {best['param']} with {best['voltages']} voltages, {best['timestamps']} timestamps")
        
        # Phase 3: Sequential bulk data retrieval
        print(f"\n📋 Phase 3: Sequential Bulk Data Retrieval")
        
        # Test commands that might retrieve data in chunks
        bulk_commands = [
            # Different approaches to bulk data
            ("d15506", "Bulk Data Command 1"),
            ("d15508", "Bulk Data Command 2"), 
            ("d15510", "Bulk Data Command 3"),
            ("d15520", "Bulk Data Command 4"),
            ("d15580", "High Bulk Command 1"),
            ("d155f0", "System Bulk Command"),
            ("d155ff", "Max Command"),
        ]
        
        for cmd_prefix, description in bulk_commands:
            print(f"  {description}: ", end="")
            
            # Try with different chunk parameters
            best_result = None
            best_score = 0
            
            for chunk_size in [10, 20, 50, 100]:
                for start_idx in [0, 1]:
                    command = f"{cmd_prefix}{start_idx:02x}{chunk_size:02x}0000000000000000"
                    
                    responses = await self.send_command(command, 3.0)
                    
                    if responses:
                        total_voltages = sum(len(analyze_response_for_history(r['decrypted'])['voltages']) for r in responses)
                        total_timestamps = sum(len(analyze_response_for_history(r['decrypted'])['timestamps']) for r in responses)
                        
                        score = total_voltages * 2 + total_timestamps * 3 + len(responses)
                        
                        if score > best_score:
                            best_score = score
                            best_result = {
                                'responses': len(responses),
                                'voltages': total_voltages,
                                'timestamps': total_timestamps,
                                'command': command
                            }
            
            if best_result:
                print(f"✅ Best: {best_result['responses']} resp, V:{best_result['voltages']}, T:{best_result['timestamps']}")
                print(f"    Command: {best_result['command']}")
            else:
                print("No significant responses")
        
        return all_findings
    
    async def deep_analysis_of_best_commands(self, findings):
        """Perform deep analysis of the most promising commands"""
        
        if not findings:
            print("No promising commands found for deep analysis")
            return
        
        print(f"\n🔬 DEEP ANALYSIS OF BEST COMMANDS")
        print("=" * 70)
        
        # Sort by total data content
        sorted_findings = sorted(findings, key=lambda x: x['voltages'] + x['timestamps'], reverse=True)
        
        for finding in sorted_findings[:3]:  # Top 3 commands
            cmd = finding['command']
            print(f"\n📊 Deep analysis: Command {cmd:02x}")
            print(f"   Base performance: {finding['voltages']} voltages, {finding['timestamps']} timestamps")
            
            # Test systematic parameter progression
            print(f"   Testing parameter progression...")
            
            historical_data = []
            
            for i in range(0, 50, 5):  # Test every 5th parameter up to 50
                command = f"d155{cmd:02x}00{i:04x}00000000000000000000"
                
                responses = await self.send_command(command, 2.0)
                
                for resp in responses:
                    analysis = analyze_response_for_history(resp['decrypted'])
                    
                    for voltage_info in analysis['voltages']:
                        historical_data.append({
                            'parameter': i,
                            'voltage': voltage_info['voltage'],
                            'command': command,
                            'raw_response': resp['decrypted']
                        })
                    
                    for timestamp_info in analysis['timestamps']:
                        print(f"   📅 Parameter {i}: Timestamp {timestamp_info['datetime'].strftime('%Y-%m-%d %H:%M:%S')}")
                
                await asyncio.sleep(0.5)
            
            # Analyze the collected data
            if historical_data:
                print(f"   📊 Collected {len(historical_data)} historical voltage readings:")
                
                # Group by voltage to see patterns
                voltage_counts = {}
                for data in historical_data:
                    v = round(data['voltage'], 2)
                    if v not in voltage_counts:
                        voltage_counts[v] = []
                    voltage_counts[v].append(data['parameter'])
                
                for voltage, params in sorted(voltage_counts.items()):
                    print(f"     {voltage}V: parameters {params}")
                
                # Look for sequential patterns
                if len(historical_data) > 5:
                    print(f"   📈 Voltage progression analysis:")
                    sorted_data = sorted(historical_data, key=lambda x: x['parameter'])
                    
                    for i in range(min(10, len(sorted_data))):
                        data = sorted_data[i]
                        print(f"     Param {data['parameter']:2d}: {data['voltage']:6.2f}V")
                    
                    if len(sorted_data) > 10:
                        print(f"     ... and {len(sorted_data) - 10} more readings")

async def main():
    parser = argparse.ArgumentParser(description='BM6 Targeted History Command Testing')
    parser.add_argument('--address', type=str, required=True, help='BM6 device address')
    parser.add_argument('--output', type=str, help='Output JSON file for results')
    parser.add_argument('--quick', action='store_true', help='Quick test of most likely commands only')
    
    args = parser.parse_args()
    
    print("🎯 BM6 TARGETED HISTORY COMMAND TESTING")
    print("Based on BLE traffic analysis - searching for complete history access")
    print("=" * 80)
    
    if args.quick:
        print("🚀 QUICK MODE: Testing most likely history commands")
    else:
        print("🔍 COMPREHENSIVE MODE: Testing full command range")
    
    client = BM6TargetedHistoryClient(args.address)
    
    try:
        print(f"\n🔗 Connecting to BM6 at {args.address}...")
        await client.connect()
        print("✅ Connected!")
        
        if args.quick:
            # Quick test of most likely commands
            print("\n🚀 QUICK TEST: Most Likely History Commands")
            
            quick_commands = [
                # Most likely based on embedded systems patterns
                ("d1550600000000000000000000000000", "Command 06 - History List"),
                ("d1550800000000000000000000000000", "Command 08 - History Data"),
                ("d1551000000000000000000000000000", "Command 10 - Extended History"),
                ("d1552000000000000000000000000000", "Command 20 - Bulk History"),
                ("d1558000000000000000000000000000", "Command 80 - System History"),
                
                # Parameter variations of promising commands
                ("d1550600010000000000000000000000", "Command 06 with param 01"),
                ("d1550600100000000000000000000000", "Command 06 with param 10"),
                ("d1550800010000000000000000000000", "Command 08 with param 01"),
                ("d1550800100000000000000000000000", "Command 08 with param 10"),
                
                # Range-based requests
                ("d1550600006400000000000000000000", "Command 06 - request 100 records"),
                ("d1550800006400000000000000000000", "Command 08 - request 100 records"),
            ]
            
            findings = []
            
            for command, description in quick_commands:
                print(f"\n  {description}: ", end="")
                
                responses = await client.send_command(command, 3.0)
                
                if responses:
                    total_voltages = 0
                    total_timestamps = 0
                    
                    for resp in responses:
                        analysis = analyze_response_for_history(resp['decrypted'])
                        total_voltages += len(analysis['voltages'])
                        total_timestamps += len(analysis['timestamps'])
                        
                        # Show any timestamps found
                        for ts_info in analysis['timestamps']:
                            print(f"\n    📅 Timestamp: {ts_info['datetime'].strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    if total_voltages > 0 or total_timestamps > 0:
                        print(f"✅ {len(responses)} resp, V:{total_voltages}, T:{total_timestamps}")
                        findings.append({
                            'command': command,
                            'description': description,
                            'responses': len(responses),
                            'voltages': total_voltages,
                            'timestamps': total_timestamps
                        })
                        
                        # Show voltage details for promising results
                        if total_voltages > 2:
                            print(f"    Voltages found:")
                            for resp in responses:
                                analysis = analyze_response_for_history(resp['decrypted'])
                                for v_info in analysis['voltages']:
                                    print(f"      {v_info['voltage']:.2f}V at position {v_info['position']}")
                    else:
                        print(f"{len(responses)} resp")
                else:
                    print("No response")
        
        else:
            # Comprehensive test
            findings = await client.test_comprehensive_history_commands()
            await client.deep_analysis_of_best_commands(findings)
        
        # Summary and recommendations
        print(f"\n🎯 SUMMARY AND RECOMMENDATIONS")
        print("=" * 80)
        
        if findings:
            # Sort findings by potential
            sorted_findings = sorted(findings, key=lambda x: x.get('voltages', 0) + x.get('timestamps', 0), reverse=True)
            
            print(f"\n📊 TOP FINDINGS:")
            for i, finding in enumerate(sorted_findings[:5]):
                cmd = finding.get('command', 'unknown')
                if isinstance(cmd, int):
                    cmd_str = f"Command {cmd:02x}"
                else:
                    cmd_str = f"Command {cmd}"
                
                print(f"  {i+1}. {cmd_str}")
                print(f"     Responses: {finding.get('responses', 0)}")
                print(f"     Voltages: {finding.get('voltages', 0)}")
                print(f"     Timestamps: {finding.get('timestamps', 0)}")
                if 'description' in finding:
                    print(f"     Description: {finding['description']}")
            
            print(f"\n💡 NEXT STEPS:")
            best_finding = sorted_findings[0]
            if best_finding.get('voltages', 0) > 5 or best_finding.get('timestamps', 0) > 0:
                print(f"✅ SUCCESS! Found promising history command(s)")
                print(f"1. Focus on the top-ranked commands above")
                print(f"2. Test parameter variations around successful commands")
                print(f"3. Look for sequential patterns in the data")
                print(f"4. Implement proper parsing for the data format")
            else:
                print(f"⚠️  Limited success - need deeper investigation")
                print(f"1. Try capturing more detailed BLE traffic during app usage")
                print(f"2. Test the successful commands with more parameter variations")
                print(f"3. Consider that history might be stored in a different format")
        
        else:
            print(f"❌ No significant findings")
            print(f"Recommendations:")
            print(f"1. Verify the BM6 device actually has historical data stored")
            print(f"2. Try using the official app to confirm history is accessible")
            print(f"3. Capture more detailed BLE traffic during app history browsing")
        
        # Export results
        if args.output and findings:
            with open(args.output, 'w') as f:
                json.dump(findings, f, indent=2, default=str)
            print(f"\n💾 Results exported to {args.output}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
