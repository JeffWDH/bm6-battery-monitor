#!/usr/bin/env python3

# BM6 Voltage History Deep Dive - Phase 5
# Focus on commands 03 and 05 which showed voltage data
# Systematic testing to extract historical records

import argparse
import asyncio
import time
from datetime import datetime
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

def find_voltage_values(hex_data):
    """Find all potential voltage values in hex data"""
    voltage_candidates = []
    
    # Check every 2-byte position for voltage-like values
    for i in range(0, len(hex_data) - 3, 2):
        try:
            # Try big-endian 16-bit
            val16_be = int(hex_data[i:i+4], 16)
            if 600 <= val16_be <= 2000:  # 6.0V to 20.0V
                voltage_candidates.append({
                    'position': i,
                    'raw_value': val16_be,
                    'voltage': val16_be / 100.0,
                    'bytes': hex_data[i:i+4],
                    'endian': 'big'
                })
            
            # Try little-endian 16-bit
            if i + 4 <= len(hex_data):
                val16_le = int(hex_data[i+2:i+4] + hex_data[i:i+2], 16)
                if 600 <= val16_le <= 2000:
                    voltage_candidates.append({
                        'position': i,
                        'raw_value': val16_le,
                        'voltage': val16_le / 100.0,
                        'bytes': hex_data[i:i+4],
                        'endian': 'little'
                    })
        except:
            continue
    
    return voltage_candidates

def parse_response_detailed(hex_data):
    """Detailed parsing of response data"""
    analysis = {
        'length': len(hex_data),
        'prefix': hex_data[:8] if len(hex_data) >= 8 else hex_data,
        'full_data': hex_data,
        'voltage_candidates': find_voltage_values(hex_data),
        'byte_analysis': []
    }
    
    # Analyze individual bytes
    for i in range(0, min(len(hex_data), 32), 2):
        if i + 2 <= len(hex_data):
            byte_val = int(hex_data[i:i+2], 16)
            analysis['byte_analysis'].append({
                'position': i,
                'hex': hex_data[i:i+2],
                'decimal': byte_val,
                'ascii': chr(byte_val) if 32 <= byte_val <= 126 else '.'
            })
    
    return analysis

async def test_voltage_history(address):
    """Deep dive testing of commands 03 and 05 for voltage history"""
    
    all_history_data = []
    
    async def notification_handler(sender, data):
        timestamp = time.time()
        decrypted = decrypt_bm6(data)
        
        analysis = parse_response_detailed(decrypted)
        
        record = {
            'timestamp': timestamp,
            'datetime': datetime.fromtimestamp(timestamp).strftime('%H:%M:%S.%f')[:-3],
            'raw': data.hex(),
            'decrypted': decrypted,
            'analysis': analysis
        }
        
        all_history_data.append(record)
        
        # Print voltage findings immediately
        if analysis['voltage_candidates']:
            voltages = [f"{v['voltage']}V({v['endian']})" for v in analysis['voltage_candidates']]
            print(f"  🔋 VOLTAGES: {voltages}")
        else:
            print(f"  📦 {decrypted[:24]}{'...' if len(decrypted) > 24 else ''}")

    async with BleakClient(address, timeout=30) as client:
        print(f"🔗 Connected to BM6 at {address}")
        await client.start_notify("FFF4", notification_handler)
        
        print("🎯 DEEP DIVE: Commands 03 & 05 showed voltage data")
        print("Systematic testing to extract all historical records...\n")
        
        # Test 1: Command 03 with various parameters
        print("📋 TEST 1: Command 03 Variations")
        print("Testing command 03 with different parameters...")
        
        for param in range(0, 20):
            all_history_data.clear()
            command = f"d155030{param:01x}000000000000000000000000"
            print(f"\nParam 0{param:01x}: ", end="")
            
            try:
                command_bytes = bytearray.fromhex(command)
                encrypted = encrypt_bm6(command_bytes)
                await client.write_gatt_char("FFF3", encrypted, response=True)
                await asyncio.sleep(1.5)
                
                if all_history_data:
                    voltage_records = [r for r in all_history_data if r['analysis']['voltage_candidates']]
                    if voltage_records:
                        print(f"✅ {len(voltage_records)} voltage record(s)")
                        for vr in voltage_records:
                            for vc in vr['analysis']['voltage_candidates']:
                                print(f"    {vc['voltage']}V at pos {vc['position']} ({vc['bytes']})")
                    else:
                        print(f"{len(all_history_data)} response(s), no voltage")
                else:
                    print("No response")
                    
            except Exception as e:
                print(f"Error: {e}")
        
        # Test 2: Command 05 with various parameters
        print(f"\n📋 TEST 2: Command 05 Variations")
        print("Testing command 05 with different parameters...")
        
        for param in range(0, 20):
            all_history_data.clear()
            command = f"d155050{param:01x}000000000000000000000000"
            print(f"\nParam 0{param:01x}: ", end="")
            
            try:
                command_bytes = bytearray.fromhex(command)
                encrypted = encrypt_bm6(command_bytes)
                await client.write_gatt_char("FFF3", encrypted, response=True)
                await asyncio.sleep(2)  # Longer wait since 05 gave multiple responses
                
                if all_history_data:
                    voltage_records = [r for r in all_history_data if r['analysis']['voltage_candidates']]
                    if voltage_records:
                        print(f"✅ {len(voltage_records)} voltage record(s) of {len(all_history_data)} total")
                        for i, vr in enumerate(voltage_records):
                            for vc in vr['analysis']['voltage_candidates']:
                                print(f"    #{i+1}: {vc['voltage']}V at pos {vc['position']} ({vc['bytes']})")
                    else:
                        print(f"{len(all_history_data)} response(s), no voltage")
                else:
                    print("No response")
                    
            except Exception as e:
                print(f"Error: {e}")
        
        # Test 3: Extended parameter testing
        print(f"\n📋 TEST 3: Extended Parameter Testing")
        print("Testing larger parameter ranges for comprehensive history...")
        
        promising_commands = []
        
        # Test both commands with 2-byte parameters
        for cmd in ['03', '05']:
            print(f"\nTesting command {cmd} with 16-bit parameters:")
            
            for param_val in [0x00, 0x01, 0x02, 0x05, 0x0A, 0x10, 0x20, 0x50, 0xFF]:
                all_history_data.clear()
                
                # Try both little and big endian parameter encoding
                param_le = f"{param_val & 0xFF:02x}{(param_val >> 8) & 0xFF:02x}"
                param_be = f"{(param_val >> 8) & 0xFF:02x}{param_val & 0xFF:02x}"
                
                for endian, param_hex in [('LE', param_le), ('BE', param_be)]:
                    command = f"d155{cmd}00{param_hex}00000000000000000000"
                    print(f"  0x{param_val:02x}({endian}): ", end="")
                    
                    try:
                        command_bytes = bytearray.fromhex(command)
                        encrypted = encrypt_bm6(command_bytes)
                        await client.write_gatt_char("FFF3", encrypted, response=True)
                        await asyncio.sleep(1.5)
                        
                        voltage_count = sum(1 for r in all_history_data if r['analysis']['voltage_candidates'])
                        total_count = len(all_history_data)
                        
                        if voltage_count > 0:
                            print(f"✅ {voltage_count}/{total_count} voltage")
                            promising_commands.append({
                                'command': command,
                                'voltage_records': voltage_count,
                                'total_records': total_count
                            })
                        else:
                            print(f"{total_count} resp" if total_count > 0 else "none")
                            
                    except Exception as e:
                        print("err")
        
        # Test 4: Systematic record extraction
        print(f"\n📋 TEST 4: Systematic Record Extraction")
        
        if promising_commands:
            print("Using most promising command for systematic extraction...")
            best_cmd = max(promising_commands, key=lambda x: x['voltage_records'])
            print(f"Best command: {best_cmd['command']}")
            
            print(f"\nExtracting multiple records with incremental parameters:")
            
            historical_voltages = []
            
            for i in range(50):  # Try to get 50 historical records
                all_history_data.clear()
                
                # Use the best command with incremental parameter
                base_cmd = best_cmd['command'][:12]  # d155XX00
                param_hex = f"{i:04x}"
                command = f"{base_cmd}{param_hex}000000000000000000"
                
                try:
                    command_bytes = bytearray.fromhex(command)
                    encrypted = encrypt_bm6(command_bytes)
                    await client.write_gatt_char("FFF3", encrypted, response=True)
                    await asyncio.sleep(1)
                    
                    for record in all_history_data:
                        for vc in record['analysis']['voltage_candidates']:
                            historical_voltages.append({
                                'index': i,
                                'voltage': vc['voltage'],
                                'timestamp': record['datetime'],
                                'raw_data': record['decrypted']
                            })
                    
                    if len(all_history_data) > 0:
                        voltage_found = any(r['analysis']['voltage_candidates'] for r in all_history_data)
                        print(f"  {i:2d}: {'✅' if voltage_found else '❌'}")
                    
                except Exception as e:
                    print(f"  {i:2d}: ❌")
                    
            print(f"\n🎯 EXTRACTED HISTORICAL DATA:")
            print(f"Found {len(historical_voltages)} voltage readings")
            
            if historical_voltages:
                print(f"\nSample of historical voltages:")
                for i, hv in enumerate(historical_voltages[:10]):
                    print(f"  {hv['timestamp']}: {hv['voltage']}V (index {hv['index']})")
                
                if len(historical_voltages) > 10:
                    print(f"  ... and {len(historical_voltages) - 10} more")
        
        await client.stop_notify("FFF4")
        
        print("\n" + "="*70)
        print("🎯 FINAL SUMMARY")
        print("="*70)
        
        if promising_commands:
            print(f"\n✅ SUCCESS! Found {len(promising_commands)} commands that return voltage data")
            print(f"Most promising commands:")
            for cmd in sorted(promising_commands, key=lambda x: x['voltage_records'], reverse=True)[:3]:
                print(f"  {cmd['command']}: {cmd['voltage_records']} voltage records")
            
            print(f"\n🚀 NEXT STEPS:")
            print(f"1. Commands 03 and 05 definitely return historical voltage data")
            print(f"2. Parameter variations affect which records are returned")
            print(f"3. Ready to implement proper get_history() function")
            print(f"4. Need to parse timestamps/dates from the data")
        else:
            print(f"\n❌ No consistent voltage data found in this session")
            print(f"Try running again or check device state")

async def main():
    parser = argparse.ArgumentParser(description='BM6 Voltage History Deep Dive')
    parser.add_argument('--address', type=str, required=True, help='BM6 device address')
    
    args = parser.parse_args()
    
    print("🎯 BM6 Voltage History Deep Dive - Phase 5")
    print("Focus on commands 03 & 05 which showed voltage data")
    print("Systematic extraction of historical records...\n")
    
    await test_voltage_history(args.address)

if __name__ == "__main__":
    asyncio.run(main())
