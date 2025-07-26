#!/usr/bin/env python3

# BM6 History Retrieval Test - Phase 3
# Focus on the 0A command which shows parameter processing
# Test systematic parameter ranges to find history data

import argparse
import asyncio
import time
import struct
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

def analyze_0a_response(response_hex):
    """Analyze 0A command responses for patterns"""
    if not response_hex.startswith('d1550a00'):
        return None
    
    # Extract the data portion after d1550a00
    data_part = response_hex[8:]  # Skip 'd1550a00'
    
    analysis = {
        'full_response': response_hex,
        'data_section': data_part,
        'potential_values': []
    }
    
    # Try to extract meaningful values from the data section
    try:
        # Parse as pairs of bytes
        for i in range(0, min(len(data_part), 16), 2):
            if i + 2 <= len(data_part):
                byte_val = int(data_part[i:i+2], 16)
                analysis['potential_values'].append(byte_val)
    except:
        pass
    
    return analysis

async def test_history_retrieval(address):
    """Systematically test the 0A command with various parameters"""
    
    history_responses = []
    
    async def notification_handler(sender, data):
        timestamp = time.time()
        decrypted = decrypt_bm6(data)
        
        if decrypted.startswith('d1550a00'):
            analysis = analyze_0a_response(decrypted)
            history_responses.append({
                'timestamp': timestamp,
                'raw': data.hex(),
                'decrypted': decrypted,
                'analysis': analysis
            })
            
            print(f"  📦 Response: {decrypted}")
            if analysis and analysis['potential_values']:
                print(f"     Values: {analysis['potential_values']}")

    async with BleakClient(address, timeout=30) as client:
        print(f"🔗 Connected to BM6 at {address}")
        await client.start_notify("FFF4", notification_handler)
        
        print("\n🧪 PHASE 1: Test parameter range 0-50")
        print("Looking for history record indices or counts...")
        
        for param in range(0, 51):
            history_responses.clear()
            
            # Build command: d1550a00 + param + zeros
            command = f"d1550a00{param:02x}0000000000000000000000"
            print(f"Testing param {param:02x}: ", end="")
            
            try:
                command_bytes = bytearray.fromhex(command)
                encrypted = encrypt_bm6(command_bytes)
                await client.write_gatt_char("FFF3", encrypted, response=True)
                await asyncio.sleep(1)
                
                if history_responses:
                    resp = history_responses[0]
                    analysis = resp['analysis']
                    if analysis and analysis['potential_values']:
                        non_zero_values = [v for v in analysis['potential_values'] if v != 0]
                        if non_zero_values:
                            print(f"Got values: {non_zero_values}")
                        else:
                            print("All zeros")
                    else:
                        print("No data")
                else:
                    print("No response")
                    
            except Exception as e:
                print(f"Error: {e}")
        
        print("\n🧪 PHASE 2: Test 16-bit parameters")
        print("Testing larger parameter values...")
        
        # Test some 16-bit values that might represent record counts or timestamps
        test_values = [
            0x0001, 0x0002, 0x0005, 0x000A, 0x0010, 0x0020, 0x0030,
            0x0064, 0x00FF, 0x0100, 0x0200, 0x03E8, 0x07D0, 0x1000,
            0x2000, 0x4000, 0x8000, 0xFFFF
        ]
        
        for value in test_values:
            history_responses.clear()
            
            # Try both little-endian and big-endian
            for endian in ['little', 'big']:
                if endian == 'little':
                    param_bytes = struct.pack('<H', value).hex()
                else:
                    param_bytes = struct.pack('>H', value).hex()
                
                command = f"d1550a00{param_bytes}00000000000000000000"
                print(f"Testing 0x{value:04x} ({endian}): ", end="")
                
                try:
                    command_bytes = bytearray.fromhex(command)
                    encrypted = encrypt_bm6(command_bytes)
                    await client.write_gatt_char("FFF3", encrypted, response=True)
                    await asyncio.sleep(1)
                    
                    if history_responses:
                        resp = history_responses[0]
                        analysis = resp['analysis']
                        if analysis and analysis['potential_values']:
                            non_zero_values = [v for v in analysis['potential_values'] if v != 0]
                            if non_zero_values:
                                print(f"Values: {non_zero_values}")
                            else:
                                print("Zeros")
                        else:
                            print("No data")
                    else:
                        print("No response")
                        
                except Exception as e:
                    print(f"Error: {e}")
        
        print("\n🧪 PHASE 3: Test timestamp-like parameters")
        print("Testing values that might represent time...")
        
        # Test recent timestamps (days/hours ago)
        now = int(time.time())
        for hours_ago in [1, 6, 12, 24, 48, 72, 168]:  # 1h to 1 week ago
            timestamp = now - (hours_ago * 3600)
            
            # Try different timestamp formats
            test_formats = [
                timestamp & 0xFFFF,           # Lower 16 bits
                (timestamp >> 16) & 0xFFFF,   # Upper 16 bits  
                timestamp & 0xFF,             # Single byte
                hours_ago,                    # Hours directly
            ]
            
            for fmt_value in test_formats:
                if fmt_value > 0xFFFF:
                    continue
                    
                history_responses.clear()
                param_bytes = struct.pack('>H', fmt_value).hex()
                command = f"d1550a00{param_bytes}00000000000000000000"
                
                print(f"Testing {hours_ago}h ago (0x{fmt_value:04x}): ", end="")
                
                try:
                    command_bytes = bytearray.fromhex(command)
                    encrypted = encrypt_bm6(command_bytes)
                    await client.write_gatt_char("FFF3", encrypted, response=True)
                    await asyncio.sleep(1)
                    
                    if history_responses:
                        resp = history_responses[0]
                        analysis = resp['analysis']
                        if analysis and analysis['potential_values']:
                            non_zero_values = [v for v in analysis['potential_values'] if v != 0]
                            if non_zero_values:
                                print(f"Values: {non_zero_values}")
                                # Check if this looks like voltage data
                                for val in non_zero_values:
                                    if 600 <= val <= 2000:  # Voltage range 6-20V * 100
                                        voltage = val / 100.0
                                        print(f"       -> Potential voltage: {voltage}V")
                            else:
                                print("Zeros")
                        else:
                            print("No data")
                    else:
                        print("No response")
                        
                except Exception as e:
                    print(f"Error: {e}")
        
        print("\n🧪 PHASE 4: Test multi-parameter commands")
        print("Testing commands with multiple parameters...")
        
        # Try combinations that might request multiple records
        multi_tests = [
            ("010100", "Start=1, Count=1"),
            ("010500", "Start=1, Count=5"), 
            ("000A00", "Start=0, Count=10"),
            ("001E00", "Start=0, Count=30"),
            ("000001", "Different pattern 1"),
            ("000002", "Different pattern 2"),
            ("010203", "Sequential bytes"),
            ("FF0001", "High start, count 1"),
        ]
        
        for params, description in multi_tests:
            history_responses.clear()
            command = f"d1550a00{params}000000000000000000"
            print(f"Testing {description}: ", end="")
            
            try:
                command_bytes = bytearray.fromhex(command)
                encrypted = encrypt_bm6(command_bytes)
                await client.write_gatt_char("FFF3", encrypted, response=True)
                await asyncio.sleep(2)  # Longer wait for multi-record responses
                
                if history_responses:
                    print(f"{len(history_responses)} responses")
                    for i, resp in enumerate(history_responses):
                        analysis = resp['analysis']
                        if analysis and analysis['potential_values']:
                            non_zero_values = [v for v in analysis['potential_values'] if v != 0]
                            if non_zero_values:
                                print(f"    {i+1}: {non_zero_values}")
                                # Look for voltage patterns
                                for val in non_zero_values:
                                    if 600 <= val <= 2000:
                                        voltage = val / 100.0
                                        print(f"         -> Voltage: {voltage}V")
                else:
                    print("No response")
                    
            except Exception as e:
                print(f"Error: {e}")
        
        await client.stop_notify("FFF4")
        
        print("\n" + "="*70)
        print("🎯 SUMMARY & RECOMMENDATIONS")
        print("="*70)
        print("\nIf any responses showed voltage-like values (6-20V range),")
        print("those are strong candidates for historical voltage data!")
        print("\nNext steps if promising results found:")
        print("1. Focus on parameter ranges that gave voltage-like values")
        print("2. Test sequential parameters around successful ones") 
        print("3. Try requesting larger record counts")
        print("4. Implement proper parsing of multi-record responses")

async def main():
    parser = argparse.ArgumentParser(description='BM6 History Retrieval Testing')
    parser.add_argument('--address', type=str, required=True, help='BM6 device address')
    
    args = parser.parse_args()
    
    print("🎯 BM6 History Retrieval Test - Phase 3")
    print("Systematic testing of command 0A parameter processing")
    print("Looking for actual historical voltage data...\n")
    
    await test_history_retrieval(args.address)

if __name__ == "__main__":
    asyncio.run(main())
