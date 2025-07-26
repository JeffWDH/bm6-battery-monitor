#!/usr/bin/env python3

# BM6 History Test Script
# Test various BM2-style history commands on BM6 device
# Add this to the bm6-battery-monitor repository as test_history.py

import argparse
import json
import asyncio
from Crypto.Cipher import AES
from bleak import BleakClient
from bleak import BleakScanner

# BM6 encryption key (different from BM2)
BM6_KEY = bytearray([108, 101, 97, 103, 101, 110, 100, 255, 254, 48, 49, 48, 48, 48, 48, 57])

# BM2 encryption key for reference
BM2_KEY = bytearray([108, 101, 97, 103, 101, 110, 100, 255, 254, 49, 56, 56, 50, 52, 54, 54])

def decrypt_bm6(crypted):
    """Decrypt data using BM6 key"""
    cipher = AES.new(BM6_KEY, AES.MODE_CBC, 16 * b'\0')
    decrypted = cipher.decrypt(crypted).hex()
    return decrypted

def encrypt_bm6(plaintext):
    """Encrypt data using BM6 key"""
    cipher = AES.new(BM6_KEY, AES.MODE_CBC, 16 * b'\0')
    encrypted = cipher.encrypt(plaintext)
    return encrypted

def decrypt_bm2(crypted):
    """Decrypt data using BM2 key for comparison"""
    cipher = AES.new(BM2_KEY, AES.MODE_CBC, 16 * b'\0')
    decrypted = cipher.decrypt(crypted).hex()
    return decrypted

def encrypt_bm2(plaintext):
    """Encrypt data using BM2 key for comparison"""
    cipher = AES.new(BM2_KEY, AES.MODE_CBC, 16 * b'\0')
    encrypted = cipher.encrypt(plaintext)
    return encrypted

async def scan_bm6():
    """Scan for BM6 devices"""
    device_list = []
    scan = await BleakScanner.discover(return_adv=True, timeout=5)
    
    for device in scan.values():
        if device[0].name == "BM6":
            device_list.append([device[0].address, device[1].rssi])
    
    if device_list:
        print("Found BM6 devices:")
        for item in device_list:
            print(f"  {item[0]} (RSSI: {item[1]})")
    else:
        print("No BM6 devices found.")
    
    return device_list

async def test_history_commands(address):
    """Test various history-related commands on BM6"""
    
    # Test commands to try (based on BM2 reverse engineering patterns)
    test_commands = [
        # Standard voltage command (known to work)
        ("d1550700000000000000000000000000", "Standard voltage command (baseline)"),
        
        # Potential history commands based on BM2 patterns
        ("f5508164000000000000000000000000", "BM2-style history command 1"),
        ("f5507164000000000000000000000000", "BM2-style history command 2"), 
        ("f5500164000000000000000000000000", "BM2-style history command 3"),
        ("d1558164000000000000000000000000", "BM6-style history command 1"),
        ("d1557164000000000000000000000000", "BM6-style history command 2"),
        ("d1550164000000000000000000000000", "BM6-style history command 3"),
        
        # Try different command prefixes
        ("d2550700000000000000000000000000", "Alternative prefix d2"),
        ("d3550700000000000000000000000000", "Alternative prefix d3"),
        ("d1560700000000000000000000000000", "Alternative command d156"),
        ("d1570700000000000000000000000000", "Alternative command d157"),
        
        # Try history-specific patterns
        ("d1550800000000000000000000000000", "History variant 1"),
        ("d1550900000000000000000000000000", "History variant 2"),
        ("d1550a00000000000000000000000000", "History variant 3"),
        ("d1550b00000000000000000000000000", "History variant 4"),
    ]
    
    results = []
    
    async def notification_handler(sender, data):
        """Handle notifications from the device"""
        try:
            decrypted = decrypt_bm6(data)
            timestamp = asyncio.get_event_loop().time()
            
            # Also try BM2 decryption for comparison
            try:
                bm2_decrypted = decrypt_bm2(data)
                results.append({
                    'timestamp': timestamp,
                    'raw_data': data.hex(),
                    'bm6_decrypted': decrypted,
                    'bm2_decrypted': bm2_decrypted,
                    'data_length': len(data)
                })
            except:
                results.append({
                    'timestamp': timestamp,
                    'raw_data': data.hex(),
                    'bm6_decrypted': decrypted,
                    'bm2_decrypted': 'failed',
                    'data_length': len(data)
                })
                
            print(f"  Received: {data.hex()}")
            print(f"  BM6 decrypt: {decrypted}")
            
        except Exception as e:
            print(f"  Error decrypting: {e}")
    
    async with BleakClient(address, timeout=30) as client:
        print(f"Connected to BM6 at {address}")
        
        # Subscribe to notifications
        await client.start_notify("FFF4", notification_handler)
        print("Subscribed to notifications on FFF4")
        
        for command_hex, description in test_commands:
            print(f"\nTesting: {description}")
            print(f"Command: {command_hex}")
            
            try:
                # Clear previous results
                results.clear()
                
                # Send the encrypted command
                command_bytes = bytearray.fromhex(command_hex)
                encrypted_command = encrypt_bm6(command_bytes)
                
                print(f"Encrypted: {encrypted_command.hex()}")
                await client.write_gatt_char("FFF3", encrypted_command, response=True)
                
                # Wait for responses
                await asyncio.sleep(2)
                
                if results:
                    print(f"Results ({len(results)} responses):")
                    for i, result in enumerate(results):
                        print(f"  Response {i+1}:")
                        print(f"    Raw: {result['raw_data']}")
                        print(f"    BM6: {result['bm6_decrypted']}")
                        if result['bm2_decrypted'] != 'failed':
                            print(f"    BM2: {result['bm2_decrypted']}")
                        
                        # Try to parse as voltage/temp data
                        decrypted = result['bm6_decrypted']
                        if len(decrypted) >= 18 and decrypted.startswith('d15507'):
                            try:
                                voltage = int(decrypted[15:18], 16) / 100
                                temp_flag = decrypted[6:8]
                                if temp_flag == "01":
                                    temperature = -int(decrypted[8:10], 16)
                                else:
                                    temperature = int(decrypted[8:10], 16)
                                print(f"    Parsed: {voltage}V, {temperature}°C")
                            except:
                                print(f"    Parse failed")
                else:
                    print("  No responses received")
                    
            except Exception as e:
                print(f"  Command failed: {e}")
            
            print("-" * 50)
        
        await client.stop_notify("FFF4")

async def main():
    parser = argparse.ArgumentParser(description='Test BM6 history commands')
    parser.add_argument('--address', type=str, help='BM6 device address')
    parser.add_argument('--scan', action='store_true', help='Scan for BM6 devices')
    
    args = parser.parse_args()
    
    if args.scan:
        await scan_bm6()
    elif args.address:
        print("Testing history commands on BM6...")
        print("This script will try various commands that might retrieve history data.")
        print("Based on BM2 reverse engineering, looking for patterns...\n")
        
        await test_history_commands(args.address)
        
        print("\n" + "="*60)
        print("ANALYSIS NOTES:")
        print("- Look for responses that differ from standard voltage data")
        print("- History data might have different prefixes or lengths")
        print("- Multiple responses might indicate historical records")
        print("- Compare timestamps and patterns in the data")
        print("- If successful, you'll see longer or repeated data packets")
        print("="*60)
    else:
        print("Use --scan to find devices or --address <MAC> to test")

if __name__ == "__main__":
    asyncio.run(main())
