#!/usr/bin/env python3

# BM6 Focused History Test - Phase 2
# Based on promising results from initial testing
# Focus on the commands that showed anomalous responses

import argparse
import json
import asyncio
import time
from Crypto.Cipher import AES
from bleak import BleakClient
from bleak import BleakScanner

# BM6 encryption key
BM6_KEY = bytearray([108, 101, 97, 103, 101, 110, 100, 255, 254, 48, 49, 48, 48, 48, 48, 57])

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

def analyze_response(decrypted_hex):
    """Analyze decrypted response for patterns"""
    analysis = {
        'is_standard_voltage': False,
        'is_potential_history': False,
        'prefix': decrypted_hex[:6] if len(decrypted_hex) >= 6 else '',
        'full_data': decrypted_hex,
        'parsed_data': {}
    }
    
    # Check if it's standard voltage data
    if decrypted_hex.startswith('d15507') and len(decrypted_hex) >= 18:
        analysis['is_standard_voltage'] = True
        try:
            voltage = int(decrypted_hex[15:18], 16) / 100
            temp_flag = decrypted_hex[6:8]
            if temp_flag == "01":
                temperature = -int(decrypted_hex[8:10], 16)
            else:
                temperature = int(decrypted_hex[8:10], 16)
            analysis['parsed_data'] = {
                'voltage': voltage,
                'temperature': temperature,
                'soc': int(decrypted_hex[12:14], 16) if len(decrypted_hex) >= 14 else None
            }
        except:
            pass
    
    # Check for potential history data patterns
    elif decrypted_hex.startswith('d155') and not decrypted_hex.startswith('d15507'):
        analysis['is_potential_history'] = True
        # Try to parse command structure
        if len(decrypted_hex) >= 8:
            analysis['parsed_data'] = {
                'command_type': decrypted_hex[4:6],
                'sub_command': decrypted_hex[6:8],
                'data_section': decrypted_hex[8:] if len(decrypted_hex) > 8 else ''
            }
    
    return analysis

async def test_focused_history_commands(address):
    """Test the most promising commands with variations and longer waits"""
    
    # Commands that showed promise, plus variations
    focused_commands = [
        # The three commands that gave interesting results
        ("d1550164000000000000000000000000", "Promising command 1 (gave unique response)"),
        ("d1550900000000000000000000000000", "Promising command 2 (echo response)"),
        ("d1550a00000000000000000000000000", "Promising command 3 (modified response)"),
        
        # Variations of the promising commands with different parameters
        ("d1550164010000000000000000000000", "Command 1 with param 01"),
        ("d1550164020000000000000000000000", "Command 1 with param 02"),
        ("d1550164ff0000000000000000000000", "Command 1 with param ff"),
        
        ("d1550900010000000000000000000000", "Command 2 with param 01"),
        ("d1550900020000000000000000000000", "Command 2 with param 02"),
        ("d1550900ff0000000000000000000000", "Command 2 with param ff"),
        
        ("d1550a00010000000000000000000000", "Command 3 with param 01"),
        ("d1550a00020000000000000000000000", "Command 3 with param 02"),
        ("d1550a00ff0000000000000000000000", "Command 3 with param ff"),
        
        # Try sequential commands that might be history-related
        ("d1550c00000000000000000000000000", "Next in sequence (0c)"),
        ("d1550d00000000000000000000000000", "Next in sequence (0d)"),
        ("d1550e00000000000000000000000000", "Next in sequence (0e)"),
        ("d1550f00000000000000000000000000", "Next in sequence (0f)"),
        
        # Try different command types with the 01 pattern
        ("d1550101000000000000000000000000", "Command type 01 variant 1"),
        ("d1550102000000000000000000000000", "Command type 01 variant 2"),
        ("d1550103000000000000000000000000", "Command type 01 variant 3"),
        
        # Test if it's a read/write pattern
        ("d1550264000000000000000000000000", "Read variant of command 1"),
        ("d1550364000000000000000000000000", "Write variant of command 1"),
    ]
    
    all_responses = []
    
    async def notification_handler(sender, data):
        """Enhanced notification handler"""
        try:
            timestamp = time.time()
            decrypted = decrypt_bm6(data)
            analysis = analyze_response(decrypted)
            
            response_data = {
                'timestamp': timestamp,
                'raw_data': data.hex(),
                'decrypted': decrypted,
                'analysis': analysis
            }
            all_responses.append(response_data)
            
            # Print immediate feedback
            if analysis['is_potential_history']:
                print(f"  🎯 POTENTIAL HISTORY DATA: {decrypted}")
                if analysis['parsed_data']:
                    print(f"     Command type: {analysis['parsed_data'].get('command_type', 'unknown')}")
                    print(f"     Sub-command: {analysis['parsed_data'].get('sub_command', 'unknown')}")
                    print(f"     Data: {analysis['parsed_data'].get('data_section', 'none')}")
            elif analysis['is_standard_voltage']:
                parsed = analysis['parsed_data']
                print(f"  📊 Standard: {parsed['voltage']}V, {parsed['temperature']}°C")
            else:
                print(f"  ❓ Unknown: {decrypted}")
                
        except Exception as e:
            print(f"  ❌ Error: {e}")
    
    async with BleakClient(address, timeout=30) as client:
        print(f"🔗 Connected to BM6 at {address}")
        await client.start_notify("FFF4", notification_handler)
        print("👂 Listening for responses...\n")
        
        for i, (command_hex, description) in enumerate(focused_commands):
            print(f"[{i+1}/{len(focused_commands)}] Testing: {description}")
            print(f"Command: {command_hex}")
            
            try:
                # Clear previous responses for this command
                all_responses.clear()
                
                # Send command
                command_bytes = bytearray.fromhex(command_hex)
                encrypted_command = encrypt_bm6(command_bytes)
                await client.write_gatt_char("FFF3", encrypted_command, response=True)
                
                # Wait longer for potential multiple history responses
                await asyncio.sleep(5)  # Increased wait time
                
                # Analyze responses for this command
                unique_responses = {}
                for response in all_responses:
                    key = response['decrypted']
                    if key not in unique_responses:
                        unique_responses[key] = response
                
                print(f"📋 Results: {len(unique_responses)} unique responses")
                
                history_responses = []
                voltage_responses = []
                unknown_responses = []
                
                for response in unique_responses.values():
                    if response['analysis']['is_potential_history']:
                        history_responses.append(response)
                    elif response['analysis']['is_standard_voltage']:
                        voltage_responses.append(response)
                    else:
                        unknown_responses.append(response)
                
                if history_responses:
                    print(f"🎯 HISTORY CANDIDATES ({len(history_responses)}):")
                    for resp in history_responses:
                        print(f"   {resp['decrypted']}")
                        if resp['analysis']['parsed_data']:
                            parsed = resp['analysis']['parsed_data']
                            print(f"      Type: {parsed.get('command_type')}, Sub: {parsed.get('sub_command')}")
                
                if unknown_responses:
                    print(f"❓ UNKNOWN RESPONSES ({len(unknown_responses)}):")
                    for resp in unknown_responses:
                        print(f"   {resp['decrypted']}")
                        
                print()
                
            except Exception as e:
                print(f"❌ Command failed: {e}\n")
        
        await client.stop_notify("FFF4")
        
        # Final analysis
        print("=" * 70)
        print("🔍 FINAL ANALYSIS")
        print("=" * 70)
        
        print("\n📊 SUMMARY OF INTERESTING RESPONSES:")
        print("Commands that produced non-standard responses:")
        
        history_candidates = [
            "d1550101080002000000000000000000",  # From command d1550164
            "d1550900000000000000000000000000",  # Echo from command d1550900  
            "d1550a00000002000000000000000000"   # Modified from command d1550a00
        ]
        
        for candidate in history_candidates:
            print(f"  • {candidate}")
        
        print("\n🔬 PATTERN ANALYSIS:")
        print("- d155 01 XX: Might be response format (01 = response type?)")
        print("- d155 09 XX: Echo suggests command recognition")
        print("- d155 0a XX: Modified response suggests parameter processing")
        
        print("\n💡 NEXT STEPS:")
        print("1. These commands show the device recognizes non-voltage requests")
        print("2. Try capturing real BM6 app traffic during history access")
        print("3. Focus on command types 01, 09, 0a variations")
        print("4. Test with time/date parameters")
        print("5. Try requesting specific record counts or ranges")

async def main():
    parser = argparse.ArgumentParser(description='BM6 Focused History Testing')
    parser.add_argument('--address', type=str, required=True, help='BM6 device address')
    
    args = parser.parse_args()
    
    print("🔍 BM6 Focused History Command Testing")
    print("Based on promising results from initial scan")
    print("Testing commands that showed anomalous responses...\n")
    
    await test_focused_history_commands(args.address)

if __name__ == "__main__":
    asyncio.run(main())
