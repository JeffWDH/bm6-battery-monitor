#!/usr/bin/env python3

# BM6 Record Retrieval Test - Phase 4
# Based on discovery that 0A command increments an internal counter
# Test other commands that might retrieve actual data using the counter

import argparse
import asyncio
import time
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

def parse_voltage_data(hex_data):
    """Try to parse hex data as voltage/temperature like standard BM6 format"""
    if len(hex_data) < 18:
        return None
    
    try:
        # Standard BM6 voltage parsing
        if hex_data.startswith('d15507'):
            voltage = int(hex_data[15:18], 16) / 100.0
            temp_flag = hex_data[6:8]
            if temp_flag == "01":
                temperature = -int(hex_data[8:10], 16)
            else:
                temperature = int(hex_data[8:10], 16)
            soc = int(hex_data[12:14], 16) if len(hex_data) >= 14 else None
            
            return {
                'voltage': voltage,
                'temperature': temperature, 
                'soc': soc,
                'format': 'standard'
            }
        
        # Try alternative voltage formats
        voltage_candidates = []
        for i in range(0, len(hex_data) - 4, 2):
            try:
                # Try 16-bit values that might be voltage * 100
                val16 = int(hex_data[i:i+4], 16)
                if 600 <= val16 <= 2000:  # 6.0V to 20.0V
                    voltage_candidates.append({
                        'position': i,
                        'raw_value': val16,
                        'voltage': val16 / 100.0
                    })
            except:
                pass
        
        if voltage_candidates:
            return {
                'voltage_candidates': voltage_candidates,
                'format': 'alternative'
            }
                
    except Exception as e:
        pass
    
    return None

async def test_record_retrieval(address):
    """Test commands that might retrieve actual record data"""
    
    responses = []
    
    async def notification_handler(sender, data):
        timestamp = time.time()
        decrypted = decrypt_bm6(data)
        
        response_data = {
            'timestamp': timestamp,
            'raw': data.hex(),
            'decrypted': decrypted
        }
        
        # Try to parse as voltage data
        voltage_data = parse_voltage_data(decrypted)
        if voltage_data:
            response_data['voltage_data'] = voltage_data
        
        responses.append(response_data)
        
        # Print immediate analysis
        if voltage_data:
            if voltage_data.get('format') == 'standard':
                v = voltage_data['voltage']
                t = voltage_data['temperature']
                s = voltage_data.get('soc', 'N/A')
                print(f"  🔋 VOLTAGE DATA: {v}V, {t}°C, SoC:{s}%")
            elif voltage_data.get('format') == 'alternative':
                candidates = voltage_data['voltage_candidates']
                candidate_strs = [f"{c['voltage']}V@pos{c['position']}" for c in candidates]
                print(f"  ⚡ VOLTAGE CANDIDATES: {candidate_strs}")
        else:
            print(f"  📦 Response: {decrypted[:32]}{'...' if len(decrypted) > 32 else ''}")

    async with BleakClient(address, timeout=30) as client:
        print(f"🔗 Connected to BM6 at {address}")
        await client.start_notify("FFF4", notification_handler)
        
        print("\n🎯 THEORY: 0A command increments counter, other commands read data")
        print("Testing data retrieval commands after setting counter position...\n")
        
        # Test 1: Reset counter and try reading
        print("📋 TEST 1: Reset counter and read data")
        
        # Commands to test for data retrieval (based on patterns we've seen)
        data_commands = [
            ("d1550b00000000000000000000000000", "Command 0B (next after 0A)"),
            ("d1550800000000000000000000000000", "Command 08 (history variant)"),
            ("d1550164000000000000000000000000", "Command 01 variant (gave unique response)"),
            ("d1550200000000000000000000000000", "Command 02 (from earlier test)"),
            ("d1550300000000000000000000000000", "Command 03 variant"),
            ("d1550400000000000000000000000000", "Command 04 (might be read data)"),
            ("d1550500000000000000000000000000", "Command 05 variant"),
            ("d1550600000000000000000000000000", "Command 06 variant"),
        ]
        
        for command_hex, description in data_commands:
            responses.clear()
            print(f"\nTesting: {description}")
            print(f"Command: {command_hex}")
            
            try:
                command_bytes = bytearray.fromhex(command_hex)
                encrypted = encrypt_bm6(command_bytes)
                await client.write_gatt_char("FFF3", encrypted, response=True)
                await asyncio.sleep(2)
                
                if responses:
                    print(f"📊 Got {len(responses)} response(s)")
                    for resp in responses:
                        if 'voltage_data' in resp:
                            print("  ⭐ CONTAINS VOLTAGE DATA!")
                else:
                    print("  ❌ No response")
                    
            except Exception as e:
                print(f"  ❌ Error: {e}")
        
        print("\n📋 TEST 2: Set counter position then read")
        
        # Set counter to specific positions and try reading
        counter_positions = [0, 1, 5, 10, 20, 50]
        
        for pos in counter_positions:
            print(f"\n🔄 Setting counter to position {pos}")
            responses.clear()
            
            # Send 0A command with parameter to set position
            set_command = f"d1550a00{pos:02x}0000000000000000000000"
            
            try:
                command_bytes = bytearray.fromhex(set_command)
                encrypted = encrypt_bm6(command_bytes)
                await client.write_gatt_char("FFF3", encrypted, response=True)
                await asyncio.sleep(1)
                
                # Now try to read data at this position
                for read_cmd, desc in [
                    ("d1550b00000000000000000000000000", "Read with 0B"),
                    ("d1550800000000000000000000000000", "Read with 08"),
                    ("d1550164000000000000000000000000", "Read with 01"),
                ]:
                    responses.clear()
                    print(f"  📖 {desc}: ", end="")
                    
                    try:
                        cmd_bytes = bytearray.fromhex(read_cmd)
                        encrypted = encrypt_bm6(cmd_bytes)
                        await client.write_gatt_char("FFF3", encrypted, response=True)
                        await asyncio.sleep(1)
                        
                        if responses:
                            resp = responses[0]
                            if 'voltage_data' in resp:
                                print("VOLTAGE DATA FOUND! ⭐")
                                vdata = resp['voltage_data']
                                if vdata.get('format') == 'standard':
                                    print(f"    {vdata['voltage']}V, {vdata['temperature']}°C")
                            else:
                                # Look for any non-standard patterns
                                decrypted = resp['decrypted']
                                if not decrypted.startswith('d15507') and not decrypted.startswith('d1550a'):
                                    print(f"Different pattern: {decrypted[:20]}...")
                                else:
                                    print("Standard/counter response")
                        else:
                            print("No response")
                            
                    except Exception as e:
                        print(f"Error: {e}")
                        
            except Exception as e:
                print(f"❌ Failed to set position: {e}")
        
        print("\n📋 TEST 3: Rapid sequential reads")
        print("Testing if multiple reads return different historical records")
        
        # Set counter to beginning
        try:
            reset_cmd = "d1550a00000000000000000000000000"
            command_bytes = bytearray.fromhex(reset_cmd)
            encrypted = encrypt_bm6(command_bytes)
            await client.write_gatt_char("FFF3", encrypted, response=True)
            await asyncio.sleep(1)
            
            print("Counter reset, now doing sequential reads...")
            
            # Try rapid sequential reads with different commands
            read_commands = [
                "d1550b00000000000000000000000000",
                "d1550800000000000000000000000000", 
                "d1550164000000000000000000000000"
            ]
            
            for i in range(10):  # Read 10 records
                print(f"\n📖 Sequential read {i+1}:")
                
                for cmd_hex in read_commands:
                    responses.clear()
                    
                    try:
                        command_bytes = bytearray.fromhex(cmd_hex)
                        encrypted = encrypt_bm6(command_bytes)
                        await client.write_gatt_char("FFF3", encrypted, response=True)
                        await asyncio.sleep(0.5)
                        
                        if responses and len(responses) > 0:
                            resp = responses[0]
                            if 'voltage_data' in resp:
                                vdata = resp['voltage_data']
                                if vdata.get('format') == 'standard':
                                    print(f"  🔋 {vdata['voltage']}V, {vdata['temperature']}°C")
                                    # This would be historical data!
                                    break
                        
                    except Exception as e:
                        continue
                        
                # Increment counter for next record
                try:
                    inc_cmd = "d1550a00010000000000000000000000"
                    command_bytes = bytearray.fromhex(inc_cmd)
                    encrypted = encrypt_bm6(command_bytes)
                    await client.write_gatt_char("FFF3", encrypted, response=True)
                    await asyncio.sleep(0.2)
                except:
                    pass
                        
        except Exception as e:
            print(f"❌ Sequential read test failed: {e}")
        
        await client.stop_notify("FFF4")
        
        print("\n" + "="*70)
        print("🎯 ANALYSIS SUMMARY")
        print("="*70)
        print("\nKey findings from this test:")
        print("1. If any commands returned actual voltage data (not standard readings)")
        print("2. If different positions returned different voltage values")
        print("3. If sequential reads produced a series of historical records")
        print("\nIf we found historical voltage data, the next step is:")
        print("- Implement proper record parsing")
        print("- Add timestamp interpretation")
        print("- Create a get_history() function")

async def main():
    parser = argparse.ArgumentParser(description='BM6 Record Retrieval Testing')
    parser.add_argument('--address', type=str, required=True, help='BM6 device address')
    
    args = parser.parse_args()
    
    print("🎯 BM6 Record Retrieval Test - Phase 4")
    print("Testing theory: 0A sets counter position, other commands read data")
    print("Looking for actual historical voltage records...\n")
    
    await test_record_retrieval(args.address)

if __name__ == "__main__":
    asyncio.run(main())
