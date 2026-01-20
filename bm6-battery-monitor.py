# bm6-battery-monitor - Read data from BM6 BLE battery monitors
# https://github.com/jeffwdh/bm6-battery-monitor
#
# Wouldn't have been able to create this without the following resources:
# https://github.com/KrystianD/bm2-battery-monitor/blob/master/.docs/reverse_engineering.md
# https://doubleagent.net/bm2-reversing-the-ble-protocol-of-the-bm2-battery-monitor/
# https://www.youtube.com/watch?v=lhLff9VACU4

import argparse
import json
import asyncio
import time
from Crypto.Cipher import AES
from bleak import BleakClient
from bleak import BleakScanner
from bleak.exc import BleakError

# Function to scan for BM6 devices
async def scan_bm6(format):
  device_list = []
  scan = await BleakScanner.discover(return_adv=True, timeout=5)

  # Filter only BM6 devices
  # BleakScanner.discover returns a list of BLEDevice objects
  for device in scan:
    if device.name == "BM6":
      device_list.append([device.address, device.rssi])

  # Output data
  if format == "ascii":
    if device_list:
      print("Address           RSSI")
      for item in device_list:
        print(item[0] + " " + str(item[1]))
    else:
      print("No BM6 devices found.")
  if format == "json":
    print(json.dumps(device_list))

# Function to connect to a BM6 and pull voltage and temperature readings
# Note: Temperature readings are in Celsius and do not go below 0C
async def get_bm6_data(address, format, max_retries=3):
  # The BM6 encryption key is only /slightly/ different than the BM2
  key=bytearray([108, 101, 97, 103, 101, 110, 100, 255, 254, 48, 49, 48, 48, 48, 48, 57])

  bm6_data = {
    "voltage": "",
    "temperature": "",
    "soc": ""
  }

  def decrypt(crypted):
    cipher = AES.new(key, AES.MODE_CBC, 16 * b'\0')
    decrypted = cipher.decrypt(crypted).hex()
    return decrypted

  def encrypt(plaintext):
    cipher = AES.new(key, AES.MODE_CBC, 16 * b'\0')
    encrypted = cipher.encrypt(plaintext)
    return encrypted

  async def notification_handler(sender, data):
    message = decrypt(data)
    if message[0:6] == "d15507": # Probably not needed, but voltage/temp messages start with d15507
      bm6_data["voltage"] = int(message[15:18],16) / 100
      bm6_data["soc"] = int(message[12:14],16)
      if message[6:8] == "01":
        bm6_data["temperature"] = -int(message[8:10],16)
      else:
        bm6_data["temperature"] = int(message[8:10],16)

  # Pre-check: Scan for device to verify it's available and get BLEDevice object
  ble_device = None
  if format == "ascii":
    print(f"Scanning for device {address}...")
  
  try:
    scan_results = await BleakScanner.discover(return_adv=True, timeout=5)
    device_found = False
    for device in scan_results:
      if device.address.upper() == address.upper():
        device_found = True
        ble_device = device  # Store the BLEDevice object for connection
        if format == "ascii":
          print(f"Device found! RSSI: {device.rssi} dBm")
        break
    
    if not device_found:
      print(f"Warning: Device {address} not found during scan, will try connecting anyway...")
  except Exception as e:
    print(f"Warning: Scan failed ({e}), attempting connection anyway...")
  
  # Small delay after scan before connection attempt
  if ble_device:
    await asyncio.sleep(0.5)

  # Attempt connection with retry logic
  last_error = None
  for attempt in range(max_retries):
    try:
      if format == "ascii" and attempt > 0:
        print(f"Retry attempt {attempt + 1}/{max_retries}...")
      
      # Use BLEDevice object if available, otherwise use address string
      device_to_connect = ble_device if ble_device else address
      
      async with BleakClient(device_to_connect, timeout=20) as client:
        if format == "ascii":
          print("Connected successfully!")
        
        # Wait for services to be discovered
        if not client.is_connected:
          raise BleakError("Client connection failed")
        
        # Give the services time to be discovered
        await asyncio.sleep(1)
        
        # The d15507 command tells the BM6 to start sending volt/temp notifications
        await client.write_gatt_char("0000fff3-0000-1000-8000-00805f9b34fb", encrypt(bytearray.fromhex("d1550700000000000000000000000000")), response=True)

        # Subscribe to notifications
        await client.start_notify("0000fff4-0000-1000-8000-00805f9b34fb", notification_handler)

        # Wait for readings with timeout
        timeout_counter = 0
        max_timeout = 50  # 5 seconds
        while not bm6_data["voltage"] and not bm6_data["temperature"]:
          await asyncio.sleep(0.1)
          timeout_counter += 1
          if timeout_counter > max_timeout:
            raise TimeoutError("Timeout waiting for data from device")

        # Clean up
        await client.stop_notify("0000fff4-0000-1000-8000-00805f9b34fb")

        # Output data
        if format == "ascii":
          print("\nData received:")
          print("Voltage: " + str(bm6_data["voltage"]) + "v")
          print("Temperature: " + str(bm6_data["temperature"]) + "C")
          print("SoC: " + str(bm6_data["soc"]) + "%")
        if format == "json":
          print(json.dumps(bm6_data))
        
        return  # Success, exit function
        
    except BleakError as e:
      last_error = e
      if format == "ascii":
        print(f"Connection attempt {attempt + 1} failed: {e}")
      if attempt < max_retries - 1:
        delay = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
        if format == "ascii":
          print(f"Waiting {delay} seconds before retry...")
        await asyncio.sleep(delay)
    except TimeoutError as e:
      last_error = e
      if format == "ascii":
        print(f"Timeout on attempt {attempt + 1}: {e}")
      if attempt < max_retries - 1:
        delay = 2 ** attempt
        if format == "ascii":
          print(f"Waiting {delay} seconds before retry...")
        await asyncio.sleep(delay)
    except Exception as e:
      last_error = e
      if format == "ascii":
        print(f"Unexpected error on attempt {attempt + 1}: {e}")
      if attempt < max_retries - 1:
        delay = 2 ** attempt
        if format == "ascii":
          print(f"Waiting {delay} seconds before retry...")
        await asyncio.sleep(delay)
  
  # All retries failed
  print(f"\nERROR: Failed to connect after {max_retries} attempts.")
  print(f"Last error: {last_error}")
  print("\nTroubleshooting steps:")
  print("  1. Ensure the BM6 device is powered on and nearby")
  print("  2. Check if device is connected to another app (disconnect it)")
  print("  3. Try restarting Bluetooth: sudo hciconfig hci0 down && sudo hciconfig hci0 up")
  print("  4. Run with --scan to verify the device is discoverable")

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("--format", choices=["ascii", "json"], default="ascii", help="Output format")
  req = parser.add_mutually_exclusive_group(required=True)
  req.add_argument("--address", metavar="<address>", help="Address of BM6 to poll data from")
  req.add_argument("--scan", action="store_true", help="Scan for available BM6 devices")
  args = parser.parse_args()
  if args.address:
    try:
      asyncio.run(get_bm6_data(args.address, args.format))
    except Exception:
      raise
  if args.scan:
    try:
      asyncio.run(scan_bm6(args.format))
    except Exception:
      raise
