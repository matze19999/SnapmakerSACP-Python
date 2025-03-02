#!/usr/bin/env python3
import socket
import struct
import time
import re

SACP_PORT = 8888
SACP_TIMEOUT = 5  # seconds
sequence = 2     # Global sequence number (starts at 2)

def head_checksum(data: bytes) -> int:
    crc = 0
    poly = 7
    for byte in data:
        for j in range(8):
            bit = ((byte >> (7 - j)) & 0x01) == 1
            c07 = ((crc >> 7) & 0x01) == 1
            crc = (crc << 1) & 0xff
            if (not c07 and bit) or (c07 and not bit):
                crc ^= poly
    return crc & 0xff

def u16_checksum(data: bytes) -> int:
    check_num = 0
    length = len(data)
    i = 0
    while i < length - 1:
        check_num += (data[i] << 8) | data[i+1]
        check_num &= 0xffffffff
        i += 2
    if length % 2 != 0:
        check_num += data[-1]
    while check_num > 0xFFFF:
        check_num = ((check_num >> 16) & 0xFFFF) + (check_num & 0xFFFF)
    check_num = ~check_num
    return check_num & 0xFFFF

class SACPPacket:
    """
    Represents a SACP packet.

    Structure:
      - Start bytes: 0xAA 0x55
      - 2-byte length: len(Data) + 6 (from ReceiverID to CommandID) + 2 (checksum)
      - Version: 0x01
      - ReceiverID (1 byte)
      - Header checksum (1 byte, over the first 6 bytes)
      - SenderID (1 byte)
      - Attribute (1 byte)
      - Sequence (2 bytes, little endian)
      - CommandSet (1 byte)
      - CommandID (1 byte)
      - Data (variable length)
      - 2-byte data checksum (little endian, over result[7:13+len(Data)])
    """
    def __init__(self, receiver_id, sender_id, attribute, sequence, command_set, command_id, data: bytes):
        self.receiver_id = receiver_id
        self.sender_id = sender_id
        self.attribute = attribute
        self.sequence = sequence
        self.command_set = command_set
        self.command_id = command_id
        self.data = data

    def encode(self) -> bytes:
        # Length = len(Data) + 6 (from ReceiverID to CommandID) + 2 (checksum)
        data_length = len(self.data) + 6 + 2
        total_length = 15 + len(self.data)  # 15 = 13-byte header + 2-byte checksum
        result = bytearray(total_length)
        result[0] = 0xAA
        result[1] = 0x55
        result[2:4] = struct.pack("<H", data_length)
        result[4] = 0x01  # Version
        result[5] = self.receiver_id
        result[6] = head_checksum(result[0:6])
        result[7] = self.sender_id
        result[8] = self.attribute
        result[9:11] = struct.pack("<H", self.sequence)
        result[11] = self.command_set
        result[12] = self.command_id
        if self.data:
            result[13:13+len(self.data)] = self.data
        checksum = u16_checksum(result[7:13+len(self.data)])
        result[-2:] = struct.pack("<H", checksum)
        return bytes(result)

def read_packet(conn: socket.socket, timeout: float) -> SACPPacket:
    conn.settimeout(timeout)
    header = conn.recv(4)
    if len(header) < 4:
        raise Exception("Header too short")
    data_len = struct.unpack("<H", header[2:4])[0]
    remaining_length = data_len + 7 - 4  # Total length minus already read 4 bytes
    body = b""
    while len(body) < remaining_length:
        chunk = conn.recv(remaining_length - len(body))
        if not chunk:
            break
        body += chunk
    packet_data = header + body
    if len(packet_data) < 13:
        raise Exception("Packet too short")
    if packet_data[0] != 0xAA or packet_data[1] != 0x55:
        raise Exception("Not a valid SACP packet")
    if packet_data[4] != 0x01:
        raise Exception("SACP version does not match")
    if head_checksum(packet_data[0:6]) != packet_data[6]:
        raise Exception("Invalid header checksum")
    expected_ck = u16_checksum(packet_data[7:len(packet_data)-2])
    actual_ck = struct.unpack("<H", packet_data[-2:])[0]
    if expected_ck != actual_ck:
        raise Exception("Invalid data checksum")
    receiver_id = packet_data[5]
    sender_id = packet_data[7]
    attribute = packet_data[8]
    sequence_val = struct.unpack("<H", packet_data[9:11])[0]
    command_set = packet_data[11]
    command_id = packet_data[12]
    data = packet_data[13:-2]
    return SACPPacket(receiver_id, sender_id, attribute, sequence_val, command_set, command_id, data)

def sacp_connect(ip: str, timeout: float) -> socket.socket:
    conn = socket.create_connection((ip, SACP_PORT), timeout=timeout)
    conn.settimeout(timeout)
    # Send hello packet (authentication)
    data = bytes([11, 0]) + b"sm2uploader" + bytes([0, 0, 0, 0])
    packet = SACPPacket(
        receiver_id=2,
        sender_id=0,
        attribute=0,
        sequence=1,
        command_set=0x01,
        command_id=0x05,
        data=data
    )
    conn.sendall(packet.encode())
    print("Hello packet sent, waiting for response...")
    while True:
        response = read_packet(conn, timeout)
        if response.command_set == 0x01 and response.command_id == 0x05:
            print("Authentication successful!")
            break
    return conn

def sacp_disconnect(conn: socket.socket, timeout: float) -> None:
    packet = SACPPacket(
        receiver_id=2,
        sender_id=0,
        attribute=0,
        sequence=1,
        command_set=0x01,
        command_id=0x06,
        data=b""
    )
    conn.settimeout(timeout)
    conn.sendall(packet.encode())
    print("Disconnect packet sent.")

def sacp_send_command(conn: socket.socket, command_set: int, command_id: int, data: bytes, timeout: float) -> None:
    global sequence
    sequence += 1
    current_sequence = sequence
    packet = SACPPacket(
        receiver_id=1,
        sender_id=0,
        attribute=0,
        sequence=current_sequence,
        command_set=command_set,
        command_id=command_id,
        data=data
    )
    conn.settimeout(timeout)
    conn.sendall(packet.encode())
    print(f"Sent: Sequence={current_sequence}, CommandSet=0x{command_set:02x}, CommandID=0x{command_id:02x}")
    while True:
        response = read_packet(conn, timeout)
        if (response.sequence == current_sequence and
            response.command_set == command_set and
            response.command_id == command_id):
            if len(response.data) == 1 and response.data[0] == 0:
                print("Command executed successfully.")
                return

def sacp_get_module_info_list(conn: socket.socket, timeout: float):
    global sequence
    sequence += 1
    current_sequence = sequence
    pkt = SACPPacket(1, 0, 0, current_sequence, 0x01, 0x20, b"")
    conn.settimeout(timeout)
    conn.sendall(pkt.encode())
    print(f"Sent: Get Module Info List (Seq={current_sequence}, CmdSet=0x01, CmdID=0x20)")
    while True:
        resp = read_packet(conn, timeout)
        if resp.sequence == current_sequence and resp.command_set == 0x01 and resp.command_id == 0x20:
            data = resp.data
            if len(data) < 1:
                raise Exception("Response too short, no result byte")
            result = data[0]
            if result != 0:
                raise Exception(f"Get Module Info List failed, result={result}")
            offset = 1
            modules = []
            while offset < len(data):
                if offset + 1 > len(data):
                    print("Warning: incomplete module info (key)")
                    break
                key = data[offset]
                offset += 1
                if offset + 2 > len(data):
                    print("Warning: incomplete module info (moduleId)")
                    break
                module_id = struct.unpack_from("<H", data, offset)[0]
                offset += 2
                if offset + 1 > len(data):
                    print("Warning: incomplete module info (moduleIndex)")
                    break
                module_index = data[offset]
                offset += 1
                if offset + 1 > len(data):
                    print("Warning: incomplete module info (moduleState)")
                    break
                module_state = data[offset]
                offset += 1
                if offset + 4 > len(data):
                    print("Warning: incomplete module info (serialNum)")
                    break
                serial_num = struct.unpack_from("<I", data, offset)[0]
                offset += 4
                if offset + 1 > len(data):
                    print("Warning: incomplete module info (hardwareVersion)")
                    break
                hardware_version = data[offset]
                offset += 1
                if offset + 2 > len(data):
                    print("Warning: incomplete module info (firmwareVersion length)")
                    break
                fw_len = struct.unpack_from("<H", data, offset)[0]
                offset += 2
                if offset + fw_len > len(data):
                    print("Warning: incomplete module info (firmwareVersion content), using remaining bytes")
                    firmware_version_bytes = data[offset:]
                    offset = len(data)
                else:
                    firmware_version_bytes = data[offset:offset+fw_len]
                    offset += fw_len
                firmware_version = firmware_version_bytes.decode("ascii", errors="ignore")
                modules.append({
                    "key": key,
                    "moduleId": module_id,
                    "moduleIndex": module_index,
                    "moduleState": module_state,
                    "serialNum": serial_num,
                    "hardwareVersion": hardware_version,
                    "firmwareVersion": firmware_version
                })
            print("\nReceived modules:")
            if not modules:
                print("No modules received.")
            else:
                for m in modules:
                    print(m)
                # Search for the module that contains all submodules (e.g. moduleId 1024)
                for m in modules:
                    if m.get("moduleId") == 1024:
                        fw_string = m.get("firmwareVersion", "")
                        print("\nFirmwareVersion String:")
                        print(repr(fw_string))
                        submodules = parse_submodules(fw_string)
                        print(f"\nDetected submodules ({len(submodules)}):")
                        for i, sm in enumerate(submodules):
                            print(f"Submodule {i}: Header: {repr(sm['header'])}, Version: {sm['version']}, Raw: {sm['raw']}")
            return modules

def parse_submodules(fw_string: str) -> list:
    """
    Attempts heuristically to extract additional information from the large firmwareVersion string.

    This approach searches for patterns where a submodule starts with a header
    (non-ASCII bytes) and a version string (e.g. "v1.0.0" or "v1.14.6").

    Here we use a regex that attempts to capture an optional header (any non-printable characters)
    before a version string "v1.<number>.<number>".
    """
    pattern = re.compile(rb'((?:[\x00-\x1F\x7F-\xff]+)?)(v1\.\d+\.\d+)')
    fw_bytes = fw_string.encode("latin1", errors="replace")
    matches = list(pattern.finditer(fw_bytes))
    submodules = []
    for m in matches:
        header_bytes = m.group(1)
        version_bytes = m.group(2)
        try:
            header_text = header_bytes.decode("ascii", errors="replace")
        except:
            header_text = header_bytes.hex()
        version_text = version_bytes.decode("ascii", errors="replace")
        submodules.append({
            "header": header_text,
            "version": version_text,
            "raw": m.group(0).hex()
        })
    return submodules

def sacp_home(conn: socket.socket, timeout: float) -> None:
    """
    Constructs a packet for homing by creating a data buffer with 0x00.
    The command with CommandSet 0x01 and CommandID 0x35 is sent, which triggers homing on all axes.
    """
    data = bytearray()
    data.append(0x00)
    print("Starting homing (all axes)...")
    sacp_send_command(conn, 0x01, 0x35, bytes(data), timeout)

def sacp_set_bed_temperature(conn: socket.socket, tool_id: int, temperature: int, timeout: float) -> None:
    """
    Constructs a packet to set the bed temperature:
      - First byte: 0x05
      - Second byte: tool_id (for example 13)
      - Then 2 bytes (little endian) for the temperature.
    Uses CommandSet 0x14 and CommandID 0x02.
    """
    data = bytearray()
    data.append(0x05)
    data.append(tool_id)  # tool_id, for example 13
    data += struct.pack("<H", temperature)
    print(f"Setting bed temperature to {temperature} (tool_id={tool_id})")
    sacp_send_command(conn, 0x14, 0x02, bytes(data), timeout)

def sacp_set_tool_temperature(conn: socket.socket, tool_id: int, temperature: int, timeout: float) -> None:
    """
    Constructs a packet to set the tool temperature:
      - First byte: 0x08
      - Second byte: tool_id (e.g. 13)
      - Then 2 bytes (little endian) for the temperature.
    Uses CommandSet 0x10 and CommandID 0x02.
    """
    data = bytearray()
    data.append(0x08)
    data.append(tool_id)
    data += struct.pack("<H", temperature)
    print(f"Set Tool Temperature to {temperature}°C (tool_id={tool_id})")
    sacp_send_command(conn, 0x10, 0x02, bytes(data), timeout)

def main():
    # Ask the user for the printer's IP address
    ip = input("Enter the printer IP address: ")
    try:
        conn = sacp_connect(ip, SACP_TIMEOUT)
        time.sleep(1)
        # Get module info
        sacp_get_module_info_list(conn, SACP_TIMEOUT)
        # Go Home
        sacp_home(conn, SACP_TIMEOUT)
        time.sleep(1)
        # Set Tool Temperature to 200°C
        # sacp_set_tool_temperature(conn, 0, 200, SACP_TIMEOUT)
        # Set Bed Temperature to 60°C
        # sacp_set_bed_temperature(conn, 13, 60, SACP_TIMEOUT)
        sacp_disconnect(conn, SACP_TIMEOUT)
        conn.close()
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
