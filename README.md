# SACP Communication Script for Snapmaker
This Python script implements the SACP (Snapmaker Communication Protocol) to interact with a Snapmaker device. It demonstrates how to send various commands to the device, such as authentication, retrieving module information, homing all axes, and setting temperatures for tools and the bed.

## Features
Dynamic Printer IP Input: The script prompts the user to enter the printer's IP address when executed.
Authentication: Sends a hello packet to authenticate with the Snapmaker device.
Module Information Retrieval: Retrieves and displays detailed module information from the device.
Homing Command: Sends a command to home all axes of the printer.
Temperature Control (Commented Out): Contains functions to set tool and bed temperatures (currently commented out; can be enabled as needed).
## Requirements
Python 3.x
Network connectivity to the Snapmaker device on the specified IP address and port (default port: 8888).
## Installation
### Clone the Repository:
```
git clone https://github.com/yourusername/your-repository.git
cd your-repository
```
### Ensure Python 3 is installed:
```
python3 --version
```
### (Optional) Create and activate a virtual environment:
```
python3 -m venv venv
source venv/bin/activate   # On Windows, use `venv\Scripts\activate`
```
## Usage
### Run the script:
```
./your_script.py
```
### Enter the Printer's IP Address:

When prompted, input the IP address of your Snapmaker device (e.g., 10.1.1.86).

### Observe the Output:

The script will authenticate, retrieve module info, perform a homing command, and finally disconnect from the device.

Note: Temperature setting commands are currently commented out in the code. To enable them, uncomment the respective function calls in the main() function.

## Code Overview
### Checksum Functions:

head_checksum(data: bytes) -> int calculates the header checksum.
u16_checksum(data: bytes) -> int computes the 16-bit checksum for the data.
### SACPPacket Class:

Represents a SACP packet with methods to encode it into bytes.
The packet structure includes start bytes, length, version, IDs, sequence number, command set, command ID, payload data, and a data checksum.
### Communication Functions:

sacp_connect(ip: str, timeout: float) -> socket.socket: Connects to the device and performs authentication.
read_packet(conn: socket.socket, timeout: float) -> SACPPacket: Reads and validates incoming SACP packets.
sacp_disconnect(conn: socket.socket, timeout: float): Disconnects from the device.
sacp_send_command(...): Sends commands and waits for a valid response.
Additional functions handle module info retrieval, submodule parsing, homing, and temperature commands.
## Customization
### IP Address:
The printer's IP address is now input by the user at startup.
### Commands:
To change which commands are sent (e.g., setting temperatures), modify or uncomment the corresponding function calls in the main() function.
### Timeouts and Ports:
Adjust SACP_TIMEOUT and SACP_PORT at the beginning of the script if needed.
## License
This project is provided "as-is" without any warranty. See the LICENSE file for details if available.

Feel free to contribute or modify the script as needed for your specific Snapmaker setup. If you encounter any issues or have suggestions, please open an issue or submit a pull request.
