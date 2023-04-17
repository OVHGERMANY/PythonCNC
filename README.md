# Python CNC Tool

A Command-and-Control (CNC) Command Line Interface (CLI) tool for managing network tasks, designed for educational purposes and responsible use.

## Prerequisites

- Python 3.x installed on your system
- Basic knowledge of Python and networking concepts

## Installation

1. Clone this repository or download the source code as a ZIP file and extract it to a directory of your choice.

```bash
git clone https://github.com/OVHGERMANY/PythonCNC.git
```

2. Navigate to the `PythonCNC` directory.

```bash
cd PythonCNC
```

3. Open the `cnc_config.json` file in a text editor and customize the settings as needed. Replace `your_api_key` with your actual API key and adjust other settings according to your requirements.

## Usage

1. Open a terminal or command prompt and navigate to the `PythonCNC` directory.

2. Run the following command to start the CNC CLI tool:

```bash
python3 cnc_cli.py
```

3. If you want to enable the auto-update feature, run the following command instead:

```bash
python3 cnc_cli.py --auto-update
```

4. Connect to the CNC CLI tool using a Raw connection client (e.g., Netcat, PuTTY) and the specified IP address and port number (default is 8888).

5. Use the available commands to control the CNC CLI tool and start attacks.

## Commands

- `.<method> IP port time [threads]`: Start an attack with the specified method, target IP, port, time (in seconds), and optionally, the number of threads.
- `exit`: Exit the CNC CLI tool.
- `clear`: Clear the screen.
- `config <key> <value>`: Update the configuration settings.

## How it works and fetures.
The CNC CLI tool is designed to manage network tasks and send commands to a CNC server. The tool itself does not directly perform the attacks but rather acts as an interface for users to send commands to the CNC server, which then carries out the requested tasks. Here's a high-level overview of how the CNC CLI tool works:

1. **Running the CNC CLI tool**: When you run the `cnc_cli.py` script, it starts a server that listens for incoming connections on a specified port (default is 8888). Users can connect to this server using a Raw connection client (e.g., Netcat, PuTTY).

2. **User authentication**: The CNC CLI tool checks the connecting user's IP address against a list of allowed IP addresses specified in the `cnc_config.json` file. If the IP address is not allowed, the connection is rejected.

3. **Command processing**: Once a user is connected, they can enter commands to control the CNC CLI tool and start attacks. The tool processes these commands and performs the requested actions, such as starting an attack or updating configuration settings.

4. **Sending commands to the CNC server**: When a user requests an attack, the CNC CLI tool sends a request to the CNC server with the necessary information, such as the target IP, port, attack method, duration, and number of threads. This is typically done using an HTTP POST request or an API call, depending on the CNC server's implementation.

5. **CNC server execution**: The CNC server receives the request and carries out the attack using the specified method, target, and parameters. The server may have a pool of bots or other resources to perform the attack.

6. **Monitoring and control**: The CNC CLI tool allows users to monitor ongoing attacks and control them as needed. Users can stop attacks, adjust parameters, or start new attacks using the available commands.

7. **Logging**: The CNC CLI tool logs user activity and any errors that occur during command processing. This information can be useful for troubleshooting and understanding how the tool is being used.


## Disclaimer

This CNC CLI tool is intended for educational purposes and responsible use only. The user is responsible for ensuring that their actions comply with applicable laws and regulations. I "OVHGERMANY" assumes no liability for any misuse of this tool.

## License

This project is licensed under the GNU General Public License v3.0(LICENSE).


