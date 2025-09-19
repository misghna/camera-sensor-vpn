import os
import re
import subprocess
import logging

NGINX_CONFIG_FILE = "/etc/nginx/sites-available/vpn-root.conf"
NGINX_ENABLED_LINK = "/etc/nginx/sites-enabled/vpn-root.conf"

def update_vpn_root_config(port, client_ip):
    """
    Update vpn-root.conf with new port mapping.
    port: string like "8010"
    client_ip: string like "10.0.0.10"
    """
    
    # Read current config
    if not os.path.exists(NGINX_CONFIG_FILE):
        logging.error(f"Config file not found: {NGINX_CONFIG_FILE}")
        return f"Error: Config file not found"
    
    with open(NGINX_CONFIG_FILE, 'r') as f:
        content = f.read()
    
    # Check if port mapping already exists
    port_pattern = f'"{port}"'
    if port_pattern in content:
        logging.info(f"Port {port} already exists in config")
        return f"Port {port} already configured"
    
    # Find the map section and add new mapping
    map_pattern = r'(map \$arg_sn \$backend_config \{[^}]+)(    # Add more as needed\n\})'


    
    match = re.search(map_pattern, content, re.DOTALL)
    if not match:
        logging.error("Could not find map section in config")
        return "Error: Could not find map section"
    
    # Create new mapping line
    sn = payload.get('sn')
    new_mapping = f'    "{sn}" "{client_ip}:9000";\n'
    
    # Insert new mapping before the comment line
    updated_content = content.replace(
        match.group(2),
        new_mapping + match.group(2)
    )
    
    # Write updated config
    try:
        with open(NGINX_CONFIG_FILE, 'w') as f:
            f.write(updated_content)
        logging.info(f"Added mapping: {port} -> {client_ip}:9000")
        
        # Ensure symlink exists
        if not os.path.exists(NGINX_ENABLED_LINK):
            os.symlink(NGINX_CONFIG_FILE, NGINX_ENABLED_LINK)
            logging.info(f"Created symlink: {NGINX_ENABLED_LINK}")
        
        # Test nginx config
        test_result = subprocess.run(['nginx', '-t'], 
                                   capture_output=True, text=True)
        if test_result.returncode == 0:
            # Reload nginx
            reload_result = subprocess.run(['systemctl', 'reload', 'nginx'],
                                         capture_output=True, text=True)
            if reload_result.returncode == 0:
                return f"Successfully added port {port} -> {client_ip}:9000"
            else:
                return f"Config updated but reload failed: {reload_result.stderr}"
        else:
            return f"Config syntax error: {test_result.stderr}"
            
    except Exception as e:
        logging.error(f"Error updating config: {e}")
        return f"Error updating config: {e}"

def handle_device_request(payload):
    """
    Handle the device registration payload and update nginx config.
    payload: dict with 'name', 'port', 'key'
    """
    port = payload.get('port')
    sn = payload.get('name')
    name = payload.get('name')
    
    if not port or not name:
        return "Error: Missing port or name"
    
    try:
        # Calculate client IP from port (port - 8000 = last octet)
        port_num = int(port)
        if port_num < 8001 or port_num > 8254:
            return "Error: Port must be between 8001-8254"
        
        client_octet = port_num - 8000
        client_ip = f"10.0.0.{client_octet}"
        
        # Update nginx config
        result = update_vpn_root_config(port, client_ip)
        logging.info(f"Device {name} (port {port}) -> {result}")
        return result
        
    except ValueError:
        return "Error: Invalid port number"

# Example usage for your POST request handler:
def example_post_handler():
    """Example of how to integrate this into your existing code"""
    payload = {
        "name": "e232eb06",
        "port": "8010", 
        "key": "+4RKwlLTRrYdyoqPVpWsbA=="
    }
    
    # Call the handler
    result = handle_device_request(payload)
    print(f"Update result: {result}")

if __name__ == "__main__":
    # Test the function
    example_post_handler()
