import json
import socket

def send_message(sock, message_type, payload):
    """Send a message with type and payload."""
    try:
        message = {"type": message_type, "payload": payload}
        message_bytes = json.dumps(message).encode()
        # Send length prefix followed by the message
        sock.sendall(len(message_bytes).to_bytes(4, byteorder="big"))
        sock.sendall(message_bytes)
    except Exception as e:
        print(f"Error in send_message: {e}")
        raise  # Propagate the exception for handling by the caller


def recv_with_length_prefix(sock):
    """Receive data with a length prefix."""
    try:
        # Read the 4-byte length prefix
        length_prefix = sock.recv(4)
        if not length_prefix:
            return None  # Connection closed
        data_length = int.from_bytes(length_prefix, byteorder="big")
        # Ensure the entire payload is received
        data = b""
        while len(data) < data_length:
            chunk = sock.recv(data_length - len(data))
            if not chunk:  # Connection closed during transmission
                return None
            data += chunk
        return data
    except Exception as e:
        print(f"Error in recv_with_length_prefix: {e}")
        return None


def recv_message(sock):
    """Receive a JSON message with type and payload."""
    try:
        message_bytes = recv_with_length_prefix(sock)
        if not message_bytes:
            return None, None  # Connection error or no data
        message = json.loads(message_bytes.decode())
        return message.get("type"), message.get("payload")
    except Exception as e:
        print(f"Error in recv_message: {e}")
        return None, None

def flush_socket(conn):
    conn.settimeout(0.1)  # Temporarily set a timeout to avoid blocking
    try:
        while conn.recv(1024):  # Read until there's no more data
            pass
    except socket.timeout:
        pass  # Timeout means there's no more data
    finally:
        conn.settimeout(None)  # Reset the timeout to blocking mode

