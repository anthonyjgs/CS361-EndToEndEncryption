import zmq
import sys
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import pickle
import json

REP_PORT = None
REQ_PORT = None

context = zmq.Context()
rep_socket = context.socket(zmq.REP)
req_socket = context.socket(zmq.REQ)

# A dict of the current connections and the symmetric keys for them
current_connections = dict[str, str]()

# List of public keys associated with known target ips
ip_to_pubs = {}

# Generate service RSA keypair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

def main():
    global REP_PORT, REQ_PORT
    if 2 <= len(sys.argv) <= 3:
        # Which port to listen on (connected to client if client is a req service)
        REP_PORT = sys.argv[1]
        if len(sys.argv) == 3:
            # Which port to send to (connected to client if client is a rep service)
            REQ_PORT = sys.argv[2]
    else:
        print("Incorrect number of arguments")
        print("Usage: python3 EndToEnd.py REP_PORT [REQ_PORT]")
        exit(1)

    print("End to End Encryption Service")
    print("Initializing...")
    rep_socket.bind(f"tcp://localhost:{REP_PORT}")
    print(f"rep port: {REP_PORT}")
    if REQ_PORT is not None:
        req_socket.connect(f"tcp://localhost:{REQ_PORT}")
        print(f"Client port: {REQ_PORT}")

    try:
        while True:
            service_listen(rep_socket)
    except KeyboardInterrupt:
        print("Shutting down...")
        rep_socket.close()

def service_listen(listen_socket):
    req = listen_socket.recv_json()
    print(f"REQUEST RECEIVED: {str(req)}")
    rep = None
    try:
        # If a local client wants to encrypt and send data to a service
        if req["action"] == "send":
            rep = send_request(req)
    except KeyError as e:
        print(f"KeyError for send_request: {str(e)}")
        rep = {"status": "error", "data": str(e)}

    try:
        # If receiving an end-to-end message to pass to client
        if req["action"] == "decrypt":
            rep = decrypt_request(req)
    except KeyError as e:
        print(f"KeyError for decrypt_request: {str(e)}")
        rep = {"status": "error", "data": str(e)}

    try:
        # If end-to-end receives a first-time connection and handshake request
        if req["action"] == "handshake_init":
            rep = handshake_init(req)
    except KeyError as e:
        print(f"KeyError for handshake_init: {str(e)}")
        rep = {"status": "error", "data": str(e)}

    if rep is None:
        rep = {"status": "error", "data": "Unknown request action"}

    print(f"SENDING REPLY: {str(rep)}")
    listen_socket.send_json(rep)

def send_request(req):
    """ Unencrypted data is encrypted then sent to the remote connection """
    remote_pub = ip_to_pubs.get(req["remote_addr"])
    key = current_connections.get(remote_pub)

    # Establish a secure symmetric key with remote if we haven't already
    if key is None:
        establish_symmetric_connection(req)
        remote_pub = ip_to_pubs.get(req["remote_addr"])
        key = current_connections.get(remote_pub)

    data_str = json.dumps(req["data"])
    encrypted_str = encrypt_data(key, data_str)

    socket = context.socket(zmq.REQ)
    socket.connect(f"tcp://{req["remote_addr"]}")
    rep = send_encrypted(socket, encrypted_str)

    socket.close()

    encrypted_reply_str = json.dumps(rep["data"])
    decrypted_str = decrypt_data(key, encrypted_reply_str)
    decrypted_json = json.loads(decrypted_str)
    return {"status": "success", "data": decrypted_json}


def decrypt_request(req):
    """ Encrypted data is decrypted then the reply is prepared and returned """
    if REQ_PORT is None:
        return {"status": "error", "data": "This connection does not have a listenting service"}

    try:
        key = current_connections.get(req["public_key"])
    except KeyError as e:
        print(f"Key error in decrypt request: {str(e)}")
        return {"status": "error", "data": f"KeyError in decrypt request: {str(e)}"}

    # If no key has been established return an error response
    if key is None:
        return {"status": "error", "data": "No connection established"}

    decrypted_str = decrypt_data(key, req["data"])
    decrypted_json = json.loads(decrypted_str)

    # Forwarding to local client
    req_socket.send_json(decrypted_json)
    reply_obj = req_socket.recv_json()
    reply_str = json.dumps(reply_obj)
    encrypted_reply = encrypt_data(key, reply_str)

    return {
        "status": "success",
        "data": encrypted_reply
    }


def establish_symmetric_connection(req):
    """ Perform RSA handshake to estcablish a shared symmetric key with remote service """
    # Create a socket and connect to remote service
    socket = context.socket(zmq.REQ)
    socket.connect(f"tcp://{req["remote_addr"]}")

    socket.send_json({
        "action": "handshake_init",
        "public_key": public_pem
    })

    rep = socket.recv_json()

    encrypted_key = base64.b64decode(rep["encrypted_key"])

    # Decrypt symmetric key using private RSA key
    symmetric_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    ip_to_pubs[req["remote_addr"]] = rep["public_key"]
    current_connections[rep["public_key"]] = symmetric_key

    socket.close()

def encrypt_data(key:str, data: str, encoding:str="utf-8") -> str:
    cipher = Fernet(key)
    data_bytes = data.encode(encoding)
    encrypted_bytes: bytes = cipher.encrypt(data_bytes)
    encrypted_str = encrypted_bytes.decode(encoding)
    return encrypted_str

def decrypt_data(key:str, data:str, encoding:str="utf-8") -> str:
    cipher = Fernet(key)
    decrypted_bytes = cipher.decrypt(data)
    decrypted_str = decrypted_bytes.decode(encoding)
    return decrypted_str

def send_encrypted(socket, encrypted_data:str):
    req = {
        "action": "decrypt",
        "public_key": public_pem,
        "data": encrypted_data
    }
    socket.send_json(req)
    rep = socket.recv_json()
    return rep

def handshake_init(req):
    remote_pub = serialization.load_pem_public_key(
        req["public_key"].encode()
    )

    symmetric_key = Fernet.generate_key()

    encrypted_key = remote_pub.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_key_b64 = base64.b64encode(encrypted_key).decode()

    # Index symmetric keys by the other instance's public key
    current_connections[req["public_key"]] = symmetric_key

    return {
        "status": "success",
        "public_key": public_pem,
        "encrypted_key": encrypted_key_b64
    }

if __name__ == '__main__':
    main()
