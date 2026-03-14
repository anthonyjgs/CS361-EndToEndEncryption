import zmq
import sys
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

if len(sys.argv) != 3:
    print("Incorrect number of arguments")
    print("Usage: python3 EndToEnd.py REP_PORT REQ_PORT")
    exit(1)

# Which port to listen on (connected to client if client is a req service)
REP_PORT = sys.argv[1]
# Which port to send to (connected to client if client is a rep service)
REQ_PORT = sys.argv[2]

context = zmq.Context()
rep_socket = context.socket(zmq.REP)
req_socket = context.socket(zmq.REQ)

# A dict of the current connections and the symmetric keys for them
current_connections = dict[str, str]()

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

    try:
        # If a local client wants to encrypt and send data to a service
        if req["action"] == "send":
            rep = send_request(req)

        # If receiving an end-to-end message to pass to client
        elif req["action"] == "decrypt":
            rep = decrypt_request(req)

        # If end-to-end receives a first-time connection and handshake request
        elif req["action"] == "handshake_init":
            rep = handshake_init(req)

        else:
            rep = {"status": "error", "data": "Unknown request action"}


    except Exception as e:

        print("ERROR OCCURRED")


        rep = {"status": "error", "data": str(e)}

    listen_socket.send_json(rep)

def send_request(req):
    """ Unencrypted data is encrypted then sent to the remote connection """
    key = current_connections.get(req["public_key"])

    # Establish a secure symmetric key with remote if we haven't already
    if key is None:
        establish_symmetric_connection(req["remote_addr"])
        key = current_connections.get(req["public_key"])

    encrypted_data = encrypt_data(key, req["data"])

    socket = context.socket(zmq.REQ)
    socket.connect(f"tcp://{req["remote_addr"]}")

    rep = send_encrypted(socket, encrypted_data)

    socket.close()

    decrypted_data = decrypt_data(key, rep["data"])
    return {"status": "success", "data": decrypted_data}


def decrypt_request(req):
    """ Encrypted data is decrypted then the reply is prepared and returned """
    key = current_connections.get(req["public_key"])

    # If no key has been established return an error response
    if key is None:
        return {"status": "error", "data": "No connection established"}

    decrypted_data = decrypt_data(key, req["data"])

    # Forwarding to local client
    req_socket.send_json(decrypted_data)
    reply = req_socket.recv_json()

    encrypted_reply = encrypt_data(key, reply)

    return {
        "status": "success",
        "data": encrypted_reply
    }


def establish_symmetric_connection(req):
    """ Perform RSA handshake to establish a shared symmetric key with remote service """
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

    current_connections[req["public_key"]] = symmetric_key

    socket.close()

def encrypt_data(key, data):
    cipher = Fernet(key)
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(key, data):
    cipher = Fernet(key)
    return cipher.decrypt(data.encode()).decode()

def send_encrypted(socket, encrypted_data):
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
        "status": "ok",
        "encrypted_key": encrypted_key_b64
    }

if __name__ == '__main__':
    main()
