import zmq
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

LISTEN_PORT = 55551

context = zmq.Context()

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
    listen_socket = context.socket(zmq.REP)
    listen_socket.bind(f"tcp://localhost:{LISTEN_PORT}")
    print(f"Listening on port {LISTEN_PORT}")

    try:
        while True:
            service_listen(listen_socket)
    except KeyboardInterrupt:
        print("Shutting down...")
        listen_socket.close()

def service_listen(listen_socket):
    req = listen_socket.recv_json()

    try:
        if req["action"] == "send":
            rep = send_request(req)

        elif req["action"] == "decrypt":
            rep = decrypt_request(req)

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

    key = current_connections.get(req["remote_addr"])

    # Establish a secure symmetric key with remote if we haven't already
    if key is None:
        establish_symmetric_connection(req["remote_addr"])
        key = current_connections.get(req["remote_addr"])

    encrypted_data = encrypt_data(key, req["data"])

    socket = context.socket(zmq.REQ)
    socket.connect(f"tcp://{req["remote_addr"]}")

    rep = send_encrypted(socket, encrypted_data, req["remote_addr"])

    socket.close()

    decrypted_data = decrypt_data(key, rep["data"])

    return {"status": "success", "data": decrypted_data}


def decrypt_request(req):
    """ Encrypted data is decrypted then the reply is prepared and returned """
    key = current_connections.get("client")

    # If no key has been established return an error response
    if key is None:
        return {"status": "error", "data": "No connection established"}

    decrypted_data = decrypt_data(key, req["data"])

    # simulate forwarding to local client
    response_message = decrypted_data

    encrypted_reply = encrypt_data(key, response_message)

    return {
        "status": "success",
        "data": encrypted_reply
    }


def establish_symmetric_connection(remote_addr):
    """ Perform RSA handshake to establish a shared symmetric key with remote service """

    # Create a socket and connect to remote service
    socket = context.socket(zmq.REQ)
    socket.connect(f"tcp://{remote_addr}")

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

    current_connections[remote_addr] = symmetric_key

    socket.close()

def encrypt_data(key, data):
    cipher = Fernet(key)
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(key, data):
    cipher = Fernet(key)
    return cipher.decrypt(data.encode()).decode()

def send_encrypted(socket, encrypted_data, remote_addr):
    req = {
        "action": "decrypt",
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

    # store using requester address
    current_connections["client"] = symmetric_key

    return {
        "status": "ok",
        "encrypted_key": encrypted_key_b64
    }

if __name__ == '__main__':
    main()
