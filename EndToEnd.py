import zmq
from cryptography.fernet import Fernet

LISTEN_PORT = 55551

context = zmq.Context()

# A dict of the current connections and the symmetric keys for them
current_connections = dict[str, str]()

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
        if req.type == "plain":
            rep = plain_request(req)
        elif req.type == "encrypted":
            rep = encrypted_request(req)
        else:
            rep = {"type": "error", "data": "Unknown request type"}

    except Exception as e:
        rep = {"type": "error", "data": "failed while processing request"}

    listen_socket.send_json(rep)

def plain_request(req):
    """ Unencrypted data is encrypted then sent to the remote connection """
    key = current_connections.get(req.remote_addr)

    # Establish a secure symmetric key with remote if we haven't already
    if key is None:
        # TODO: Establish connection
        pass

    encrypted_data = encrypt_data(key, req.data)

    socket = context.socket(zmq.REQ)
    socket.connect(f"tcp://{req.remote_addr}")
    send_encrypted(encrypted_data)
    rep = socket.recv_json()
    decrypted_data = decrypt_data(key, rep.data)
    socket.close()
    return {"type": rep.type, "data": decrypted_data}


def encrypted_request(req):
    """ Encrypted data is decrypted then the reply is prepared and returned """
    key = current_connections.get(req.remote_address)

    # If no key has been established return an error response
    if key is None:
        return {"type": "error", "data": "No connection established"}

    decrypted_data = decrypt_data(key, req.data)
    return {"type": "received", "data": decrypted_data}


def establish_symmetric_connection(remote_addr):
    """ Uses asymmetric encryption to share a symmetric key and stores it in
        current connections if successful. """
    pass

def encrypt_data(key, data):
    cipher = Fernet(key)
    return cipher.encrypt(data)

def decrypt_data(key, data):
    cipher = Fernet(key)
    return cipher.decrypt(data)

def send_encrypted(socket, encrypted_data):
    req = {"type": "encrypted", "data": encrypted_data}
    socket.send(req)
    rep = socket.recv_json()
    return rep

if __name__ == '__main__':
    main()