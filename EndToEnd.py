import zmq

LOCAL_PORT = 55551

REMOTE_ADDRESS = 'localhost'
REMOTE_PORT = 55552

context = zmq.Context()

def main():
    print("End to End Encryption Service")
    print("Initializing...")
    listen_socket = context.socket(zmq.REP)
    listen_socket.bind(f"tcp://localhost:{LOCAL_PORT}")
    print(f"Listening on port {LOCAL_PORT}")

    try:
        while True:

    except KeyboardInterrupt:
        print("Shutting down...")
        listen_socket.close()


def service_listen():
    req = listen_socket.recv_json()
    try:
        if req.type == "plain":
            encrypted_data = encrypt_data(req.data)
            send_encrypted(encrypted_data)
        elif req.type == "encrypted":
            decrypted_data = decrypt_data(req.data)
            send_decrypted(decrypted_data)
        else:
            print("Invalid Request Type")
    # TODO: Provide error handling for the exceptions
    except:
        print("Invalid Request Type")

    listen_socket.send_json(response)


def encrypt_data():
    pass

def send_encrypted(encrypted_data):
    send_socket = context.socket(zmq.REQ)


if __name__ == '__main__':
    main()