import socket
import struct
import argparse
import logging
import sys

def get_args(argv=None):
    '''read the arguments from command line and return the values'''
    parser = argparse.ArgumentParser(description="LIGHTCLIENT")
    parser.add_argument('-s', type=str, required=True, help='Server IP')
    parser.add_argument('-p', type=int, required=True, help='Port')
    parser.add_argument('-l', dest='log_file', type=str, required=True, help='logFile')
    args = parser.parse_args()
    server_ip = args.s
    server_port = args.p
    log_file = args.log_file
    return server_ip, server_port, log_file

def send_packet(sock, msg_type, msg):
    '''send packet'''
    data = struct.pack('>III', 17, msg_type, len(msg)) + msg.encode()
    print("Sending Message {}".format(msg))
    logging.info(f"Sending Message: {msg}")
    sock.sendall(data)

def recv_data(sock):
    '''receive data'''
    recv_data = sock.recv(struct.calcsize('>III'))
    msg_version, msg_type, msg_length = struct.unpack('>III', recv_data)
    recv_message = sock.recv(msg_length)
    decoded_message = recv_message.decode()
    logging.info(f"Received Message: {decoded_message}")
    return decoded_message

def main():
    #parse arguments
    server_ip, server_port, log_location = get_args(sys.argv[1:])
    print("Server IP: {}, Port: {}, Log location: {}".format(server_ip,server_port, log_location))

    #configure logging
    logging.basicConfig(filename=log_location, filemode='w', format='%(asctime)s- %(levelname)s - %(funcName)s - %(message)s', level=logging.INFO)
    logging.info(f'Starting LIGHTCLIENT')
    logging.info(f"Remote Server IP = {server_ip}, Remote Server Port ={server_port}, Logfile = {log_location}")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))
    print("Connected to server on {}".format((server_ip, server_port)))
    logging.info(f"Connected to remote server on IP: {server_ip} Port:{server_port}")

    # send hello
    send_packet(client_socket, 0, "HELLO")

    #receive hello
    received_message = recv_data(client_socket)
    if received_message != "HELLO":
        logging.error(f"Unrecognized message. Expecting 'HELLO', received{received_message}. Dropping packet and exiting.")
        sys.exit(1)

    #sending lighton command
    send_packet(client_socket, 1, "LIGHTON")

    #receive SUCCESS
    received_message = recv_data(client_socket)
    if received_message == "SUCCESS":
        logging.info(f"LIGHTON command successful")

    #sending lightoff command
    send_packet(client_socket, 2, "LIGHTOFF")

    #receive SUCCESS
    received_message = recv_data(client_socket)
    if received_message == "SUCCESS":
        logging.info(f"LIGHTOFF command successful")

    #send disconnect
    logging.info(f"Disconnecting")
    send_packet(client_socket, 3, "DISCONNECT")
    client_socket.close()

if __name__ == '__main__':
    main()
