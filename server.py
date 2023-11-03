import argparse
import socket
import struct
import threading
import sys 
import logging
import time
ENCODING = 'utf-8'

def get_args(argv=None):
    #read the arguments from command line and return the values
    parser = argparse.ArgumentParser(description="lightserver")
    parser.add_argument('-p', type=int, required=True, help='Port')
    parser.add_argument('-l', type=str, required=True, help='logFile')
    args = parser.parse_args()
    LOGFILE = args.l
    PORT = args.p
    return PORT, LOGFILE

def unpack_header(thread_id, formatter, header):
    '''Unpack a header and return the values'''
    try:
        msg_version, msg_type, msg_length = struct.unpack(formatter, header)
        logging.info(f"Unpacked Header: Version:{msg_version}, Type:{msg_type},Length:{msg_length}")
    except struct.error as e:
        logging.error(f"Error unpacking data. Error:{e}")
        print("Error unpacking data in thread {}. Exitingthread.".format(thread_id))
        sys.exit(1)

    #check if version is 17
    if msg_version == 17:
        print("Version Accepted")
        logging.info(f"Version is correct. Current version is {msg_version}.")
    else:
        print("Version Mismatch")
        logging.error(f"Wrong version in packet {msg_version}. Exiting thread.")
        print("Version Mismatch")
        sys.exit(1)

    #return the length of content
    return msg_version, msg_length, msg_type

def unpack_command(message):
    '''unpack command from the received message'''
    try:
        decoded_data = message.decode()
        logging.info(f"Decoded data: {decoded_data}")
        print("Decoded data {}".format(decoded_data))
    except UnicodeDecodeError:
        logging.error(f"Error decoding data. Error:{e}")
        sys.exit(1)
    return decoded_data

def send_packet(thread_id, conn, addr, data_packet):
    '''send packet to client'''
    try:
        conn.sendall(data_packet)
        logging.info(f"Thread ID: {thread_id}. Sent data {data_packet} to Addr:{addr} ")
        return 0
    except socket.error as e:
        logging.error(f"Error: Sending packet to:{addr}, Error:{e}")
        sys.exit(1)

def handle_command(thread_id, decoded_data, message_type, conn, addr):
    '''handle different commands in the assignment'''
    send_version = 17
    status = 0
    if (message_type == 0 and decoded_data == "HELLO"):
        msg_type = 0
        message = "HELLO"
        data = struct.pack('>III5s', send_version, msg_type, len(message),message.encode())
        status = send_packet(thread_id, conn, addr, data)

    if (message_type == 1 and decoded_data == "LIGHTON"):
        msg_type = 1
        message = "SUCCESS"
        data = struct.pack('>III7s', send_version, msg_type, len(message),message.encode())
        status = send_packet(thread_id, conn, addr, data)

    if (message_type == 2 and decoded_data == "LIGHTOFF"):
        msg_type = 2
        message = "SUCCESS"
        data = struct.pack('>III7s', send_version, msg_type, len(message),message.encode())
        status = send_packet(thread_id, conn, addr, data)

    if (message_type == 3 and decoded_data == "DISCONNECT"):
        conn.close()
        print("Thread ID {}: Closed Connection".format(thread_id))
        status = 1

    if message_type not in [0,1,2,3]:
        logging.info(f"Thread ID: {thread_id}. Unknown message {message_type} -ignoring")
        status = 1
        
    return status

def handle_client(conn, addr):
    '''Handling a client connection. One thread per client connection.'''
    thread_id = threading.get_ident()
    print("Thread ID {} is handling connection from {}".format(thread_id, addr))
    logging.info(f"Thread ID: {thread_id}. Handling a connection from: {addr}")
    while conn:
        #receive the header
        try:
            header = conn.recv(struct.calcsize('>III'))
        except OSError:
            logging.info(f"Thread ID: {thread_id}. 0 byte from client. Completed communication. ")
            sys.exit(1)

        message_version, message_length, message_type = unpack_header(thread_id,'>III', header)
        logging.info(f"Thread ID: {thread_id}. Header values: Message version:{message_version}, Message Length: {message_length}, Message Type:{message_type}")
        
        #get the content based on information in the header, message_length in this example
        received_data = conn.recv(message_length)
        logging.info(f"Thread ID: {thread_id}. Read {message_length} bytes ofdata")
        
        #decode command
        decoded_command = unpack_command(received_data)
        logging.info(f"Thread ID: {thread_id}. Decoded command in packet:{decoded_command}")

        #handle command
        res = handle_command(thread_id, decoded_command, message_type, conn,addr)
        if res == 0:
            logging.info(f"Thread ID: {thread_id}. Command {decoded_command}successfully executed. Return Code {res}")
        else:
            logging.warning(f"Thread ID: {thread_id}. Command {decoded_command}.Return Code {res}")

if __name__ == '__main__':
    #parse arguments
    port, log_location = get_args(sys.argv[1:])
    print("Port: {}, Log location: {}".format(port, log_location))
    #configure logging
    logging.basicConfig(filename=log_location, filemode='w', format='%(asctime)s- %(levelname)s - %(funcName)s - %(message)s', level=logging.INFO)
    logging.info('Starting LIGHTSERVER')
    logging.info(f"Server Port = {port}, Logfile = {log_location}")

    #get the local IP. 
    my_ip = socket.gethostbyname(socket.gethostname())
    logging.info(f"Server IP = {my_ip}")

    #create socket
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logging.info(f"Success: Created socket on IP:{my_ip}, Port:{port}")
    except socket.error as e:
        logging.error(f"Error: Creating socket on IP:{my_ip}, Port:{port},Error:{e}")
        sys.exit(1)

    #bind it to the ip and port
    try:
        server_socket.bind((my_ip,port))
        logging.info(f"Success:Bind Successful")
    except socket.error as e:
        logging.error(f"Error: Binding socket to IP:{my_ip}, Port:{port}, Error:{e}")
        sys.exit(1)

    #listen
    logging.info(f"Starting to listen on IP:{my_ip}, Port:{port}")
    print("Lightserver listening...")
    server_socket.listen(1)

    #start handling clients
    while True:
        connection, address = server_socket.accept()
        logging.info(f"Received a connection from: {connection}, address:{address}")
        thread = threading.Thread(target=handle_client, args=(connection,address))
        thread.start()