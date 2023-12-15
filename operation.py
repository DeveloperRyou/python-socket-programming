import struct
from threading import Thread
from time import sleep
from pj_1 import NetworkSocket
from pj_2 import FileTransfer
from pj_3 import ARPTable
from config import *
from tkinter import END
import time
import sys



class OperationManager:
    def __init__(self) -> None:
        self.network_socket = NetworkSocket()
        self.file_transper = FileTransfer()
        self.arp_table = ARPTable()
        self.is_client = None
        self.server_open_thr = None
        self.tcp_box_thread = None
        self.udp_box_thread = None
        
        self.tcp_thr_flag = True
        self.udp_thr_flag = True

        self.tcp_box = None
        self.udp_box = None
    
    def open_server(self, host: str, tcp_port: int, udp_port: int) -> Thread:
        if host == DEFAULT_IP:
            host = DEFAULT_SERVER_BIND
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.connection_thread = Thread(target=self.network_socket.server_open_func, args=(host, tcp_port, udp_port))
        self.connection_thread.daemon = True
        self.connection_thread.start()
        return self.connection_thread

    def open_client(self, host: str, tcp_port: int, udp_port: int) -> Thread:
        if host == DEFAULT_IP:
            host = DEFAULT_CLIENT_BIND
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        def while_conn(network_class, host, tcp_port, udp_port):
            while True:
                output = network_class.client_connect_func(host, tcp_port, udp_port)
                if output == 0:
                    break
                elif output == -1:
                    sleep(1)
        self.connection_thread = Thread(target=while_conn, args=(self.network_socket, host, tcp_port, udp_port))
        self.connection_thread.daemon = True
        self.connection_thread.start()
        return self.connection_thread

    def tcp_recv_thread(self, tcp_txt_box) -> None:
        def tcp_recv_data():
            tcp_delayed_buffer = None
            while self.tcp_thr_flag:
                if sys.version_info[0] >= 3 and sys.version_info[1] >= 8:
                    alive = self.connection_thread.is_alive()
                else:
                    alive = self.connection_thread.isAlive()
                while alive:
                    sleep(0.01)
                    if sys.version_info[0] >= 3 and sys.version_info[1] >= 8:
                        alive = self.connection_thread.is_alive()
                    else:
                        alive = self.connection_thread.isAlive()
                try:
                    if tcp_delayed_buffer:
                        data = tcp_delayed_buffer
                    else:
                        data = self.network_socket.tcp_recv()

                    while len(data) < PACKET_SIZE + APP_HEADER_LEN:
                        data = data + self.network_socket.tcp_recv()

                    if len(data) > PACKET_SIZE + APP_HEADER_LEN:
                        tcp_delayed_buffer = data[PACKET_SIZE + APP_HEADER_LEN:]
                        data = data[:PACKET_SIZE + APP_HEADER_LEN]
                    else:
                        tcp_delayed_buffer = None

                    if len(data) > 0:
                        app_header = data[:APP_HEADER_LEN]
                        app_data = data[APP_HEADER_LEN:]
                        if app_header == TYPE_TEXT_MSG:
                            data_len = struct.unpack(">H", app_data[:2])[0]
                            app_data = app_data[2:2+data_len]
                            text = app_data.decode(ENCODING)
                            tcp_txt_box.insert(END, time.strftime("(recv) %H:%M:%S -> ") + text)
                            tcp_txt_box.update()
                        elif app_header == TYPE_FILE_TRANSFER:
                            cpl_flag = self.file_transper.tcp_file_receive(app_data)
                            if cpl_flag == 0:
                                tcp_txt_box.insert(END, time.strftime("(file recv start) %H:%M:%S\n"))
                                tcp_txt_box.update()
                            
                            elif cpl_flag == 2:
                                tcp_txt_box.insert(END, time.strftime("(file recv end) %H:%M:%S\n"))
                                self.file_transper.file_name = None
                                tcp_txt_box.update()
                except OSError:
                    break
        self.tcp_thr_flag = True
        self.tcp_box_thread = Thread(target=tcp_recv_data)
        self.tcp_box_thread.daemon = True
        self.tcp_box_thread.start()

    def udp_recv_thread(self, udp_txt_box) -> None:
        def udp_recv_data():  # add delayed buffer???
            udp_delayed_buffer = None
            while self.udp_thr_flag:
                if sys.version_info[0] >= 3 and sys.version_info[1] >= 8:
                    alive = self.connection_thread.is_alive()
                else:
                    alive = self.connection_thread.isAlive()
                while alive:
                    sleep(0.01)
                    if sys.version_info[0] >= 3 and sys.version_info[1] >= 8:
                        alive = self.connection_thread.is_alive()
                    else:
                        alive = self.connection_thread.isAlive()
                try:
                    if udp_delayed_buffer:
                        data = udp_delayed_buffer
                    else:
                        data = self.network_socket.udp_recv()
                    while len(data) < PACKET_SIZE + APP_HEADER_LEN:
                        data = data + self.network_socket.udp_recv()
                    if len(data) > PACKET_SIZE + APP_HEADER_LEN:
                        udp_delayed_buffer = data[PACKET_SIZE + APP_HEADER_LEN:]
                        data = data[:PACKET_SIZE + APP_HEADER_LEN]
                    else:
                        udp_delayed_buffer = None

                    app_header = data[:APP_HEADER_LEN]
                    app_data = data[APP_HEADER_LEN:]
                    if len(data) > 0:
                        if app_header == TYPE_TEXT_MSG:
                            data_len = struct.unpack(">H", app_data[:2])[0]
                            app_data = app_data[2:2+data_len]
                            text = app_data.decode(ENCODING)
                            udp_txt_box.insert(END, time.strftime("(recv) %H:%M:%S -> ") + text)
                            udp_txt_box.update()
                        elif app_header == TYPE_FILE_TRANSFER:
                            cpl_flag = self.file_transper.udp_file_receive(app_data, self.udp_file_transfer_send)
                            if cpl_flag == 0:
                                udp_txt_box.insert(END, time.strftime("(file recv start) %H:%M:%S\n"))
                                self.file_transper.file_name = None
                                udp_txt_box.update()
                            elif cpl_flag == 2:
                                udp_txt_box.insert(END, time.strftime("(file recv end) %H:%M:%S\n"))
                                self.file_transper.file_name = None
                                udp_txt_box.update()
                            
                except OSError:
                    break
        self.udp_thr_flag = True
        self.udp_box_thread = Thread(target=udp_recv_data)
        self.udp_box_thread.daemon = True
        self.udp_box_thread.start()

    def send_msg_func(self, send_opt: int, msg: str, tcp_txt_box, udp_txt_box) -> None:
        data = msg.encode(ENCODING)

        while data:
            if len(data) > PACKET_SIZE - 2:
                send_data = data[:PACKET_SIZE-2]
                data = data[PACKET_SIZE-2:]
            else:
                send_data = data
                data = None
            len_data = len(send_data)
            if len_data < PACKET_SIZE-2:
                send_data = send_data + bytes(PACKET_SIZE - 2 - len_data)
            
            send_data = TYPE_TEXT_MSG + struct.pack(">H", len_data) + send_data

            if send_opt in (0, 2):
                try:
                    self.network_socket.tcp_send(send_data)
                    tcp_txt_box.insert(END, time.strftime("(send) %H:%M:%S -> ") + msg)
                except ConnectionResetError:
                    if sys.version_info[0] >= 3 and sys.version_info[1] >= 8:
                        alive = self.connection_thread.is_alive()
                    else:
                        alive = self.connection_thread.isAlive()
                    if not alive:
                        self.network_socket.close()
                        if self.is_client == 0:
                            self.connection_thread = self.open_server(self.host, self.tcp_port, self.udp_port)
                        elif self.is_client == 1:
                            self.connection_thread = self.open_client(self.host, self.tcp_port, self.udp_port)
                        self.tcp_recv_thread(tcp_txt_box)
                        self.udp_recv_thread(udp_txt_box)
                    tcp_txt_box.insert(END, time.strftime("(connection lost) %H:%M:%S\n"))
                    tcp_txt_box.update()
                except OSError as errormsg:
                    print(f"TCP Unexpected {errormsg}, {type(errormsg)}")
                    tcp_txt_box.insert(END, time.strftime("(connection lost) %H:%M:%S\n"))
                    tcp_txt_box.update()
            if send_opt in (1, 2):
                try:
                    self.network_socket.udp_send(send_data)
                    udp_txt_box.insert(END, time.strftime("(send) %H:%M:%S -> ") + msg)
                except OSError as errormsg:
                    print(f"UDP Unexpected {errormsg}, {type(errormsg)}")
                    udp_txt_box.insert(END, time.strftime("(connection lost) %H:%M:%S\n"))
                    udp_txt_box.update()
    
    def tcp_file_transfer_send(self, packet):
        # 캡슐화
        packet = TYPE_FILE_TRANSFER + packet
        self.network_socket.tcp_send(packet)

    def udp_file_transfer_send(self, packet):
        packet = TYPE_FILE_TRANSFER + packet
        self.network_socket.udp_send(packet)

    def send_file_func(self, send_opt: int, filename: str, tcp_txt_box, udp_txt_box) -> None:
        if send_opt == 0:
            tcp_txt_box.insert(END, time.strftime("(file send start) %H:%M:%S\n"))
            tcp_txt_box.update()
            self.file_transper.tcp_file_send(filename, tcp_send_func=self.tcp_file_transfer_send)
            tcp_txt_box.insert(END, time.strftime("(file send end) %H:%M:%S\n"))
            tcp_txt_box.update()
        elif send_opt == 1:
            udp_txt_box.insert(END, time.strftime("(file send start) %H:%M:%S\n"))
            udp_txt_box.update()
            self.file_transper.udp_file_send(filename, udp_send_func=self.udp_file_transfer_send)
            udp_txt_box.insert(END, time.strftime("(file send end) %H:%M:%S\n"))
            udp_txt_box.update()
        else:
            tcp_txt_box.insert(END, time.strftime("(file send start) %H:%M:%S\n"))
            tcp_txt_box.update()
            self.file_transper.tcp_file_send(filename, tcp_send_func=self.tcp_file_transfer_send)
            tcp_txt_box.insert(END, time.strftime("(file send end) %H:%M:%S\n"))
            tcp_txt_box.update()
            sleep(1.)
            udp_txt_box.insert(END, time.strftime("(file send start) %H:%M:%S\n"))
            udp_txt_box.update()
            self.file_transper.udp_file_send(filename, udp_send_func=self.udp_file_transfer_send)
            udp_txt_box.insert(END, time.strftime("(file send end) %H:%M:%S\n"))
            udp_txt_box.update()

    def close(self):
        self.tcp_thr_flag = False
        self.udp_thr_flag = False
        self.network_socket.close()
