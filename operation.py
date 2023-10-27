from threading import Thread
from time import sleep
from pj_1 import NetworkSocket
from config import *
from tkinter import END
import time



class OperationManager:
    def __init__(self) -> None:
        self.network_socket = NetworkSocket()
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
        
        thr = Thread(target=self.network_socket.server_open_func, args=(host, tcp_port, udp_port))
        thr.daemon = True
        thr.start()
        return thr

    def open_client(self, host: str, tcp_port: int, udp_port: int) -> Thread:
        if host == DEFAULT_IP:
            host = DEFAULT_CLIENT_BIND
        thr = Thread(target=self.network_socket.client_connect_func, args=(host, tcp_port, udp_port))
        thr.daemon = True
        thr.start()
        return thr

    def tcp_txt_box_thread(self, tcp_txt_box) -> None:
        def tcp_recv_data():
            while self.tcp_thr_flag:
                try:
                    data = self.network_socket.tcp_recv()
                    if len(data) > 0:
                        text = data.decode(ENCODING)
                        tcp_txt_box.insert(END, time.strftime("(recv) %H:%M -> ") + text)
                        tcp_txt_box.update()
                except OSError:
                    break
        self.tcp_thr_flag = True
        self.tcp_box_thread = Thread(target=tcp_recv_data)
        self.tcp_box_thread.daemon = True
        self.tcp_box_thread.start()

    def udp_txt_box_thread(self, udp_txt_box) -> None:
        def udp_recv_data():
            while self.udp_thr_flag:
                try:
                    data = self.network_socket.udp_recv()
                    if len(data) > 0:
                        text = data.decode(ENCODING)
                        udp_txt_box.insert(END, time.strftime("(recv) %H:%M -> ") + text)
                        udp_txt_box.update()
                except OSError:
                    break
        self.udp_thr_flag = True
        self.udp_box_thread = Thread(target=udp_recv_data)
        self.udp_box_thread.daemon = True
        self.udp_box_thread.start()

    def send_msg_func(self, send_opt: int, msg) -> None:
        data = msg.encode(ENCODING)
        if send_opt in (0, 2):
            self.network_socket.tcp_send(data)
        if send_opt in (1, 2):
            self.network_socket.udp_send(data)

    def close(self):
        self.tcp_thr_flag = False
        self.udp_thr_flag = False
        self.network_socket.close()
