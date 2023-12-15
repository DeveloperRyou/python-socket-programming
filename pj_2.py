
import os
from threading import TIMEOUT_MAX
from tkinter.messagebox import NO
# from turtle import st

from config import *
from collections.abc import Callable

import struct
from typing import Tuple, Any

from time import time
from time import sleep

from tkinter import END


UDP_WINDOW_SIZE = 100
UDP_MAX_ACK_NUM = int(2**16)
UDP_TIMEOUT = 5
UDP_WAIT = 0.05

PACKET_TYPE_FILE_START = b'\x00'
PACKET_TYPE_FILE_DATA = b'\x01'
PACKET_TYPE_FILE_END = b'\x02'
PACKET_TYPE_FILE_ACK = b'\x03'

TCP_FILE_TRANSFER_END = PACKET_TYPE_FILE_END + bytes(PACKET_SIZE-1) # TCP에서의 파일 전송 종료를 알리기 위한 패킷


class FileTransfer:
    def __init__(self) -> None:
        self.file_pointer = None
        self.udp_recv_packet = [bytes(PACKET_SIZE) for _ in range(UDP_MAX_ACK_NUM)]
        self.udp_recv_flag = [False for _ in range(UDP_MAX_ACK_NUM)]
        self.udp_send_packet = dict()
        self.udp_ack_windows = [False for _ in range(UDP_MAX_ACK_NUM)]
        self.udp_ack_num = 0
        self.udp_last_ack_num = 0
        self.file_packet_start = 0
        self.file_name = None

    @staticmethod
    def tcp_packet_pack(packet_type: bytes, data: bytes) -> bytes:
        data_len = len(data)
        packet = packet_type + struct.pack(">H", data_len) + data
        packet = packet + bytes(PACKET_SIZE - len(packet)) # packet 크기 맞추기
        return packet
    
    @staticmethod
    def tcp_packet_unpack(packet: bytes) -> Tuple[bytes, bytes]:
        packet_type = packet[:1]
        data_len = struct.unpack(">H", packet[1:3])[0]
        data = packet[3:3+data_len]
        return packet_type, data

    @staticmethod
    def udp_packet_pack(packet_type: bytes, ack_num: Any, data: bytes) -> bytes:
        data_len = len(data)
        if type(ack_num) == int:
            packet = packet_type + struct.pack(">HH", ack_num, data_len) + data
        elif type(ack_num) == bytes:
            packet = packet_type + ack_num + struct.pack(">H", data_len) + data
        packet = packet + bytes(PACKET_SIZE - len(packet)) # packet 크기 맞추기
        return packet
    
    @staticmethod
    def udp_packet_unpack(packet: bytes) -> Tuple[bytes, int, bytes]:
        packet_type = packet[:1]
        ack_num, data_len = struct.unpack(">HH", packet[1:5])
        data = packet[5:5+data_len]
        return packet_type, ack_num, data

    @staticmethod
    def udp_ack_bytes(packet: bytes) -> bytes:
        return packet[1:3]

    def tcp_file_name_packet(self, file_name: str) -> bytes:
        # TCP 통신에서의 file 이름 전송용 패킷 생성 
        # 패킷 구조: \x00 + (이름 data 크기) + (파일 이름 data)
        data = file_name.encode(ENCODING)
        return self.tcp_packet_pack(PACKET_TYPE_FILE_START, data)

    
    def tcp_file_data_packet(self) -> Tuple[bool, bytes]:
        # tcp sener가 가진 self.file_pointer에서
        # 전송을 위한 packet을 생성한다,
        # 결과값: 패킷이 존재 여부, 생성된 패킷
        # 패킷 구조: \x01 + (data 크기) + (file data)
        data = self.file_pointer.read(PACKET_SIZE -1 -2)
        if data:
            return True, self.tcp_packet_pack(PACKET_TYPE_FILE_DATA, data)
        else:
            return False, None
    
    def udp_file_data(self) -> Tuple[bool, bytes]:
        # udp sener가 전송할 file data를 얻는다
        # 결과값: file data
        data = self.file_pointer.read(PACKET_SIZE -1 -2 -2)
        if data:
            return True, data
        else:
            return False, None

    def tcp_file_name_transfer(self, filename: str, tcp_send_func: Callable)-> None:
        # TCP 통신에서 sender에게 파일 전송이 시작을 알리면서 파일 이름을 전송한다.
        packet = self.tcp_file_name_packet(filename)
        tcp_send_func(packet)

    def tcp_file_send(self, filename: str, tcp_send_func: Callable)-> None:
        basename = os.path.basename(filename)
        self.file_pointer = open(filename, "rb")

        # packet의 파일 이름(basename)을 전송한다.
        self.tcp_file_name_transfer(basename, tcp_send_func)
        # 이름 전송 종료

        # 파일을 구성하는 data를 전송한다.
        while True: # data가 존재하는 동안 반복
            is_data_ready, packet = self.tcp_file_data_packet()
            if is_data_ready == False:
                break
            tcp_send_func(packet)
        # 파일 data 전송 종료

        # TCP_FILE_TRANSFER_END을 전송하여 
        # 파일의 전송이 끝냈음을 알린다.
        tcp_send_func(TCP_FILE_TRANSFER_END)
        # TCP_FILE_TRANSFER_END을 전송 종료
        
        # 파일 닫기
        self.file_pointer.close()
        self.file_pointer = None
        
            
    def tcp_file_receive(self, packet) -> int:
        packet_type, data = self.tcp_packet_unpack(packet)

        if packet_type == PACKET_TYPE_FILE_START:
            basename = data.decode(ENCODING)
            self.file_name = basename
            try:
                if not os.path.exists('./downloads'):
                    os.makedirs('./downloads')
            except OSError:
                print('Error: Creating directory. ' + './downloads')
            file_path = './downloads/(tcp) '+basename
            # 파일의 이름을 받아 file_path 위치에 self.file_pointer를 생성한다.
            self.file_pointer = open(file_path, "wb")
            return 0

        elif packet_type == PACKET_TYPE_FILE_DATA:
            # self.file_pointer에 전송 받은 data를 저장한다.
            self.file_pointer.write(data)
            return 1
            
        elif packet_type == PACKET_TYPE_FILE_END:
            # 파일 전송이 끝난 것을 확인하고 file_pointer를 종료한다.
            self.file_pointer.close()
            self.file_pointer = None
            return 2

    def udp_file_name_transfer(self, file_name: str, udp_send_func: Callable)-> None:
        data = file_name.encode(ENCODING)
        self.udp_send_with_record(PACKET_TYPE_FILE_START, data, udp_send_func)

    def udp_send_with_record(self, packet_type: bytes, data: bytes, udp_send_func: Callable) -> None:
        packet = self.udp_packet_pack(packet_type, self.udp_last_ack_num, data)
        udp_send_func(packet)
        self.udp_send_packet[self.udp_last_ack_num] = (time(), packet)
        self.udp_last_ack_num = (self.udp_last_ack_num + 1) % UDP_MAX_ACK_NUM

    def udp_file_send(self, filename: str, udp_send_func: Callable) -> None:
        basename = os.path.basename(filename)
        self.file_pointer = open(filename, "rb")

        # udp를 통해 파일의 basename을 전송하고 ack를 기다린다.
        self.udp_file_name_transfer(basename, udp_send_func)
        while len(self.udp_send_packet) > 0:
            if self.udp_time_out():
                self.udp_pipeline(udp_send_func)
            else:
                sleep(UDP_WAIT)
        
        data_ready, data = self.udp_file_data()
        while data_ready:
            if len(self.udp_send_packet) < UDP_WINDOW_SIZE: #window의 크기보다 전송한 패킷의 양의 적은 경우
                # print("send file data, ack :", self.udp_last_ack_num)
                self.udp_send_with_record(PACKET_TYPE_FILE_DATA, data, udp_send_func)
                data_ready, data = self.udp_file_data() # 다음 전송할 data를 준비한다.
            else:
                if self.udp_time_out():
                    self.udp_pipeline(udp_send_func)
                else:
                    sleep(UDP_WAIT)

        # 모든 파일 data의 ack를 기다리고 timeout에 대처한다.
        while len(self.udp_send_packet) > 0:
            if self.udp_time_out():
                self.udp_pipeline(udp_send_func)
            else:
                sleep(UDP_WAIT)

        # 파일 전송이 완료되었음을 알리고 ack에 대비한다.
        self.udp_send_with_record(PACKET_TYPE_FILE_END, b'', udp_send_func)
        while len(self.udp_send_packet) > 0:
            if self.udp_time_out():
                self.udp_pipeline(udp_send_func)
            else:
                sleep(UDP_WAIT)
        
        # 파일 포인터를 제거한다.
        self.file_pointer.close()
        self.file_pointer = None
            
    def udp_file_receive(self, packet: bytes, udp_send_func: Callable) -> int:
        ack_bytes = self.udp_ack_bytes(packet)
        packet_type, ack_num, data = self.udp_packet_unpack(packet)

        if packet_type != PACKET_TYPE_FILE_ACK:
            # print("receive packet, ack :", ack_num)
            self.udp_ack_send(ack_bytes, udp_send_func)

        if packet_type == PACKET_TYPE_FILE_START:  # file transfer start
            if self.file_pointer is not None:
                self.file_pointer.close()

            basename = data.decode(ENCODING)
            self.file_name = basename
            try:
                if not os.path.exists('./downloads'):
                    os.makedirs('./downloads')
            except OSError:
                print('Error: Creating directory. ' + './downloads')
            file_path = './downloads/(udp) '+basename
            self.file_pointer = open(file_path, "wb")
            self.file_packet_start = ack_num + 1
            return 0

        elif packet_type == PACKET_TYPE_FILE_DATA:  # file transfer
            if not self.udp_recv_flag[ack_num]:
                self.udp_recv_packet[ack_num] = data
                self.udp_recv_flag[ack_num] = True
            
            if self.udp_recv_flag[self.file_packet_start]:
                while self.udp_recv_flag[self.file_packet_start]:
                    self.file_pointer.write(self.udp_recv_packet[self.file_packet_start])
                    self.udp_recv_flag[self.file_packet_start] = False
                    self.udp_recv_packet[self.file_packet_start] = bytes(PACKET_SIZE)
                    self.file_packet_start = (self.file_packet_start + 1) % UDP_MAX_ACK_NUM
            return 1

            
        elif packet_type == PACKET_TYPE_FILE_END:  # file transfer end
            # 파일 전송이 끝난 것을 확인하고 파일을 종료한다.
            if self.file_pointer is not None:
                self.file_pointer.close()
                self.file_pointer = None
            return 2
        
        elif packet_type == PACKET_TYPE_FILE_ACK:  # ack
            # print("receive ack :", ack_num)
            # GBN, SR을 위해 self.udp_ack_windows를 update한다.
            if ack_num == self.udp_ack_num:
                self.udp_ack_windows[ack_num] = True
                while self.udp_ack_windows[self.udp_ack_num]:
                    self.udp_ack_windows[self.udp_ack_num] = False
                    try:
                        del self.udp_send_packet[self.udp_ack_num]
                        self.udp_ack_num = (self.udp_ack_num + 1) % UDP_MAX_ACK_NUM
                    except KeyError:
                        continue
            return 1
        return 1

    def udp_time_out(self) -> bool:
        try:
            if time() - self.udp_send_packet[self.udp_ack_num][0] > UDP_TIMEOUT: # timeout
                print("timeout, ack :", self.udp_ack_num)
                return True
            else:
                return False
        except KeyError:
            return False

    def udp_pipeline(self, udp_send_func: Callable) -> None:
        # GBN, SR 중 하나의 알고리즘을 선택하여 ACK를 관리한다.
        def udp_gbn():
            # GBN 으로 전송한다.
            for idx in range(self.udp_ack_num, self.udp_last_ack_num):
                try:
                    udp_send_func(self.udp_send_packet[idx][1])
                    self.udp_send_packet[idx] = (time(), self.udp_send_packet[idx][1])
                except KeyError:
                    continue
        udp_gbn()

    def udp_ack_send(self, ack_bytes: bytes, udp_send_func: Callable):
        packet = PACKET_TYPE_FILE_ACK + ack_bytes
        packet = self.udp_packet_pack(PACKET_TYPE_FILE_ACK, ack_bytes, b'')
        udp_send_func(packet)
