from time import sleep
from tkinter import *
from tkinter import filedialog

if __name__=="__main__" or __name__=="decimal":
    from config import *
    from operation import *
else:
    from .config import *
    from .operation import *


def reset_entry(tk_obj):
    tk_obj.delete(0, END)
    tk_obj.insert(0, "")


def reset_text_box(tk_obj):
    tk_obj.delete(1.0, END)
    tk_obj.insert(1.0, "")


def create_chat_window(title: str, op_man: OperationManager) -> None:
    global chat_window
    chat_window = Tk()   # user interface
    chat_window.title(title)
    chat_window.geometry("1080x760")
    chat_window.resizable(False, False)


    upper_frame = Frame(chat_window)
    upper_frame.place(relheight=0.85, relwidth=1., rely=0.)
    bottom_frame = Frame(chat_window)
    bottom_frame.place(relheight=0.15, relwidth=1., rely=0.85)

    upper_left_frame = Frame(upper_frame)
    upper_left_frame.place(relheight=1., relwidth=0.9, relx=0.)
    upper_right_frame = Frame(upper_frame)
    upper_right_frame.place(relheight=1., relwidth=0.1, relx=0.9)

    bottom_left_frame = Frame(bottom_frame)
    bottom_left_frame.place(relheight=1., relwidth=0.9, relx=0.)
    bottom_right_frame = Frame(bottom_frame)
    bottom_right_frame.place(relheight=1., relwidth=0.1, relx=0.9)

    label_tcp = Label(upper_left_frame, text=TCP_LABEL)
    label_tcp.place(relwidth=0.5, relx=0., rely=0.005)
    tcp_txt_box = Text(upper_left_frame, bg=TXT_BOX_BG, fg=TXT_BOX_TCP_TXT_COLOR)
    tcp_txt_box.place(relheight=0.95, relwidth=0.5, relx=0., rely=0.05)
    tcp_scrollbar = Scrollbar(tcp_txt_box)
    tcp_scrollbar.place(relheight=1, relx=0.974)

    label_udp = Label(upper_left_frame, text=UDP_LABEL)
    label_udp.place(relwidth=0.5, relx=0.5, rely=0.005)
    udp_txt_box = Text(upper_left_frame, bg=TXT_BOX_BG, fg=TXT_BOX_UDP_TXT_COLOR)
    udp_txt_box.place(relheight=0.95, relwidth=0.5, relx=0.5, rely=0.05)
    udp_scrollbar = Scrollbar(udp_txt_box)
    udp_scrollbar.place(relheight=1, relx=0.974)

    send_radio_value = IntVar(chat_window)
    radio_tcp = Radiobutton(upper_right_frame, text=BTN_SEND_TCP_TXT, value=0, variable=send_radio_value)
    radio_udp = Radiobutton(upper_right_frame, text=BTN_SEND_UDP_TXT, value=1, variable=send_radio_value)
    radio_both = Radiobutton(upper_right_frame, text=BTN_SEND_BOTH_TXT, value=2, variable=send_radio_value)

    def chat_close():
        op_man.close()
        start_window.destroy()
        chat_window.destroy()
    close_btn = Button(upper_right_frame, text="Close", command=chat_close)
    close_btn.place(relheight=0.1, relwidth=1, relx=0., rely=0.05)

    def file_upload():
        filename = filedialog.askopenfilename(parent=chat_window)
        send_opt = int(send_radio_value.get())
        # print("filename")
        if filename != '': 
            # select file
            op_man.send_file_func(send_opt, filename, tcp_txt_box, udp_txt_box)

    file_upload_btn = Button(upper_right_frame, text="File Upload", command=file_upload)
    file_upload_btn.place(relheight=0.1, relwidth=1, relx=0., rely=0.16)

    msg_txt_box = Text(bottom_left_frame, bg=TXT_BOX_BG, fg=TXT_BOX_TEXT_COLOR, insertbackground=TXT_BOX_TEXT_COLOR)
    msg_txt_box.place(relheight=1,relwidth=1)

    op_man.tcp_recv_thread(tcp_txt_box)
    op_man.udp_recv_thread(udp_txt_box)

    def send_msg()->None:
        send_opt = int(send_radio_value.get())
        msg = msg_txt_box.get(1.0, END)
        reset_text_box(msg_txt_box)

        op_man.send_msg_func(send_opt, msg, tcp_txt_box, udp_txt_box)

    radio_tcp.place(relwidth=1, relx=0, rely=0.85)
    radio_udp.place(relwidth=1, relx=0, rely=0.9)
    radio_both.place(relwidth=1, relx=0, rely=0.95)

    send = Button(bottom_right_frame, text=SEND_BTN_TXT, command=send_msg)
    send.place(relheight=1, relwidth=1, relx=0., rely=0.)
    chat_window.update()

    start_window.withdraw()
    chat_window.mainloop()


def create_start_window():
    global start_window
    global conn_flag
    global scan_window
    conn_flag = True
    start_window = Tk()   # user interface
    start_window.title(GUI_TITLE)
    start_window.resizable(False, False)
    scan_window = None
    op_man = OperationManager()

    title_label = Label(start_window, text=TITLE_LABEL)
    

    radio_value = IntVar()
    radio_server = Radiobutton(start_window, text="Server", value=0, variable=radio_value)
    radio_client = Radiobutton(start_window, text="Client", value=1, variable=radio_value)
    host_label = Label(start_window, text=IP_LABEL)

    title_entry = Entry(start_window, width=41)
    title_entry.bind("<Button-1>",lambda event: reset_entry(title_entry))
    host = Entry(start_window,width=35)
    host.bind("<Button-1>",lambda event: reset_entry(host))
    tcp_label = Label(start_window, text=TCP_PORT_LABEL)
    tcp_port = Entry(start_window)
    tcp_port.bind("<Button-1>",lambda event: reset_entry(tcp_port))
    udp_label = Label(start_window, text=UDP_PORT_LABEL)
    udp_port = Entry(start_window)
    udp_port.bind("<Button-1>",lambda event: reset_entry(udp_port))
    
    def ip_scan():
        global scan_window
        if scan_window is not None:
            try:
                scan_window.deiconify()
            except TclError:
                scan_window = None

        if scan_window is None:
            scan_window = Tk()
            scan_window.title("ARP Scanning")
            scan_range_label = Label(scan_window, text="scan ip range")
            scan_interface_label = Label(scan_window, text="interface name")
            scan_range = Entry(scan_window, width=20)
            default_ips, default_nif = op_man.arp_table.default_ip_nif()
            scan_range.insert(0, default_ips+"/24")
            scan_interface = Entry(scan_window, width=20)
            
            scan_interface.insert(0, default_nif)
            ip_label = Label(scan_window, text="IP address list")
            ip_list = Listbox(scan_window, selectmode="SINGLE", width=40, height=20)

            if len(op_man.arp_table.ARP_table) > 0:
                ip_list.delete(0,END)
                for idx, values in enumerate(op_man.arp_table.ARP_table):
                    ip_list.insert(idx, "{} ({})".format(*values))

            def arp_scan():
                ip_list.delete(0,END)
                ip_list.insert(0, "ARP Table Scanning...")
                ip_list.update()
                nic = scan_interface.get()
                op_man.arp_table.get_ARP_table(interface=nic, ips=scan_range.get())
                ip_list.delete(0,END)
                for idx, values in enumerate(op_man.arp_table.ARP_table):
                    ip_list.insert(idx, "{} ({})".format(*values))
                op_man.arp_table.interface = nic
            scan_start_btn = Button(scan_window, text="Scan Start", command=arp_scan)
            def select_ip():
                reset_entry(host)
                ip_idx = ip_list.curselection()[0]
                op_man.arp_table.selected_idx = ip_idx
                ip_addr = op_man.arp_table.ARP_table[ip_idx][0]
                host.insert(0, ip_addr)
                host.update()
                scan_window.destroy()
            select_btn = Button(scan_window, text="Select", command=select_ip)
            ip_scrollbar = Scrollbar(ip_list)
            scan_range_label.grid(row=0, column=0)
            scan_interface_label.grid(row=0, column=1)
            scan_range.grid(row=1, column=0)
            scan_interface.grid(row=1, column=1)
            ip_label.grid(row=2, columnspan=2)
            ip_list.grid(row=3, columnspan=2)
            ip_scrollbar.place(relheight=1, relx=0.96)
            scan_start_btn.grid(row=4, column=0)
            select_btn.grid(row=4, column=1)
        
        
        scan_window.mainloop()
    scan_btn = Button(start_window, text="IP Scan", width=5, command=ip_scan)
    conn_btn = Button(start_window, text="Connect")
    
    def connect(event):
        global conn_flag
        if conn_flag:
            conn_flag = False
            if conn_btn['state'] != 'disabled':
                check_value = radio_value.get()
                radio_server['state']='disabled'
                radio_client['state']='disabled'
                host['state']='disabled'
                tcp_port['state']='disabled'
                udp_port['state']='disabled'
                conn_btn['text']='wait connection'
                conn_btn['state']='disabled'
                title_entry['state']='disabled'

                start_window.update()
                if check_value == 0:
                    op_man.is_client = 0
                    connection_thread = op_man.open_server(host.get(), int(tcp_port.get()), int(udp_port.get()))
                    
                elif check_value == 1:
                    op_man.is_client = 1
                    connection_thread = op_man.open_client(host.get(), int(tcp_port.get()), int(udp_port.get()))
                connection_thread.join()
                # op_man.arp_table.save_mac(host.get())
                create_chat_window(title_entry.get(), op_man)

    start_window.bind("<Return>", connect)
    conn_btn.bind("<Button-1>", connect)


    radio_server.grid(row=0, column=0)
    radio_client.grid(row=0, column=1)

    host_label.grid(row=1, column=0, columnspan=2)
    host.grid(row=2, column=0, columnspan=2, sticky='w')
    scan_btn.grid(row=2, column=0, columnspan=2, sticky='e')
    tcp_label.grid(row=3, column=0)
    tcp_port.grid(row=4, column=0)
    udp_label.grid(row=3, column=1)
    udp_port.grid(row=4, column=1)
    title_label.grid(row=5, column=0, columnspan=2)
    title_entry.grid(row=6, column=0, columnspan=2)
    conn_btn.grid(row=7, column=0, columnspan=2)

    host.insert(0, DEFAULT_IP)
    tcp_port.insert(0, DEFAULT_TCP_PORT)
    udp_port.insert(0, DEFAULT_UDP_PORT)
    title_entry.insert(0, "Write Your Team Name")

    start_window.update()
    sleep(1)
    start_window.mainloop()
    


if __name__=="__main__":
    create_start_window()
