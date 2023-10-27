from time import sleep
from tkinter import *
import tkinter
from tkinter.tix import COLUMN
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

    def chat_close():
        op_man.close()
        chat_window.destroy()
    close_btn = Button(upper_right_frame, text="Close", command=chat_close)
    close_btn.place(relheight=0.1, relwidth=1, relx=0., rely=0.05)
    

    msg_txt_box = Text(bottom_left_frame, bg=TXT_BOX_BG, fg=TXT_BOX_TEXT_COLOR, insertbackground=TXT_BOX_TEXT_COLOR)
    msg_txt_box.place(relheight=1,relwidth=1)

    op_man.tcp_txt_box_thread(tcp_txt_box)
    op_man.udp_txt_box_thread(udp_txt_box)

    send_radio_value = IntVar(chat_window)
    radio_tcp = Radiobutton(upper_right_frame, text=BTN_SEND_TCP_TXT, value=0, variable=send_radio_value)
    radio_udp = Radiobutton(upper_right_frame, text=BTN_SEND_UDP_TXT, value=1, variable=send_radio_value)
    radio_both = Radiobutton(upper_right_frame, text=BTN_SEND_BOTH_TXT, value=2, variable=send_radio_value)
    

    def send_msg()->None:
        send_opt = int(send_radio_value.get())
        msg = msg_txt_box.get(1.0, END)
        reset_text_box(msg_txt_box)

        if send_opt in (0, 2):
            tcp_txt_box.insert(END, time.strftime("(send) %H:%M -> ") + msg)
        if send_opt in (1, 2):
            udp_txt_box.insert(END, time.strftime("(send) %H:%M -> ") + msg)

        op_man.send_msg_func(send_opt, msg)

    radio_tcp.place(relwidth=1, relx=0, rely=0.85)
    radio_udp.place(relwidth=1, relx=0, rely=0.9)
    radio_both.place(relwidth=1, relx=0, rely=0.95)

    send = Button(bottom_right_frame, text=SEND_BTN_TXT, command=send_msg)
    send.place(relheight=1, relwidth=1, relx=0., rely=0.)
    chat_window.update()

    start_window.destroy()
    chat_window.mainloop()


    

def create_start_window():
    global start_window
    global conn_flag
    conn_flag = True
    start_window = Tk()   # user interface
    start_window.title(GUI_TITLE)
    start_window.resizable(False, False)

    title_label = Label(start_window, text=TITLE_LABEL)
    

    radio_value = IntVar()
    radio_server = Radiobutton(start_window, text="Server", value=0, variable=radio_value)
    radio_client = Radiobutton(start_window, text="Client", value=1, variable=radio_value)
    host_label = Label(start_window, text=IP_LABEL)

    title_entry = Entry(start_window, width=41)
    title_entry.bind("<Button-1>",lambda event: reset_entry(title_entry))
    host = Entry(start_window,width=41)
    host.bind("<Button-1>",lambda event: reset_entry(host))
    tcp_label = Label(start_window, text=TCP_PORT_LABEL)
    tcp_port = Entry(start_window)
    tcp_port.bind("<Button-1>",lambda event: reset_entry(tcp_port))
    udp_label = Label(start_window, text=UDP_PORT_LABEL)
    udp_port = Entry(start_window)
    udp_port.bind("<Button-1>",lambda event: reset_entry(udp_port))
    

    conn_btn = Button(start_window, text="Connect")
    op_man = OperationManager()
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
                    thr = op_man.open_server(host.get(), int(tcp_port.get()), int(udp_port.get()))
                    
                elif check_value == 1:
                    thr = op_man.open_client(host.get(), int(tcp_port.get()), int(udp_port.get()))
                    
                thr.join()
                create_chat_window(title_entry.get(), op_man)

    start_window.bind("<Return>", connect)
    conn_btn.bind("<Button-1>", connect)


    radio_server.grid(row=0, column=0)
    radio_client.grid(row=0, column=1)

    host_label.grid(row=1, column=0, columnspan=2)
    host.grid(row=2, column=0, columnspan=2)
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
    title_entry.insert(0, GUI_TITLE)

    start_window.update()
    sleep(1)
    start_window.mainloop()
    


if __name__=="__main__":
    create_start_window()
