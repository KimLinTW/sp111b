#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import os


#HOST = '192.168.245.128'
HOST = '192.168.1.109'
PORT = 7000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

record = ""
os.system("clear")
user_name = input("Ոݔ��������Q:")
s.send(user_name.encode())
os.system("clear")
print(record)


def handle_send():
    global record,user_name
    while True:
        outdata = input(f'({user_name})ݔ��ӍϢ\t: ')
        outdata = f"{user_name}\t: {outdata}"
        if "exit" in outdata:
            s.send(f"{user_name}\t: exit".encode())
        else:
            try:
                s.send(outdata.encode())
            except:
                t1.do_run = False
                t2.do_run = False
                break

            record += f"{outdata}\n"
            os.system("clear")
            print(record)

def handle_recv():
    global record, user_name,t1,t2
    while True:
        indata = s.recv(4096).decode()

        if f"kick {user_name}" in indata:
            s.close()
            os.system("clear")
            print('�㱻�߳���������!')
            t1.do_run = False
            t2.do_run = False
            break

        elif f"exit {user_name}" in indata:
            a = indata
            s.close()
            os.system("clear")
            print('���x�_��������!')
            print(a)
            t1.do_run = False
            t2.do_run = False
            break


        elif "!" in indata and indata[0:1:]=='!':
            who = indata[1::].split("\t: ")[0]
            if who != user_name:
                record += indata[1::]
                os.system("clear")
                print(record)
        else:
            try:
                who = indata.split("\t: ")[0]
                say = indata.split("\t: ")[1]
                record += f"{who}\t: {say}\n"
                os.system("clear")
                print(record)
            except:
                pass

t1 = threading.Thread(target=handle_send, args=())
t1.start()
t2 = threading.Thread(target=handle_recv, args=())
t2.start()
