#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import threading
import os

HOST = '0.0.0.0'
PORT = 7000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(5)

list_of_clients=[]
list_of_user=[]
record = ""
os.system("clear")
print('等待其他人加入聊天室')

def handle_recv(conn):
    global record, list_of_clients, list_of_user
    while True:
        try:
            indata = conn.recv(4096).decode()
            who = indata.split("\t: ")[0]
            say = indata.split("\t: ")[1]
            #record += f"who:{who} say:{say}\n"

            if say == "exit":
                conn.send(f"exit {who}".encode())
                #record += f'send:exit {who}'
                list_of_clients.pop(list_of_user.index(who))
                list_of_user.remove(who)
                conn.close()

                os.system("clear")
                record += f"---- {who_join}離開了聊天室 ----"
                print(record)

            os.system("clear")
            record += f"{who}\t: {say}\n"
            print(record)
            tmp = "!"+who+'\t: '+say+'\n'
            for conn in list_of_clients:
                conn.send(tmp.encode())
        except:
            pass

def handle_send(conn):
    global record, list_of_clients, list_of_user
    while True:
        outdata = "server\t: "+input("(server)輸入訊息   : ")
        if "print" in outdata:
            record += f"{list_of_clients}\n"
            record += f"{list_of_user}\n"
            os.system("clear")
            print(record)
        elif "kick" in outdata:
            for conn in list_of_clients:
                conn.send(outdata.encode())
            record += f"{list_of_clients}\n"
            tmp = outdata.split(" ")
            who = outdata.split(" ")[-1]
            record += f"who={who}"
            outdata = f"!{who} was kicked."
            for conn in list_of_clients:
                conn.send(outdata.encode())
            os.system("clear")
            print(record)
            list_of_clients.pop(list_of_user.index(who))
            list_of_user.remove(who)
        else:
            for conn in list_of_clients:
                conn.send(outdata.encode())
            os.system("clear")
            record += outdata+'\n'
            print(record)



while True:
    client, addr = s.accept()
    who_join = client.recv(4096).decode()
    list_of_clients.append(client)
    list_of_user.append(who_join)
    os.system("clear")
    record += f"---- {who_join}加入了聊天室 ----\n"
    print(record)
    threading.Thread(target=handle_send, args=(client,)).start()
    threading.Thread(target=handle_recv, args=(client,)).start()
