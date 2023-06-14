import threading, time, socket, os, sys, subprocess, copy

host = '0.0.0.0'
ETH_P_ALL = 0x3
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_RARP = 0x8035
ETH_P_IPV6 = 0x086dd

counter = 0
finish = False


rule_record = []
with open('rule.txt', 'r+') as f:
    con = f.readline()
    while con:
        rule_record.append(con.split("\n")[0])
        con = f.readline()



def unpack(packet):
    global counter
    counter += 1
    isARP = 0
    # 16 base paload
    # print(packet)
    # 10 base paload
    # print(list(packet))
    dst_mac = list(packet)[0:6]
    out = ""
    for i in dst_mac:
        if i>=16: out += hex(i)[2:] + ":"
        else: out += "0" + hex(i)[2:] + ":"
    src_mac = list(packet)[6:12]
    dst_mac = f"{out[:-1]}"
    ## print("dst_mac\t\t"+out[:-1])
    out = ""
    for i in src_mac:
        if i>=16: out += hex(i)[2:] + ":"
        else: out += "0" + hex(i)[2:] + ":"
    ## print("src_mac\t\t"+out[:-1])
    src_mac = f"{out[:-1]}"

    prot = list(packet)[12:14]
    if prot == [8, 0]:
        pass
        ## print("protocol\tIP")
    elif prot == [6, 0]:
        pass
        ## print("protocol\t\tXNS")
    elif prot == [8, 6]:
        isARP = 1
        # print("protocol\tARP")
        pass
    elif prot == [134, 221]:
        pass
        # 16進位    86 DD
        ## print("protocol\tIPv6")
    # https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
    else:
        pass
        ## print(f"protocol\t\t{list(packet)[12:14]} unknown")

    if hex(*packet[14:15]) == '0x0':
        version = '0'
        header_length = '0'
    else:
        version= hex(*packet[14:15])[2::][0:-1]
        header_length = hex(*packet[14:15])[2::][1]

    if version == '0':
        pass
        ## print("Ver\t\t"+version)
    else:
        pass
        ## print("Ver\t\tIPv"+version)
    HL = int(header_length)*4
    ## print("HL\t\t"+str(HL)+" bytes")

    if HL >20:
        pass
        ## print("options\t\t yes")
    else: ## print("options\t\tno")
        pass

    TL = list(packet[16:18])
    #16  12 34 -> 1*16^3 + 2*16^2 + 3*16 + 4
    #10  18 52
    TL = TL[0]*256 + TL[1]
    ## print("TL\t\t"+str(TL)+" bytes")
    ## print("payload length\t"+str(TL-HL)+' bytes')
    TTL = hex(*packet[22:23])[2::]
    ## print("TTL\t\t"+str(int(TTL,16))+" hops")

    PROC = int(*packet[23:24])
    # packet[23:24] = b'\x11'
    # int(*packet[23:24]) = 17
    proc_set={}
    proc_set[1] = "ICMP"
    proc_set[6] = "TCP"
    proc_set[17] = "UDP"
    # https://zh.wikipedia.org/zh-tw/IP%E5%8D%8F%E8%AE%AE%E5%8F%B7%E5%88%97%E8%A1%A8

    try:
        if int(PROC)==1 or int(PROC)==6 or int(PROC)==17:
            pass
            ## print("next protocol\t"+proc_set[int(PROC)])
        else:
            pass
            ## print(f"unknown next protocol\t+{int(*packet[23:24])}")
    except ValueError as v:
        pass
        ## print(f"unknown next protocol\t+{int(*packet[23:24])}")
        ## print(v)

    src = ""
    src += f"{int(*packet[26:27])}."
    src += f"{int(*packet[27:28])}."
    src += f"{int(*packet[28:29])}."
    src += f"{int(*packet[29:30])}"
    src_ip = src

    dst = ""
    dst += f"{int(*packet[30:31])}."
    dst += f"{int(*packet[31:32])}."
    dst += f"{int(*packet[32:33])}."
    dst += f"{int(*packet[33:34])}"
    dst_ip = dst


    ## print(f"src_ip\t\t{src}")
    ## print(f"dst_ip\t\t{dst}")
    ## print(f"counter\t\t{counter}")

    # ----------- TCP -------------- 
    syn = 0
    if int(PROC) == 6:
        flags = f"{bin(*packet[47:48])[2:].zfill(8)}"
        syn = int(flags[-2])
        # print(flags)
        # print("syn",flags[-2])

    # ----------- ICMP -------------- 
    icmp_request = 0
    icmp_reply = 0
    if int(PROC) == 1:
        icmp_type = int(*packet[34:35])
        icmp_code = int(*packet[35:36])
        if icmp_type == 8: icmp_request = 1 
        if icmp_type == 0: icmp_reply = 1 
        # print(f"type:{int(*packet[34:35])}")
        # print(f"{code:int(*packet[35:36])}")
        # print(f"icmp reqest:{icmp_request}")
        # print(f"icmp reply:{icmp_reply}")
    return [src_ip, src_mac, syn, dst_ip, dst_mac, icmp_request, icmp_reply, len(packet), isARP]

count = 0
myIP = "192.168.245.140"
myIP = "192.168.1.110"
myMAC = "00:0c:29:43:70:36"
myKey = myIP + "-" + myMAC

ip_mac = subprocess.check_output(['sh', 'getIP.sh'])
ip_mac = ip_mac.decode('utf-8').strip()
myKey = ip_mac.split("\n")[0]

def timer():
    global count, pkt_count, finish
    last_time = time.time()
    while True:
        try:
            if finish: sys.exit("")
            current_time = time.time()
            if current_time - last_time >= 1:
                # print(f"{pkt_count}")
                #os.system("clear")
                print(count, end="\n\n")
                with open('logfile.txt', 'a+') as f:
                    f.write(f"{count}\n")
                    while myKey in pkt_count:
                        send = pkt_count.pop(myKey)
                        for dst in send:
                            f.write(f"SEND   : {dst}\t :{send[dst]}\n")
                            print(f"SEND   : {dst}                  \t :{send[dst]}")
                        print(f"{'_'*70}\n")

                    for i in pkt_count:
                        f.write(f"RECEIVE: {i}\t:{pkt_count[i]}\n")
                        print(f"RECEIVE: {i}                         \t:{pkt_count[i]}")

                # print(f"{pkt_count}")
                # syn_flooding_defence(pkt_count)
                rule(pkt_count)
                pkt_count = {}

                #threading.Thread(target=record_packets).start()
                last_time = current_time
                count+=1
                print("\n\n\n")
        except Exception as e: 
            print(e)

cmd_record = []
out = []

    
    
def rule(pack_count): #meowhecker 
    try:
        tmp = copy.deepcopy(pack_count)
        
        global cmd_record
        for key, value in pack_count.items():
            _ip = key.split("-")[0]
            _mac = key.split("-")[1]
            _myip = myKey.split("-")[0]
            _mymac = myKey.split("-")[1]

            if  _ip == _myip: continue
            if  _mac == _mymac: continue

            if value['total'] > 1000:
               # print(f'{sourceIP} is Bad guy!!!')
               cmd = f"sudo iptables -A INPUT -m mac --mac-source {_mac} -j DROP"
               os.system(cmd)
               if cmd in rule_record: continue
               rule_record.append(cmd)
               with open('rule.txt', 'a+') as f:
                   f.write(cmd+"\n")

               cmd = f'sudo iptables -t filter -A INPUT -j DROP -s {_ip}'
               os.system(cmd)
               if cmd in rule_record: continue
               rule_record.append(cmd)
               with open('rule.txt', 'a+') as f:
                   f.write(cmd+"\n")
               pass
    except Exception as e:
        print(e)

pkt_count = {}
def pkt():
    global pkt_count, finish
    myIP = "192.168.245.140"
    myMAC = "00:0c:29:43:70:36"
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    while 1:
        if finish: sys.exit("")
        try:
            packet, packet_info = s.recvfrom(4096)
            packet = unpack(packet)
            if packet[8] == 1: continue

            pkt_ip       = packet[0]
            pkt_mac      = packet[1]
            syn          = packet[2]
            pkt_dst_ip   = packet[3]
            pkt_dst_mac  = packet[4]
            icmp_request = packet[5]
            icmp_reply   = packet[6]
            pkt_bytes    = packet[7]
            # print(f"byte:{pkt_bytes}")

            key = pkt_ip+"-"+pkt_mac # src_key
            dst_key = pkt_dst_ip+"-"+pkt_dst_mac
            pkt_dst_ip = dst_key

            # BUILD THE PKT STRUCTURN
            if key not in pkt_count:
                if key == myKey:
                    pkt_count[key] = {}
                else:
                    pkt_count[key]  = {"total":0, "syn":0, "icmp":0}

            # HANDLE MY SEND
            if key == myKey:
                # SET THE DETAIL PKT STURCTURE
                if pkt_dst_ip not in pkt_count[key]:  
                    # total:[0, 0] first 0 is numbers of the pkt, second 0 is bytes of pkt
                    pkt_count[key][pkt_dst_ip]={"total":[0, 0], "syn":[0, 0], "icmp":[0, 0]}
                if syn == 1:
                    pkt_count[key][pkt_dst_ip]["syn"][0] += 1 
                    pkt_count[key][pkt_dst_ip]["syn"][1] += pkt_bytes 
                elif icmp_reply == 1:
                    pkt_count[key][pkt_dst_ip]["icmp"][0] += 1 
                    pkt_count[key][pkt_dst_ip]["icmp"][1] += pkt_bytes
                pkt_count[key][pkt_dst_ip]["total"][0] += 1
                pkt_count[key][pkt_dst_ip]["total"][1] += pkt_bytes
                continue 
            # HANDLE RECEIVE
            else:
                pkt_count[key]["total"] += 1
                if syn == 1:
                    pkt_count[key]["syn"] += 1
                if icmp_request == 1:
                    pkt_count[key]["icmp"] += 1

        except KeyboardInterrupt:
            break
        except ValueError:
            print(ValueError)

def isFinish():
    global finish
    while 1:
        if input()=="e":
            print("exit")
            os.system("sudo iptables-restore < iptables.conf")
            finish = True
            time.sleep(0.5)
            os.system("sudo python3 plot_out.py")
            sys.exit("finish")
        else:
            print("Enter 'e'' to finish")

def main():
    with open('logfile.txt', 'w+') as f:
        pass
    os.system("sudo iptables-save > iptables.conf")
    threading.Thread(target=isFinish).start()
    threading.Thread(target=timer).start()
    threading.Thread(target=pkt).start()

if __name__ == '__main__':
    main()
