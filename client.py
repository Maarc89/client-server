#!/usr/bin/python3

import os
import select
import sys
import signal
import socket
import struct
import threading
from time import sleep
from datetime import datetime


def cntrlc(signum, handler):
    print("Sortint per CNTRL+C")
    raise SystemExit


signal.signal(signal.SIGINT, cntrlc)


def dt(): return datetime.now().strftime("%d/%m/%Y %H:%M:%S => ")


def dt2(): return datetime.now().strftime("%Y-%m-%d;%H:%M:%S")


packtypes = {"SUBS_REQ": 0, "SUBS_ACK": 1, "SUBS_REJ": 2, "SUBS_INFO": 3, "INFO_ACK": 4, "SUBS_NACK": 5,
             "SEND_DATA": int("0x20", base=16), "SET_DATA": int("0x21", base=16), "GET_DATA": int("0x22", base=16),
             "DATA_ACK": int("0x23", base=16), "DATA_NACK": int("0x24", base=16), "DATA_REJ": int("0x25", base=16)}

debug = False
configfile = "client.cfg"
status = "DISCONNECTED"
print(dt() + "STATUS = " + status)

if len(sys.argv) > 1:
    for argcounter, arg in enumerate(sys.argv):
        try:
            if arg == "-d":
                debug = True
            elif arg.endswith(".cfg") and sys.argv[argcounter - 1] == "-c":
                try:
                    f = open(arg, "r")
                    f.close()
                    configfile = arg
                except FileNotFoundError:
                    print("No s'ha pogut trobar el fitxer de configuració")
                    exit(-1)
            elif arg == "-c":
                if sys.argv[argcounter + 1].endswith(".cfg"):
                    try:
                        f = open(sys.argv[argcounter + 1], "r")
                        f.close()
                        configfile = sys.argv[argcounter + 1]
                    except FileNotFoundError:
                        print("No s'ha pogut trobar el fitxer de configuració")
                        exit(-1)
        except IndexError:
            print("Ús: ./cl.py {-d} {-c <nom_arxiu>}")
            exit(-1)

if debug:
    print(dt() + "Llegint dades del fitxer de configuració " + configfile)

client = {}

with open(configfile, "r") as f:
    for line in f.readlines():
        if line.split("=")[0][:-1] == "Elements":
            client["Elements"] = {}
            for param in line.split("=")[1][1:-1].split(";"):
                client["Elements"][param] = "NONE"
        else:
            client[line.split("=")[0][:-1]] = line.split("=")[1][1:-1]

should_send_subs_req = True
should_child_sleeps_hello = False


def subscribe():
    global should_send_subs_req, should_child_sleeps_hello
    if debug:
        print(dt() + "Creant un thread per a contar l'enviament de paquets SUBS_REQ")
    should_child_sleeps_hello = True
    child_sleeps_thread = threading.Thread(target=child_sleeps, args=[], daemon=True)
    child_sleeps_thread.start()


def create_subs_req():
    values = f"{client['Name']},{client['Situation']}"
    return struct.pack("B13s9s80s", int("0x00", base=16), client["MAC"].encode(), "00000000".encode(), values.encode())


def send_subs_req():
    global num_of_packets, subscribe_socket
    num_of_packets += 1
    server_UDP_address = (socket.gethostbyname(client["Server"]), int(client["Srv-UDP"]))
    if debug:
        print(dt() + "Enviant paquet SUBS_REQ al servidor amb adreça " + str(server_UDP_address))
    subscribe_socket.sendto(create_subs_req(), server_UDP_address)


def child_sleeps():
    global should_send_subs_req, should_child_sleeps_hello
    time = 1
    sleep(time)
    for i in range(3):
        if should_child_sleeps_hello:
            should_send_subs_req = True
            sleep(time)
        else:
            break
    while time < 3:
        if should_child_sleeps_hello:
            should_send_subs_req = True
            time += 1
            sleep(time)
        else:
            break
    while True:
        if should_child_sleeps_hello:
            should_send_subs_req = True
            sleep(time)
        else:
            break


if debug:
    print(dt() + "Creant socket UDP per a subscribir-se al servidor")
subscribe_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

if debug:
    print(dt() + "Iniciant subscripció")
subscribe()
status = "WAIT_ACK_SUBS"
print(dt() + "STATUS = " + str(status))

num_of_packets = 0
attempted_subscribes = 0


def decompose(packet_to_decompose):
    if debug:
        print(dt() + "Llegint la informació d'un paquet rebut")
    tup = struct.unpack("B13s9s80s", packet_to_decompose)
    decomposed = {"Tipus": tup[0], "MAC": tup[1].decode(), "Random": tup[2].decode(),
                  "Dades": tup[3].decode(errors="ignore")}
    filtered_dades = ""
    for c in decomposed["Dades"]:
        if c != '\0':
            filtered_dades = filtered_dades.__add__(c)
        else:
            break
    decomposed["Dades"] = filtered_dades
    if debug:
        print(dt() + "Dades del paquet rebut: " + str(decomposed))
    return decomposed


def create_subs_info(cl, data):
    if debug:
        print(dt() + "Preparant per enviar un paquet SUBS_INFO")
    dades = cl["Local-TCP"]
    dades = dades.__add__(",")
    for elem in cl["Elements"].keys():
        dades = dades.__add__(elem + ";")
    return struct.pack("B13s9s80s", int("0x03", base=16), cl["MAC"].encode(), data["Random"].encode(), dades.encode())


def subscribe_waiting():
    global attempted_subscribes, status, num_of_packets, subscribe_socket, should_send_subs_req, should_child_sleeps_hello
    while True:
        rdable, wtable, exceptional = select.select([subscribe_socket], [], [], 0)
        if len(rdable) > 0:
            if debug:
                print(dt() + "S'ha rebut un paquet pel port UDP")
            should_child_sleeps_hello = False
            pack_from_server = subscribe_socket.recv(103)
            data_server = decompose(pack_from_server)
            new_dades = ""
            for c in data_server["Dades"]:
                if c.isdigit() and c != '\0':
                    new_dades = new_dades.__add__(c)
                if c == '\0':
                    break
            data_server["Dades"] = new_dades
            aleatori = data_server["Random"]
            if data_server["Tipus"] != packtypes["SUBS_ACK"]:
                if debug:
                    print(dt() + "Tipus de paquet no esperat")
                if data_server["Tipus"] == packtypes["SUBS_NACK"]:
                    if debug:
                        print(dt() + "S'ha rebut un paquet SUBS_NACK")
                        print(dt() + "Reprenent enviament de SUBS_REQ")
                    status = "NOT_SUBSCRIBED"
                    print(dt() + "STATUS = " + str(status))
                    subscribe()
                else:
                    if debug:
                        print(dt() + "Iniciant nou procés de subscripció")
                    status = "NOT_SUBSCRIBED"
                    print(dt() + "STATUS = " + str(status))
                    attempted_subscribes += 1
                    num_of_packets = 0
                    subscribe()
            else:
                subs_info = create_subs_info(client, data_server)
                server_UDP_address = (socket.gethostbyname(client["Server"]), int(data_server["Dades"]))
                subscribe_socket.sendto(subs_info, server_UDP_address)
                if debug:
                    print(dt() + "Enviat paquet SUBS_INFO")
                status = "WAIT_ACK_INFO"
                print(dt() + "STATUS = " + str(status))
                rdable, wtable, exceptional = select.select([subscribe_socket], [], [], 2)
                if len(rdable) == 0:
                    if debug:
                        print(dt() + "No s'ha rebut el paquet INFO_ACK")
                    status = "NOT_SUBSCRIBED"
                    print(dt() + "STATUS = " + str(status))
                    attempted_subscribes += 1
                    num_of_packets = 0
                    subscribe()
                else:
                    pack_from_server = subscribe_socket.recv(103)
                    data_server = decompose(pack_from_server)
                    if data_server["Tipus"] != packtypes["INFO_ACK"]:
                        if debug:
                            print(dt() + "Tipus de paquet no esperat")
                        status = "NOT_SUBSCRIBED"
                        print(dt() + "STATUS = " + str(status))
                        attempted_subscribes += 1
                        num_of_packets = 0
                        subscribe()
                    else:
                        if debug:
                            print(dt() + "S'ha rebut el paquet INFO_ACK")
                        status = "SUBSCRIBED"
                        print(dt() + "STATUS = " + str(status))
                        should_child_sleeps_hello = False
                        return data_server, aleatori

        if should_send_subs_req:
            should_send_subs_req = False
            send_subs_req()

        if num_of_packets == 7:
            attempted_subscribes += 1
            num_of_packets = 0
            should_child_sleeps_hello = False
            if attempted_subscribes < 3:
                sleep(2)
                subscribe()
            else:
                print(dt() + "No s'ha pogut connectar al servidor. Sortint")
                should_child_sleeps_hello = False
                exit(-1)


if debug:
    print(dt() + "Començant el procés de subscripció ")
data, rand = subscribe_waiting()

# FINAL FASE DE SUBSCRIPCIÓ
should_clock_hello = True
sent_hellos = 0


def hello_thread_communication():
    global client, send_hello_packet, sent_hellos, status, should_clock_hello

    def hello():
        values = f"{client['Name']},{client['Situation']}"
        return struct.pack("B13s9s80s", int("0x10", base=16), client["MAC"].encode(), rand.encode(),
                           values.encode())

    sent_hellos = 0

    def send_hello():
        global should_clock_hello
        global status, sent_hellos, send_hello_packet
        if debug:
            print(dt() + "Enviant paquet HELLO")
        if sent_hellos == 3:
            if debug:
                print(dt() + "El servidor no ha contestat a 3 HELLO. Reiniciant")
            status = "NOT_SUBSCRIBED"
            print(dt() + "STATUS = " + str(status))
            os.kill(os.getpid(), signal.SIGUSR1)
            should_clock_hello = False
        subscribe_socket.sendto(hello(), (socket.gethostbyname(client["Server"]), int(client["Srv-UDP"])))
        send_hello_packet = False
        sent_hellos += 1
        if should_clock_hello:
            status = "SEND_HELLO"
            if debug:
                print(dt() + "STATUS = " + str(status))

    while should_clock_hello:
        if send_hello_packet and should_clock_hello:
            send_hello()

        rdable, wtable, exceptional = select.select([subscribe_socket], [], [], 0)
        if subscribe_socket in rdable:
            packet_from_server = subscribe_socket.recv(103)
            sent_hellos = 0
            data_from_server = decompose(packet_from_server)

            if data_from_server["Tipus"] != 16 or data_from_server["Dades"] != client["MAC"] or rand != data_from_server[
                    "Random"]:
                if debug:
                    print(dt() + "Hi ha hagut algun error amb el paquet. Reiniciant")
                os.kill(os.getpid(), signal.SIGUSR1)
                status = "NOT_SUBSCRIBED"
                print(dt() + "STATUS = " + str(status))
                should_clock_hello = False
    if debug:
        print(dt() + "Thread finalitzat")


send_hello_packet = True


def clock_signals():
    global send_hello_packet
    while should_clock_hello:
        send_hello_packet = True
        sleep(2)
    if debug:
        print(dt() + "Thread finalitzat")


def hello_handling():
    if debug:
        print(dt() + "Creant nou thread per mantenir comunicació periòdica amb el servidor")
    hello_thread = threading.Thread(target=hello_thread_communication, args=[], daemon=True)
    hello_thread.start()
    if debug:
        print(dt() + "Creant nou thread per a gestionar la comunicació periòdica amb el servidor")
    hello_clock = threading.Thread(target=clock_signals, args=[], daemon=True)
    hello_clock.start()


hello_handling()


def hand(signum, handler):
    global data, rand, should_clock_hello, should_send_subs_req, should_child_sleeps_hello
    print(dt() + "Intentant tornar a registrar")
    should_send_subs_req = True
    should_child_sleeps_hello = True
    subscribe()
    data, rand = subscribe_waiting()
    should_clock_hello = True
    hello_handling()


signal.signal(signal.SIGUSR1, hand)


def cquit(signum, handler):
    raise SystemExit


def stat():
    global status
    print("**********DADES DISPOSITIU**********")
    print("   MAC: " + client["MAC"])
    print("   Name: " + client["Name"])
    print("   Situació: " + client["Situation"])
    print("   Status: " + status)
    print("\nParametre\tValor")
    for key in client["Elements"].keys():
        print(str(key) + "\t\t" + str(client["Elements"][key]))
    print("")
    print("************************************")


def cset(param_name, new_value):
    if param_name in client["Elements"].keys():
        client["Elements"][param_name] = new_value
        print(dt() + "Nou valor de " + param_name + " = " + new_value)
        return True
    else:
        print(dt() + "ERROR => Aquest parametre no es cap dispositiu")
        return False


def send_data_packet(param):
    return struct.pack("B13s9s8s7s80s", int("0x20", base=16), client["MAC"].encode(), str(rand).encode(),
                       param.encode(), client["Elements"][param].encode(), "".encode())


def decompose_TCP(packet_recv):
    global rand
    tup = struct.unpack("B13s9s8s7s80s", packet_recv)
    new_info = ""
    for i in range(12):
        new_info = new_info.__add__(tup[5].decode(errors="ignore")[i])
    if tup[0] != packtypes["DATA_ACK"] or tup[2].decode(errors="ignore") != str(rand) or new_info != client["MAC"]:
        print(dt() + "El paquet no ha estat aceptat")
        if tup[0] == packtypes["DATA_NACK"]:
            if debug:
                print(dt() + "S'ha rebut un paquet DATA_NACK")
        elif tup[0] == packtypes["DATA_REJ"]:
            if debug:
                print(dt() + "S'ha rebut un paquet DATA_REJ")
        else:
            if debug:
                print(dt() + "S'ha rebut un paquet no esperat")
    else:
        print(dt() + "El paquet ha estat acceptat (s'ha rebut DATA_ACK)")

    decomposed = {"Tipus": tup[0], "MAC": tup[1].decode(errors="ignore"), "Random": tup[2].decode(errors="ignore"),
                  "Dispositive": tup[3].decode(errors="ignore"), "Valor": tup[4].decode(errors="ignore"),
                  "Info": new_info}
    return decomposed


def send(param_name):
    global data
    if param_name not in client["Elements"].keys():
        print(dt() + str(param_name) + " no és cap paràmetre")
        print(dt() + "No s'ha establert cap connexió")
    else:
        send_data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_TCP_address = (socket.gethostbyname(client["Server"]), int(data["Dades"]))
        send_data_socket.connect(server_TCP_address)
        send_data_socket.send(send_data_packet(param_name), 0)
        rdable, wtable, exceptional = select.select([send_data_socket], [], [], 3)
        if send_data_socket not in rdable:
            print(dt() + "El servidor no ha contestat a l'enviament de dades")
        else:
            pack_from_server = send_data_socket.recv(struct.calcsize("B13s9s8s7s80s"), 0)
            data_from_server = decompose_TCP(pack_from_server)
            print(data_from_server)


def fhelp():
    print("**********AJUDA COMANDES**********")
    print("Comanda  Ús \t\t\tUtilitat")
    print("")
    print("quit \t quit \t\t\tSortir del programa")
    print("stat \t stat \t\t\tMostrar informació del client")
    print("debug \t debug \t\t\tActiva o desactiva debug")
    print("set \t set <param> <valor> \tModifica el valor d'un paràmetre <param> amb el valor <valor>")
    print("send \t send <param> \t\tEnvia el valor de <param> al servidor via TCP")
    print("? \t ? \t\t\tMostra aquesta ajuda")
    print("**********************************")


def decompose_server(packet_server):
    tup = struct.unpack("B13s9s8s7s80s", packet_server)
    new_info = ""
    for i in range(12):
        new_info = new_info.__add__(tup[5].decode(errors="ignore")[i])
    decomposed = {"Tipus": tup[0], "MAC": tup[1].decode(errors="ignore"), "Random": tup[2].decode(errors="ignore"),
                  "Dispositive": tup[3].decode(errors="ignore"), "Valor": tup[4].decode(errors="ignore"),
                  "Info": new_info}
    return decomposed


def create_get_data(element):
    if element in client["Elements"].keys():
        if debug:
            print(dt() + "Enviant DATA_ACK")
        return struct.pack("B13s9s8s7s80s", packtypes["DATA_ACK"], client["MAC"].encode(), rand.encode(),
                           element.encode(),
                           client["Elements"][element].encode(), "".encode())
    else:
        if debug:
            print(dt() + "Enviant DATA_NACK")
        return struct.pack("B13s9s8s7s80s", packtypes["DATA_NACK"], client["MAC"].encode(), rand.encode(),
                           element.encode(),
                           "NONE".encode(), (str(element) + " no és un dispositiu del client").encode())


def create_set_data_ack(element):
    print("Data_ack element", element)
    return struct.pack("B13s9s8s7s80s", packtypes["DATA_ACK"], client["MAC"].encode(), rand.encode(), element.encode(),
                       client["Elements"][element].encode(), dt2().encode())


def create_set_data_nack(element, typeof):
    if typeof == 0:
        return struct.pack("B13s9s8s7s80s", packtypes["DATA_NACK"], client["MAC"].encode(), rand.encode(),
                           element.encode(),
                           "NONE".encode(), "Hi ha hagut un error al fer el set".encode())
    else:
        return struct.pack("B13s9s8s7s80s", packtypes["DATA_NACK"], client["MAC"].encode(), rand.encode(),
                           element.encode(),
                           "NONE".encode(), "L'element és un sensor per tant no es pot configurar".encode())


def create_data_rej(element):
    return struct.pack("B13s9s8s7s80s", packtypes["DATA_REJ"], client["MAC"].encode(), rand.encode(), element.encode(),
                       "NONE".encode(), "Error d'identificació".encode())


def waiting_for_server(new_socket):
    if debug:
        print(dt() + "S'ha rebut una connexió del servidor")
    packet_from_server = new_socket.recv(struct.calcsize("B13s9s8s7s80s"))
    data_from_server = decompose_server(packet_from_server)
    if data_from_server["Info"][:12] == client["MAC"][:12] and data_from_server["Random"] == str(rand):
        if data_from_server["Tipus"] == packtypes["GET_DATA"]:
            new_socket.send(create_get_data(data_from_server["Dispositive"][:-1]), struct.calcsize("B13s9s8s7s80s"))
        elif data_from_server["Tipus"] == packtypes["SET_DATA"]:
            if data_from_server["Dispositive"][-2] == "I":
                set_result = cset(data_from_server["Dispositive"], data_from_server["Valor"])
                if set_result:
                    if debug:
                        print(dt() + "Enviant DATA_ACK")
                    new_socket.send(create_set_data_ack(data_from_server["Dispositive"][:-1]))
                else:
                    if debug:
                        print(dt() + "Enviant DATA_NACK")
                    new_socket.send(create_set_data_nack(data_from_server["Dispositive"][:-1], 0))
            else:
                if debug:
                    print(dt() + "Enviant DATA_NACK")
                new_socket.send(create_set_data_nack(data_from_server["Dispositive"][:-1], 1))
        else:
            if debug:
                print(dt() + "Rebut paquet no esperat via TCP. No es contestarà")
            new_socket.close()
    else:
        if debug:
            print(dt() + "Rebut paquet amb identificació incorrecta. Reiniciant")
        new_socket.send(create_data_rej(data_from_server["Dispositive"][:-1]))
        new_socket.close()
        os.kill(os.getpid(), signal.SIGUSR1)


def start_waiting_thread(data_socket):
    if debug:
        print(dt() + "Creant thread per a esperar una connexió amb el servidor")
    receive_data_thread = threading.Thread(target=waiting_for_server, args=[data_socket], daemon=True)
    receive_data_thread.start()
    return receive_data_thread


def prepare_server_connection():
    receive_data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        receive_data_socket.bind(("", int(client["Local-TCP"])))
    except OSError:
        print(dt() + "No s'ha pogut bindejar el socket TCP")
        os.kill(os.getpid(), signal.SIGTERM)
        raise SystemExit
    receive_data_socket.listen(5)
    while True:
        new_socket, addr = receive_data_socket.accept()
        start_waiting_thread(new_socket)


if debug:
    print(dt() + "Creant thread per atendre peticions dels servidor")
server_connection_thread = threading.Thread(target=prepare_server_connection, args=[], daemon=True)
server_connection_thread.start()

signal.signal(signal.SIGTERM, cquit)

while True:
    command = input("Introdueix una comanda: ")
    try:
        if command.split()[0] == "quit":
            cquit(0, 0)
        elif command.split()[0] == "stat":
            stat()
        elif command.split()[0] == "set":
            cset(command.split()[1], command.split()[2])
        elif command.split()[0] == "send":
            send(command.split()[1])
        elif command.split()[0] == "?":
            fhelp()
        elif command.split()[0] == "debug":
            if debug:
                debug = False
                print(dt() + "Mode debug desactivat")
            else:
                print(dt() + "Mode debug activat")
                debug = True
        else:
            print("Comanda errònea, escriu ? per ajuda")
    except IndexError:
        print("Comanda errònea, escriu ? per ajuda")
