import socket
import threading
import os
import jwt
import json
from dotenv import load_dotenv
from pymongo import MongoClient
from bson.objectid import ObjectId
import time

MESSAGE_LEN = 512
CHUNK_LEN = 1024
FORMAT = 'utf-8'
UNKNOWN_MESSAGE = "<UNKNOWN>"

load_dotenv()
SERVER = socket.gethostbyname(socket.gethostname())
PORT = 5051
ADDR = (SERVER, PORT)

KEY = os.getenv("KEY")

database = MongoClient(os.getenv("MONGO_URL")).p2pFileSharing

tracker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


class TransferDataError(Exception):
    pass


def handle_login_info(msg):
    username, password = msg.split("|")
    username = username.split(":")[1]
    password = password.split(":")[1]
    return username, password


def login(username, password):
    result = database.users.find_one({"username": username, "password": password})
    if result:
        # login success
        return str(result['_id'])
    # Login fail
    return ""


def register(username, password):
    result = database.users.find_one({"username": username})
    if not result:
        database.users.insert_one({"username": username, "password": password})
        return True
    # register fail
    return False


def handle_login_request(conn):
    try:
        # Send back to confirm request for peer
        send_msg(conn, "login")
        # Receive username and password from peer
        msg = recv_msg(conn)
        username, password = handle_login_info(msg)
        # Check username, password
        user_id = login(username, password)
        if not user_id:
            # Send empty token
            msg = f"login fail|token:"
        else:
            payload_data = {
                "_id": user_id
            }
            token = jwt.encode(
                payload=payload_data,
                key=KEY
            )
            msg = f"login success|token:{token}"
        send_msg(conn, msg)
    except TransferDataError as e:
        print(e)


def handle_register_request(conn):
    try:
        # Send back to confirm request for peer
        send_msg(conn, "register")
        # Receive username and password from peer
        msg = recv_msg(conn)
        username, password = handle_login_info(msg)
        # Check username, password
        if register(username, password):
            # Send empty token
            msg = f"register success"
        else:
            msg = f"register fail"
        send_msg(conn, msg)
    except TransferDataError as e:
        print(e)


def handle_token_msg(token):
    token = token.split(":")[1]
    return jwt.decode(token, KEY, algorithms=['HS256'])


def authenticate_peer(conn):
    token = recv_msg(conn)
    payload = handle_token_msg(token)
    user_id = payload['_id']
    if user_id:
        send_msg(conn, "auth success")
        return user_id
    else:
        send_msg(conn, "auth fail")
        return ""


def handle_address_declaration(conn):
    try:
        # Send back to confirm request for peer
        send_msg(conn, "address")
        # Authentication process
        user_id = authenticate_peer(conn)
        if not user_id:
            return
        # Receive `ip, port` from peer
        msg = recv_msg(conn)
        # Checking port (TO DO)
        # checking_port()
        # Send ACK
        send_msg(conn, "address success")

        # Saving port
        database.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"address": msg}}
        )
    except TransferDataError as e:
        print(e)


def handle_publish_request(conn):
    try:
        # Send back to confirm going to publish process.
        send_msg(conn, "publish")
        # Authenticate peer
        user_id = authenticate_peer(conn)
        if not user_id:
            return
        # Receive filname from peer
        filename = recv_msg(conn)

        # Update database
        # Check whether filename is empty.
        if not filename:
            send_msg(conn, "publish fail|msg: Your filename is empty!")
            return
        # Check whether filename is duplicated.
        result = database.files.find_one(
            {"filename": filename, "user_id": ObjectId(user_id)}
        )
        if result:
            send_msg(conn, "publish fail|msg: Your filename is duplicated with a file you upload before!")
            return
        # No duplicate, insert into `files` collection.
        database.files.insert_one({
            "user_id": ObjectId(user_id),
            "filename": filename
        })
        send_msg(conn, "publish success")
    except TransferDataError as e:
        print(e)


def handle_no_publish_request(conn):
    try:
        # Send `no publish` back
        send_msg(conn, "no publish")
        # Authentication process
        user_id = authenticate_peer(conn)
        if not user_id:
            return
        # get filename
        msg = recv_msg(conn)
        filename = msg.split(":")[1]
        database.files.delete_one({"user_id": ObjectId(user_id), "filename": filename})
    except TransferDataError as e:
        print(e)


def handle_fetch_request(conn):
    try:
        # Send back to confirm `fetch` request from user
        send_msg(conn, "fetch")
        # Receive `filename` and `username` from peer
        req = recv_msg(conn)
        # Split
        filename, username = req.split("|")
        filename = filename.split(":")[1]
        username = username.split(":")[1]

        # Send last ACK
        # Checking whether username does exist
        result = database.users.find_one({"username": username})
        if not result:
            send_msg(conn, "fetch fail|msg: Username you provided is not found!")
            return
        user_id = str(result["_id"])
        user_addr = str(result["address"])
        if not user_addr:
            send_msg(conn, "fetch fail|msg: Username is not online!")
            return
        # Checking whether filename belongs to that user
        result = database.files.find_one({"user_id": ObjectId(user_id), "filename": filename})
        if not result:
            send_msg(conn, "fetch fail|msg: This username don't have this file!")
            return
        # Fetch success
        send_msg(conn, f"fetch success|address:{user_addr}")
    except TransferDataError as e:
        print(e)


def handle_get_file_list(conn):
    # Send back `file list` to confirm
    send_msg(conn, "file list")
    # Get file list from database then save in the file
    data = database.files.aggregate([
        {
            "$lookup": {
                "from": "users",
                "localField": "user_id",
                "foreignField": "_id",
                "as": "user"
            }
        },
        {
            "$project": {
                "_id": 0,
                "user_id": 1,
                "filename": 1,
                "user.username": 1
            }
        }
    ])
    str_data = '''
    []
    '''
    js_data = json.loads(str_data)

    for d in list(data):
        if d["user"]:
            js_data.append(
                {"filename": d["filename"], "username": d["user"][0]["username"]}
            )
        else:
            print(d["filename"])

    with open("./data/file-list.json", "w") as file:
        json.dump(js_data, file, indent=4)

    send_file(conn, "./data/file-list.json")
    try:
        if recv_msg(conn) == "file list success":
            print("Peer get file list success!")
        else:
            print("Peer cannot get file list!")
    except TransferDataError as e:
        print(e)


def handle_request(conn, addr):
    print(f"{addr} connected.")
    while True:
        try:
            command = recv_cmd(conn)
            if command == "login":
                handle_login_request(conn)
            elif command == "register":
                handle_register_request(conn)
            elif command == "address":
                handle_address_declaration(conn)
            elif command == "publish":
                handle_publish_request(conn)
            elif command == "no publish":
                handle_no_publish_request(conn)
            elif command == "fetch":
                handle_fetch_request(conn)
            elif command == "file list":
                handle_get_file_list(conn)
            elif command == "ping":
                send_msg(conn, "ping")
            elif command == "":
                break
        except:
            print(f"{addr} was closed connection!")
            return


def cml_user_list():
    result = database.users.find()
    print("---------------- USER LIST ---------------")
    for user in result:
        print(f"username={user['username']}")
    print("-------------- END USER LIST -------------")


def cml_discover(username):
    result = database.users.find_one({"username": username})
    if not result:
        print(f"Username {username} you provided is not found!")
        return
    user_id = result['_id']
    files = database.files.find({"user_id": ObjectId(user_id)})
    is_empty = 1
    for file in files:
        print(f"{file['filename']}")
        is_empty = 0
    if is_empty:
        print(f"{username} has no published file!")


def cml_ping(username):
    result = database.users.find_one({"username": username})
    if not result:
        print("Username you provided is not found!")
        return
    peer_ip = ""
    peer_port = ""

    try:
        peer_ip, peer_port = str(result["address"]).split(":")
    except:
        print("Address of this username is not found!")

    peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer.settimeout(5)
    try:
        peer.connect((peer_ip, int(peer_port)))
    except:
        print(f"[{username}] is not online!")
        return
    print(f"[{username}] is online!")
    peer.close()


def send_msg(conn, msg):
    msg = msg.encode(FORMAT)
    msg_len = len(msg)
    msg += b' ' * (MESSAGE_LEN - msg_len)
    conn.send(msg)
    print(f"SEND: {msg}")


def recv_cmd(conn):
    res = conn.recv(MESSAGE_LEN).decode(FORMAT).strip()
    print(f"RECEIVE: {res}")
    return res


def recv_msg(conn):
    try:
        conn.settimeout(5)
        res = conn.recv(MESSAGE_LEN).decode(FORMAT).strip()
        print(f"RECEIVE: {res}")
        return res
    except socket.timeout:
        raise TransferDataError("Timeout: Connection closed unexpectedly.")
    except ConnectionResetError:
        raise TransferDataError("Connection reset by peer: Connection closed unexpectedly.")
    finally:
        conn.settimeout(None)


def send_file(conn, uri):
    file = open(uri, "rb")
    while True:
        data = file.read(CHUNK_LEN)
        if not data:
            break
        conn.send(data)
    time.sleep(0.5)
    conn.send(b"<END>")
    file.close()


def recv_file(conn, uri):
    file = open(uri, "ab")
    done = False
    while not done:
        data = conn.recv(1024)
        if data[-5:] == b"<END>":
            done = True
        else:
            file.write(data)
    file.close()


def listening():
    tracker_socket.bind(ADDR)
    tracker_socket.listen()
    print(f"Tracker is listening on {ADDR}")
    while True:
        conn, addr = tracker_socket.accept()
        thread = threading.Thread(target=handle_request, args=(conn, addr))
        thread.daemon = True
        thread.start()


def main():
    thread = threading.Thread(target=listening)
    thread.daemon = True
    thread.start()
    while True:
        cmd = input()
        if cmd == "user list":
            cml_user_list()
        elif len(cmd) > 9 and cmd[0:8] == "discover" and cmd[8] == " ":
            cml_discover(cmd[9:])
        elif len(cmd) > 5 and cmd[0:4] == "ping" and cmd[4] == " ":
            cml_ping(cmd[5:])
        elif cmd == "help":
            print("user list: print all users in database")
            print("discover {username}: discover published file from username")
            print("ping {username}: ping to username")
            print("exit: End program!")
        elif cmd == "exit":
            break
        else:
            print("Wrong command format! Enter: `help` to figure out all command")


if __name__ == "__main__":
    main()
