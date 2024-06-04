## Tracker side ##
1. First you need to download and install `MongoDB Community Server` at https://www.mongodb.com/try/download/community
2. When you installed, let create a local mongoDB.
3. Create `.env` file in `Tracker` folder. You must put `MONGO_URL` and `KEY`. `MONGO_URL` is your local mongodb's link. `KEY` for JWT, you can put a random string.
4. When it's done, you now can run `tracker.py`
   

## Peer side ##
THEME: https://github.com/rdbende/Forest-ttk-theme
1. You have to git or download this theme, you need to put this folder that you git or download before inside `Peer` and `Peer2` folder (both folder is the same, they are duplicated, this because I want to run at least to Peer to check communication as well as avoid conflicting port).
2. Create `.env` in both `Peer` and `Peer2` folder.
3. You must put `TRACKER_IP`, `TRACKER_PORT`, `WORKSPACE_PATH` for both folder. `TRACKER_IP` is your tracker IP, `TRACKER_PORT` is your tracker's listening port. `WORKSPACE_PATH="./data".`.
4. When it's done, you now can run `peer.py` in both folder. If some error occur, please create `data` folder inside both `Peer` and `Peer2`.

## Video demo ##

My role in project: https://youtu.be/y7zKiO3YZgI
Git and Run: https://youtu.be/KrtRGQtNpJA
Demo: https://youtu.be/VmeE70ZTSrY
