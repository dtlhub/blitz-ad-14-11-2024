import random
import re
import requests
from checklib import *
from dataclasses import dataclass
from bs4 import BeautifulSoup
import pickle
import hashlib
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import pathlib

PORT = 5000


@dataclass
class User:
    username: str
    password: str
    preferences: str

    @staticmethod
    def rnd_preferences():
        return rnd_string(32)

    @classmethod
    def random(cls):
        username = rnd_username()
        password = rnd_password()
        preferences = User.rnd_preferences()
        return User(username, password, preferences)

    @classmethod
    def get_private_key(cls):
        cwd = pathlib.Path(__file__).parent.resolve()
        with open(cwd / "private.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        return private_key

    def serialize(self) -> str:
        bts = pickle.dumps(self)
        return bts.hex()

    @classmethod
    def deserialize(cls, raw: str) -> "User":
        return pickle.loads(bytes.fromhex(raw))


@dataclass
class Bouquet:
    id: int
    name: str
    flowers: list
    description: str

    @classmethod
    def random(cls):
        id = random.randint(1, 9)
        name = rnd_string(10)
        flowers = [random.randint(0, 5)]
        description = rnd_string(10)
        return Bouquet(id, name, flowers, description)


@dataclass
class Profile:
    username: str
    preferences: str


def brew_soup(c: BaseChecker, text: str) -> BeautifulSoup:
    try:
        return BeautifulSoup(text, "html.parser")
    except Exception as e:
        c.cquit(Status.MUMBLE, "Failed to parse response", str(e))


class CheckMachine:
    @property
    def url(self):
        return f"http://{self.c.host}:{self.port}"

    def __init__(self, checker: BaseChecker):
        self.c = checker
        self.port = PORT

    def register(
        self, s: requests.Session, username: str, password: str, preferences: str
    ):
        resp = s.post(
            f"{self.url}/register",
            data={
                "username": username,
                "password": password,
                "preferences": preferences,
            },
        )
        self.c.assert_in("session", s.cookies, f"Failed to register: {resp.text}")

    def register_user(self, s: requests.Session, user: User):
        self.register(s, user.username, user.password, user.preferences)

    def login(
        self,
        s: requests.Session,
        user: User,
        status: Status = Status.MUMBLE,
    ):
        s.post(
            f"{self.url}/login",
            data={
                "username": user.username,
                "password": user.password,
            },
        )
        self.c.assert_in("session", s.cookies, "Failed to login", status)

    def logout(self, s: requests.Session):
        s.post(f"{self.url}/logout")
        self.c.assert_nin("session", s.cookies, "Failed to logout")

    def profile_check(self, s: requests.Session, status: Status = Status.MUMBLE):
        raw_html = s.get(f"{self.url}/profile").text
        soup = brew_soup(self.c, raw_html)
        try:
            profile_info = soup.find("div", class_="profile-info")
            username = re.findall(
                r"(?<=Name:</strong> ).+?(?=</p>)", str(profile_info.find_all("p"))
            )[0]
            preferences = re.findall(
                r"(?<=Preferences:</strong> ).+?(?=</p>)",
                str(profile_info.find_all("p")),
            )[0]
            return Profile(username=username, preferences=preferences)
        except Exception as e:
            self.c.cquit(
                status, "Failed to parse general information in profile check", str(e)
            )

    def try_subscribe(
        self,
        s: requests.Session,
        status: Status = Status.MUMBLE,
    ):
        periods = random.randint(1, 4)
        raw_html = s.post(
            f"{self.url}/profile/subscribe", data={"periods": periods}
        ).text
        soup = brew_soup(self.c, raw_html)
        try:
            error_msg = soup.find("p", {"id": "error"}).string
            return error_msg
        except Exception as e:
            self.c.cquit(
                status, "Failed to parse general information in try suscribe", str(e)
            )

    def user_search(
        self,
        s: requests.Session,
        user_search: str,
        status: Status = Status.MUMBLE,
    ):
        raw_html = s.get(
            f"{self.url}/profile/user-search", params={"username": user_search}
        ).text
        soup = brew_soup(self.c, raw_html)
        try:
            profile_info = soup.find("div", class_="profile-info")
            p_tags = str(profile_info.find_all("p"))
            name = re.findall(r"(?<=Name:</strong> ).+?(?=</p>)", p_tags)
            preferences = re.findall(r"(?<=Preferences:</strong> ).+?(?=</p>)", p_tags)
            return Profile(name, preferences)
        except Exception as e:
            self.c.cquit(
                status, "Failed to parse general information in user search", str(e)
            )

    def filter_bouquet(
        self,
        s: requests.Session,
        field: str,
        value: str,
        status: Status = Status.MUMBLE,
    ):
        raw_html = s.get(
            f"{self.url}/bouquet/filter", params={"field": field, "value": value}
        ).text
        soup = brew_soup(self.c, raw_html)

        try:
            bouquet_list = soup.find("div", class_="bouquet-list")
            name = re.findall(
                r"(?<=<h2>).+?(?=</h2>)", str(bouquet_list.find_all("h2"))
            )
            description = re.findall(
                r"(?<=<b>).+?(?=</b>)", str(bouquet_list.find_all("b"))
            )
            bouquet_ids = re.findall(
                r'(?<=value=").+?(?=")', str(bouquet_list.find_all("input"))
            )
            return Bouquet(bouquet_ids, name, [1], description)
        except Exception as e:
            self.c.cquit(
                status, "Failed to parse general information in filter", str(e)
            )

    def given_bouquets(
        self, s: requests.Session, user_from: str, status: Status = Status.MUMBLE
    ):
        raw_html = s.get(
            f"{self.url}/bouquet/given", params={"user_from": user_from}
        ).text
        soup = brew_soup(self.c, raw_html)
        try:
            bouquet_list = soup.find("div", class_="bouquet-list")
            name = re.findall(
                r"(?<=<h2>).+?(?=</h2>)", str(bouquet_list.find_all("h2"))
            )
            p_tags = str(bouquet_list.find_all("p"))
            description = re.findall(r"(?<=Description:</strong> ).+?(?=</p>)", p_tags)
            user_from = re.findall(r"(?<=From:</strong> ).+?(?=</p>)", p_tags)
            return name, description, user_from
        except Exception as e:
            self.c.cquit(
                status, "Failed to parse general information in given bouquets", str(e)
            )

    def create_bouquet(
        self,
        s: requests.Session,
        bouquet: Bouquet,
    ):
        s.post(
            f"{self.url}/bouquet/create",
            data={
                "name": bouquet.name,
                "flowers": bouquet.flowers,
                "description": bouquet.description,
            },
        )

    def send_bouquet(self, s: requests.Session, user_to: str, bouquet_id: int):
        s.post(
            f"{self.url}/bouquet/send",
            data={
                "user_to": user_to,
                "bouquet_id": bouquet_id,
            },
        )

    def sign_uuid(self, s: requests.Session):
        uuid = s.get(f"{self.url}/get-uuid").text
        assert_neq(uuid, "", "Empty uuid")
        private_key = User.get_private_key()
        prehashed = hashlib.sha256(uuid.encode()).hexdigest()
        sig = private_key.sign(
            prehashed.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return base64.b64encode(sig)

    def verify_signature(self, s: requests.Session, signature):
        res = s.post(f"{self.url}/profile/admin", data={"signed_msg": signature}).text
        assert_neq(res, "Invalid signature", "Signature was corrupted")
