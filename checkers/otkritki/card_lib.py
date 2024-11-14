import enum
import json
import pickle
import requests
from checklib import BaseChecker, Status
from dataclasses import dataclass
from random import choices, randint
from string import ascii_lowercase, ascii_uppercase

PORT = 8083


@dataclass
class GiftCard(json.JSONEncoder):
    sender: str
    receiver: str
    imageType: str
    text: str
    id: int = -1

    @staticmethod
    def random_string(len: int) -> str:
        return "".join(choices(ascii_lowercase + ascii_uppercase, k=len))

    @classmethod
    def generate(cls, sender: str, receiver: str):
        random_text = GiftCard.random_string(randint(10, 50))
        random_card_id = randint(1, 10)
        return GiftCard(sender, receiver, str(random_card_id), random_text)

    @classmethod
    def fromJSON(cls, response: dict):
        return GiftCard(
            sender=response.get("from"),
            receiver=response.get("to"),
            imageType=response.get("imageType"),
            text=response.get("text"),
            id=response.get("id"),
        )

    def __eq__(self, other):
        for property, value in vars(self).items():
            if property != "id" and value != vars(other)[property]:
                return False
        return True

    def toDict(self):
        return {
            "to": self.receiver,
            "text": self.text,
            "imageType": self.imageType,
        }


@dataclass
class User:
    class Gender(enum.Enum):
        MALE = "male"
        FEMALE = "female"

    username: str
    password: str
    gender: Gender = Gender.MALE

    @staticmethod
    def random_string(len: int) -> str:
        return "".join(choices(ascii_lowercase + ascii_uppercase, k=len))

    @classmethod
    def generate(cls, gender: Gender = Gender.MALE):
        username = User.random_string(randint(20, 30))
        password = User.random_string(randint(20, 30))

        return User(username=username, password=password, gender=gender)


@dataclass
class CheckerPrivateInfo:
    female_user: User
    cardId: int

    def serialize(self) -> str:
        bts = pickle.dumps(self)
        return bts.hex()

    @classmethod
    def deserialize(cls, raw: str):
        return pickle.loads(bytes.fromhex(raw))


@dataclass
class CheckMachine:
    checker: BaseChecker
    port: int = PORT

    @property
    def url(self):
        return f"http://{self.checker.host}:{self.port}"

    def __register(
        self,
        session: requests.Session,
        username: str,
        password: str,
        gender: str,
    ) -> requests.Response:
        return session.post(
            f"{self.url}/api/register",
            data={"username": username, "password": password, "gender": gender},
        )

    def __login(
        self,
        session: requests.Session,
        username: str,
        password: str,
    ) -> requests.Response:
        return session.post(
            f"{self.url}/api/login", data={"username": username, "password": password}
        )

    def __logout(
        self,
        session: requests.Session,
    ) -> requests.Response:
        return session.post(f"{self.url}/api/logout", data={})

    def register(self, session: requests.Session, user: User):
        return self.__register(
            session, user.username, user.password, str(user.gender.value)
        )

    def login(self, session: requests.Session, user: User):
        return self.__login(session, user.username, user.password)

    def logout(self, session: requests.Session):
        return self.__logout(session)

    def send_card(self, session: requests.Session, card: GiftCard) -> requests.Response:
        return session.post(f"{self.url}/api/add_card", data=card.toDict())

    def get_card(self, session: requests.Session, cardId: int) -> requests.Response:
        return session.get(f"{self.url}/api/card", params={"id": cardId})

    def isAuthenticated(self, session: requests.Session) -> bool:
        return session.get(f"{self.url}/api/check").status_code == 200
