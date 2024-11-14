#!/usr/bin/env python3

import sys
import requests

from checklib import cquit, BaseChecker
from card_lib import *


class Checker(BaseChecker):
    vulns: int = 4
    timeout: int = 15
    uses_attack_data: bool = True

    def __init__(self, *args, **kwargs):
        super(Checker, self).__init__(*args, **kwargs)
        self.mch = CheckMachine(self)

    def action(self, action, *args, **kwargs):
        try:
            super(Checker, self).action(action, *args, **kwargs)
        except requests.exceptions.ConnectionError:
            self.cquit(Status.DOWN, "Connection error", "Got requests connection error")

    def check_auth(self):
        male_user = User.generate(User.Gender.MALE)
        female_user = User.generate(User.Gender.FEMALE)

        male_session = self.get_initialized_session()
        female_session = self.get_initialized_session()

        response = self.mch.register(male_session, male_user)
        self.assert_eq(response.status_code, 200, "Failed to register", Status.MUMBLE)
        self.assert_in("session", response.cookies, "Failed to register", Status.MUMBLE)

        response = self.mch.login(male_session, male_user)
        self.assert_eq(response.status_code, 200, "Failed to login", Status.MUMBLE)

        response = self.mch.register(female_session, female_user)
        self.assert_eq(response.status_code, 200, "Failed to register", Status.MUMBLE)
        self.assert_in("session", response.cookies, "Failed to register", Status.MUMBLE)

        response = self.mch.login(female_session, female_user)
        self.assert_eq(response.status_code, 200, "Failed to login", Status.MUMBLE)
        self.assert_in("session", response.cookies, "Failed to login", Status.MUMBLE)

        response = self.mch.logout(male_session)
        self.assert_eq(
            self.mch.isAuthenticated(male_session),
            False,
            "Site available after logout",
            Status.CORRUPT,
        )

        response = self.mch.logout(female_session)
        self.assert_eq(
            self.mch.isAuthenticated(female_session),
            False,
            "Site available after logout",
            Status.CORRUPT,
        )

        return (male_user, female_user)

    def check_female_user(self, female_user):
        session = self.get_initialized_session()

        self.mch.login(session, female_user)

        card = GiftCard.generate(female_user.username, GiftCard.random_string(10))
        response = self.mch.send_card(session, card)
        self.assert_eq(
            response.status_code,
            404,
            "Could post card as a female (got not 404 response)",
            status=Status.CORRUPT,
        )

    def check_male_user(self, male_user):
        response_card: GiftCard

        session = self.get_initialized_session()
        card = GiftCard.generate(male_user.username, male_user.username)

        self.mch.login(session, male_user)
        response = self.mch.send_card(session, card)

        self.assert_eq(
            response.status_code,
            200,
            "Could not post a card as a male",
            status=Status.CORRUPT,
        )
        try:
            GiftCard.fromJSON(response.json())
        except Exception as e:
            self.cquit(Status.CORRUPT, "Could not parse response on card put", str(e))
            return

        response_card = GiftCard.fromJSON(response.json())

        self.assert_eq(
            response_card,
            card,
            "Return card does not match input card",
            status=Status.CORRUPT,
        )

    def check_card_exchange(self, male_user, female_user):
        male_session = self.get_initialized_session()
        female_session = self.get_initialized_session()

        self.mch.login(male_session, male_user)
        self.mch.login(female_session, female_user)

        card = GiftCard.generate(male_user.username, female_user.username)
        response_card = GiftCard.fromJSON(self.mch.send_card(male_session, card).json())
        try:
            r = self.mch.get_card(male_session, response_card.id)
            female_card = GiftCard.fromJSON(r.json())

            self.assert_eq(
                female_card, card, "Female card does not match male card", Status.ERROR
            )
        except Exception as e:
            self.cquit(
                Status.CORRUPT, "Could not get the same card as a female", str(e)
            )

    def check(self):
        male, female = self.check_auth()
        self.check_female_user(female)
        self.check_male_user(male)
        self.check_card_exchange(male, female)
        self.cquit(Status.OK)

    def put(self, flag_id: str, flag: str, vuln: str):
        male_user = User.generate(User.Gender.MALE)
        male_session = self.get_initialized_session()
        self.mch.register(male_session, male_user)

        female_user = User.generate(User.Gender.FEMALE)
        female_session = self.get_initialized_session()
        self.mch.register(female_session, female_user)

        card = GiftCard.generate(male_user.username, female_user.username)
        card.text = flag

        card = GiftCard.fromJSON(self.mch.send_card(male_session, card).json())

        private_info = CheckerPrivateInfo(female_user, card.id)

        self.cquit(Status.OK, female_user.username, private_info.serialize())

    def get(self, flag_id: str, flag: str, vuln: str):
        private_info = CheckerPrivateInfo.deserialize(flag_id)
        session = self.get_initialized_session()
        self.mch.login(session, private_info.female_user)

        card = GiftCard.fromJSON(self.mch.get_card(session, private_info.cardId).json())

        self.assert_eq(card.text, flag, "Invalid flag", Status.CORRUPT)
        self.cquit(Status.OK)


if __name__ == "__main__":
    c = Checker(sys.argv[2])

    try:
        c.action(sys.argv[1], *sys.argv[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)
