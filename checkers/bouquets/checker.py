#!/usr/bin/env python3


import sys
import requests
from checklib import *
from bouquet_lib import *
import json


class Checker(BaseChecker):
    vulns: int = 2
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
        user = User.random()
        session = self.get_initialized_session()
        self.mch.register_user(session, user)
        profile = self.mch.profile_check(session)
        self.assert_eq(profile.username, user.username, "Username is different")

        self.assert_eq(
            profile.preferences, user.preferences, "Preferences are different"
        )

        self.mch.logout(session)
        self.mch.login(session, user)

    def check_filter(self):
        user = User.random()
        user_session = self.get_initialized_session()
        self.mch.register_user(user_session, user)
        bouquet = Bouquet.random()
        self.mch.create_bouquet(user_session, bouquet)
        field, value = "name", bouquet.name
        for _ in range(2):
            self.mch.create_bouquet(user_session, Bouquet.random())
        got_bouquet = self.mch.filter_bouquet(user_session, field, value)
        self.assert_eq(
            len(got_bouquet.id),
            1,
            "Filter do not work correctly, multiple rows unexpected",
        )

        self.assert_eq(
            got_bouquet.name[0],
            bouquet.name,
            "Filter do not work correctly, names are different",
        )

        self.assert_eq(
            got_bouquet.description[0],
            bouquet.description,
            "Filter do not work correctly, descriptions are different",
        )
        field, value = "description", bouquet.description
        got_bouquet = self.mch.filter_bouquet(user_session, field, value)
        self.assert_eq(
            len(got_bouquet.id),
            1,
            "Filter do not work correctly, multiple rows unexpected",
        )

        self.assert_eq(
            got_bouquet.name[0],
            bouquet.name,
            "Filter do not work correctly, names are different",
        )

        self.assert_eq(
            got_bouquet.description[0],
            bouquet.description,
            "Filter do not work correctly, descriptions are different",
        )

    def check_send_receive(self):
        first = User.random()
        second = User.random()
        first_session = self.get_initialized_session()
        second_session = self.get_initialized_session()
        self.mch.register_user(first_session, first)
        self.mch.register_user(second_session, second)
        bouquet = Bouquet.random()
        self.mch.create_bouquet(first_session, bouquet)
        bouquet_got = self.mch.filter_bouquet(
            first_session, "description", bouquet.description
        )
        self.assert_eq(
            len(bouquet_got.id),
            1,
            "Filter do not work correctly, multiple rows unexpected",
        )

        self.assert_eq(
            bouquet_got.name[0],
            bouquet.name,
            "Filter do not work correctly, names are different",
        )

        self.assert_eq(
            bouquet_got.description[0],
            bouquet.description,
            "Filter do not work correctly, descriptions are different",
        )

        self.mch.send_bouquet(first_session, second.username, bouquet_got.id)

        name, description, user_from = self.mch.given_bouquets(
            second_session, first.username
        )
        assert_eq(
            len(name),
            1,
            "Give error, should be 1 given bouquet",
        )
        assert_eq(
            name[0],
            bouquet.name,
            "Give error, Bouquets names are different",
        )

        assert_eq(
            description[0],
            bouquet.description,
            "Give error, bouques descriptions are different",
        )
        assert_eq(
            user_from[0], first.username, "Give Error, bouquets senders are different"
        )

    def check_subscribe(self):
        user = User.random()
        user_session = self.get_initialized_session()
        self.mch.register_user(user_session, user)
        msg = self.mch.try_subscribe(user_session)

        assert_eq(
            msg,
            "Sorry, but You can't pay in full in the future",
            "Subscribe error, can't try to get privileges",
        )

    def check_superuser_subscribe(self):
        user = User.random()
        user_session = self.get_initialized_session()
        self.mch.register_user(user_session, user)

        admin_session = self.get_initialized_session()
        signature = self.mch.sign_uuid(admin_session)
        self.mch.verify_signature(admin_session, signature)
        msg = str(self.mch.try_subscribe(admin_session)).strip()
        assert_eq(
            msg,
            "You are privilleged user! You can find preferences of other users",
            "Subscribe error, can't get privileges by superuser",
        )

        profile = self.mch.user_search(admin_session, user.username)

        assert_eq(len(profile.username), 1, "Only one user should be after searching")

        assert_eq(
            profile.username[0], user.username, "Cant get username from user search"
        )

        assert_eq(
            profile.preferences[0],
            user.preferences,
            "Cant get user description from user search",
        )

    def check(self):
        self.check_auth()
        self.check_filter()
        self.check_send_receive()
        self.check_subscribe()
        self.check_superuser_subscribe()
        self.cquit(Status.OK)

    def put(self, flag_id: str, flag: str, vuln: str):
        user = User.random()
        session = self.get_initialized_session()
        if vuln == "1":
            user.preferences = flag
            self.mch.register_user(session, user)
            self.cquit(
                Status.OK,
                json.dumps({"username": user.username, "location": "user_preferences"}),
                user.serialize(),
            )
        else:
            self.mch.register_user(session, user)
            bouquet = Bouquet.random()
            bouquet.description = flag
            self.mch.create_bouquet(session, bouquet)
            self.cquit(
                Status.OK,
                json.dumps(
                    {"username": user.username, "location": "bouquet_description"}
                ),
                user.serialize(),
            )

    def get(self, flag_id: str, flag: str, vuln: str):
        user = User.deserialize(flag_id)
        session = self.get_initialized_session()
        self.mch.login(session, user, Status.CORRUPT)
        if vuln == "1":
            profile = self.mch.profile_check(session)
            self.assert_eq(
                profile.preferences, flag, "Preferences are invalid", Status.CORRUPT
            )
        else:
            bouquet = self.mch.filter_bouquet(session, "", "")
            self.assert_in(
                flag, bouquet.description, "Descriptions are invalid", Status.CORRUPT
            )
        self.cquit(Status.OK)


if __name__ == "__main__":
    c = Checker(sys.argv[2])

    try:
        c.action(sys.argv[1], *sys.argv[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)
