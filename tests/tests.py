#!/usr/bin/env python3
import os
import stat
import time
from pwd import getpwnam

import ldap
import ldif
from ldap.modlist import addModlist
import pytest
import importlib

import os, sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
caco_mela = importlib.import_module("caco-mela")

SUFFIX = "dc=example,dc=test"


class LdapConnection:
    def __init__(self):
        self.server = os.environ.get("LDAP_BIND_SERVER")
        self.bind_dn = os.environ.get("LDAP_BIND_DN")
        self.password = os.environ.get("LDAP_BIND_PASSWORD")

    def __enter__(self):
        self.conn = ldap.initialize(self.server)
        self.conn.protocol_version = ldap.VERSION3
        self.conn.simple_bind_s(self.bind_dn, self.password)
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.conn.unbind_s()


def recursive_delete(conn: ldap.ldapobject.SimpleLDAPObject, base_dn: str):
    search = conn.search_s(base_dn, ldap.SCOPE_ONELEVEL)
    for dn, _ in search:
        recursive_delete(conn, dn)
    conn.delete_s(base_dn)


def filter_lines_in_file(as_list):
    as_list_2 = []
    for line in as_list:
        if not line.startswith("#") and len(line.lstrip()) > 0:
            as_list_2.append(line)
    return as_list_2


class LdifReaderAdd(ldif.LDIFParser):
    def __init__(self, input_file, conn: ldap.ldapobject.SimpleLDAPObject):
        self.conn = conn
        super().__init__(input_file)

    def handle(self, dn, entry):
        addthis = addModlist(entry)
        self.conn.add_s(dn, addthis)


@pytest.fixture(autouse=True)
def create_users():
    for user in (
        "user1",
        "user2",
        "user3",
        "user4",
        "user5",
        "userTest",
        "userUnknown",
    ):
        os.system(f"userdel -rf {user}")
        os.system(f"useradd -m {user}")


@pytest.fixture()
def user3_old_key():
    os.mkdir("/home/user3/.ssh")
    with open("/home/user3/.ssh/authorized_keys", "w") as f:
        f.write(
            "# Example file with an old key to be removed\nssh-ed25519 AAAAAremovemeremovemeREMOVEMEremoveme123 oldololdold\n"
        )
        pw = getpwnam("user3")
        os.chown("/home/user3/.ssh/authorized_keys", pw.pw_uid, pw.pw_gid)
        os.chmod("/home/user3/.ssh/authorized_keys", 0o600)


@pytest.fixture()
def userunknown_old_key():
    os.mkdir("/home/userUnknown/.ssh")
    with open("/home/userUnknown/.ssh/authorized_keys", "w") as f:
        f.write(
            "# Example file with an old key to be removed\nssh-ed25519 AAAAA123removemeremovemeREMOVEMEremoveme123 oldololdold\n"
        )
        pw = getpwnam("userUnknown")
        os.chown("/home/userUnknown/.ssh/authorized_keys", pw.pw_uid, pw.pw_gid)
        os.chmod("/home/userUnknown/.ssh/authorized_keys", 0o600)


@pytest.fixture(autouse=True)
def reset_database():
    # the official container takes a while before 389DS actually accepts the password that was passed as an env var,
    # so we try to connect for 30 s and then actually reset the database
    done = False
    tries = 0
    while not done:
        try:
            with LdapConnection() as conn:
                done = True
        except ldap.INVALID_CREDENTIALS as e:
            tries += 1
            if tries > 30:
                raise e
            else:
                print(f"LDAP invalid credentials, attempt {str(tries)} failed")
                time.sleep(1)
        except ldap.SERVER_DOWN as e:
            tries += 1
            if tries > 30:
                raise e
            else:
                print(f"LDAP server down, attempt {str(tries)} failed")
                time.sleep(1)

    with LdapConnection() as conn:
        things = (
            f"ou=groups,{SUFFIX}",
            f"ou=people,{SUFFIX}",
        )

        for thing in things:
            try:
                recursive_delete(conn, thing)
            except ldap.NO_SUCH_OBJECT:
                pass

        # conn.modify_s('cn=config', [(ldap.MOD_REPLACE, 'nsslapd-dynamic-plugins', b'on')])
        # conn.modify_s('cn=MemberOf Plugin,cn=plugins,cn=config', [(ldap.MOD_REPLACE, 'nsslapd-pluginEnabled', b'on')])

        try:
            with open(
                str(os.path.join(os.path.dirname(__file__), "create-backend.ldif")),
                "rb",
            ) as f:
                parser = LdifReaderAdd(f, conn)
                parser.parse()
        except ldap.ALREADY_EXISTS:
            pass

        with open(
            str(os.path.join(os.path.dirname(__file__), "testdata.ldif")), "rb"
        ) as f:
            parser = LdifReaderAdd(f, conn)
            parser.parse()


def test_basic(user3_old_key):
    with open("tests/.env.test", "w") as file:
        file.write('LDAP_SEARCH_BASE="ou=people,dc=example,dc=test"\n')
        file.write(
            'LDAP_FILTER="(&(memberOf=cn=sysadmin,ou=groups,dc=example,dc=test)(!(nsAccountLock=true)))"\n'
        )
        file.write('LDAP_SEARCH_SSH_KEY_ATTR="nsSshPublicKey"\n')
        file.write('SSH_USER_OWNS_FILE="1"\n')
    caco_mela.main("tests/.env.test")

    assert os.path.isfile("/home/user1/.ssh/authorized_keys")
    assert os.path.isfile("/home/user2/.ssh/authorized_keys")
    assert os.path.isfile("/home/user3/.ssh/authorized_keys")
    assert os.path.isfile("/home/user5/.ssh/authorized_keys")
    assert not os.path.isfile("/home/user4/.ssh/authorized_keys")
    assert os.path.isfile("/home/userTest/.ssh/authorized_keys")
    assert not os.path.isfile("/home/userUnknown/.ssh/authorized_keys")

    for existing in ("user1", "user2", "user3", "user5", "userTest"):
        file = f"/home/{existing}/.ssh/authorized_keys"
        assert 0o600 == stat.S_IMODE(os.stat(file).st_mode)
        assert getpwnam(existing).pw_uid == os.stat(file).st_uid
        assert getpwnam(existing).pw_gid == os.stat(file).st_gid

        with open(file, "r") as f:
            as_string = f.read()
        with open(file, "r") as f:
            as_list = filter_lines_in_file(f.readlines())
        assert "This file is managed by Caco mela" in as_string
        as_list_2 = []
        for line in as_list:
            if not line.startswith("#") and len(line.lstrip()) > 0:
                as_list_2.append(line)
        if existing == "user1":
            assert [
                "ssh-ed25519 AAAAAAAi9s0dvjvjewjio0wevjwejvwejvowiwvesd foobarbaz\n"
            ] == as_list_2
        elif existing == "user2":
            assert [
                "ssh-ed25519 AAAAmviuewjuivjrvenuvlejnreiuvwejievwojviovewiofoobar\n",
                "ssh-ed25519 AAAACvSDMI62OVMImv2eMVMS5DIOV346EMVWIEO something\n",
            ].sort() == as_list_2.sort()
        elif existing == "user3":
            assert len(as_list_2) == 0
        elif existing == "user5":
            assert [
                "ssh-ed25519 AAAAArei90vw3jb49r8hvb738uewjvuierverv foobarbaz\n"
            ] == as_list_2
        elif existing == "userTest":
            assert len(as_list_2) == 0
        else:
            assert False, "Unknown user"


def test_ignored(user3_old_key):
    with open("tests/.env.test", "w") as file:
        file.write('LDAP_SEARCH_BASE="ou=people,dc=example,dc=test"\n')
        file.write(
            'LDAP_FILTER="(&(memberOf=cn=sysadmin,ou=groups,dc=example,dc=test)(!(nsAccountLock=true)))"\n'
        )
        file.write('LDAP_SEARCH_SSH_KEY_ATTR="nsSshPublicKey"\n')
        file.write('SSH_USER_OWNS_FILE="1"\n')
        file.write("IGNORED_ACCOUNTS=user1,user3,userTest\n")
    caco_mela.main("tests/.env.test")

    assert not os.path.isfile("/home/user1/.ssh/authorized_keys")
    assert os.path.isfile("/home/user2/.ssh/authorized_keys")
    assert os.path.isfile("/home/user3/.ssh/authorized_keys")
    assert os.path.isfile("/home/user5/.ssh/authorized_keys")
    assert not os.path.isfile("/home/user4/.ssh/authorized_keys")
    assert not os.path.isfile("/home/userTest/.ssh/authorized_keys")
    assert not os.path.isfile("/home/userUnknown/.ssh/authorized_keys")

    for existing in ("user2", "user5"):
        file = f"/home/{existing}/.ssh/authorized_keys"
        assert 0o600 == stat.S_IMODE(os.stat(file).st_mode)
        assert getpwnam(existing).pw_uid == os.stat(file).st_uid
        assert getpwnam(existing).pw_gid == os.stat(file).st_gid

        with open(file, "r") as f:
            as_string = f.read()
        with open(file, "r") as f:
            as_list = filter_lines_in_file(f.readlines())
        assert "This file is managed by Caco mela" in as_string
        if existing == "user2":
            assert [
                "ssh-ed25519 AAAAmviuewjuivjrvenuvlejnreiuvwejievwojviovewiofoobar\n",
                "ssh-ed25519 AAAACvSDMI62OVMImv2eMVMS5DIOV346EMVWIEO something\n",
            ].sort() == as_list.sort()
        elif existing == "user3":
            assert len(as_list) == 0
        elif existing == "user5":
            assert [
                "ssh-ed25519 AAAAArei90vw3jb49r8hvb738uewjvuierverv foobarbaz\n"
            ] == as_list
        else:
            assert False, "Unknown user"

    for existing in ("user3",):
        file = f"/home/{existing}/.ssh/authorized_keys"
        assert 0o600 == stat.S_IMODE(os.stat(file).st_mode)
        assert getpwnam(existing).pw_uid == os.stat(file).st_uid
        assert getpwnam(existing).pw_gid == os.stat(file).st_gid

        with open(file, "r") as f:
            as_string = f.read()
        with open(file, "r") as f:
            as_list = filter_lines_in_file(f.readlines())
        assert "This file is managed by Caco mela" not in as_string
        assert [
            "ssh-ed25519 AAAAAremovemeremovemeREMOVEMEremoveme123 oldololdold\n"
        ] == as_list


def test_deleted_user(userunknown_old_key):
    with open("tests/.env.test", "w") as file:
        file.write('LDAP_SEARCH_BASE="ou=people,dc=example,dc=test"\n')
        file.write(
            'LDAP_FILTER="(&(memberOf=cn=sysadmin,ou=groups,dc=example,dc=test)(!(nsAccountLock=true)))"\n'
        )
        file.write('LDAP_SEARCH_SSH_KEY_ATTR="nsSshPublicKey"\n')
        file.write('SSH_USER_OWNS_FILE="1"\n')
        file.write('IGNORED_ACCOUNTS=""\n')
    caco_mela.main("tests/.env.test")

    assert os.path.isfile("/home/userUnknown/.ssh/authorized_keys")

    existing = "userUnknown"
    file = f"/home/{existing}/.ssh/authorized_keys"
    assert 0o600 == stat.S_IMODE(os.stat(file).st_mode)
    assert getpwnam(existing).pw_uid == os.stat(file).st_uid
    assert getpwnam(existing).pw_gid == os.stat(file).st_gid

    with open(file, "r") as f:
        as_string = f.read()
    with open(file, "r") as f:
        as_list = filter_lines_in_file(f.readlines())
    assert "This file is managed by Caco mela" in as_string
    assert [] == as_list


def test_deleted_user_ignore(userunknown_old_key):
    with open("tests/.env.test", "w") as file:
        file.write('LDAP_SEARCH_BASE="ou=people,dc=example,dc=test"\n')
        file.write(
            'LDAP_FILTER="(&(memberOf=cn=sysadmin,ou=groups,dc=example,dc=test)(!(nsAccountLock=true)))"\n'
        )
        file.write('LDAP_SEARCH_SSH_KEY_ATTR="nsSshPublicKey"\n')
        file.write('SSH_USER_OWNS_FILE="1"\n')
        file.write('IGNORED_ACCOUNTS="userUnknown,user999"\n')
    caco_mela.main("tests/.env.test")

    assert os.path.isfile("/home/userUnknown/.ssh/authorized_keys")

    existing = "userUnknown"
    file = f"/home/{existing}/.ssh/authorized_keys"
    assert 0o600 == stat.S_IMODE(os.stat(file).st_mode)
    assert getpwnam(existing).pw_uid == os.stat(file).st_uid
    assert getpwnam(existing).pw_gid == os.stat(file).st_gid

    with open(file, "r") as f:
        as_string = f.read()
    with open(file, "r") as f:
        as_list = filter_lines_in_file(f.readlines())
    assert "This file is managed by Caco mela" not in as_string
    assert [
        "ssh-ed25519 AAAAA123removemeremovemeREMOVEMEremoveme123 oldololdold\n"
    ] == as_list
