#!/usr/bin/env python
import argparse
import os
import pwd
from typing import Optional, Union

import ldap
from dotenv import load_dotenv, find_dotenv


def set_default(config: dict, var: str, default: str):
	if var not in config or config[var] is None:
		config[var] = default


def set_boolean(config: dict, var: str):
	if isinstance(config[var], str):
		config[var] = config[var].lower() not in ('0', 'no', 'false', 'n', 'off')


def parse_args(tests_env: Optional[str] = None) -> dict[str, Union[str, bool]]:
	parser = argparse.ArgumentParser(description='Provision SSH keys from a LDAP server, without syncing UIDs.', prog="caco-mela")
	parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')
	parser.add_argument('-l', '--ldap', dest='LDAP_BIND_SERVER', type=str, help="LDAP server address")
	parser.add_argument('-D', '--binddn', dest='LDAP_BIND_DN', type=str, help="LDAP bind DN")
	parser.add_argument('-w', '--bindpw', dest='LDAP_BIND_PASSWORD', type=str, help="LDAP bind password")
	parser.add_argument('-t', '--starttls', action='store_true', dest='LDAP_STARTTLS', help="Use LDAP_STARTTLS")
	parser.add_argument('-s', '--search', dest='LDAP_SEARCH_BASE', type=str, help="LDAP search base")
	parser.add_argument('-f', '--filter', dest='LDAP_FILTER', type=str, help="LDAP filter")
	parser.add_argument('--key', dest='LDAP_SEARCH_SSH_KEY_ATTR', type=str, help="Attribute containing the SSH public key")
	parser.add_argument('--uid', dest='LDAP_SEARCH_SSH_UID_ATTR', type=str, help="Attribute containing the username")
	parser.add_argument('-a', '--authorized', dest='SSH_AUTHORIZED_KEYS_FILES', type=str, help="Value of sshd option AuthorizedKeysFile")
	parser.add_argument('--user-owns-file', dest='SSH_USER_OWNS_FILE', action='store_true', help="Users are set to owners of their authorized_keys file, if the file is created")
	parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output")
	parser.add_argument('IGNORED_ACCOUNTS', nargs='*', type=str, help="Accounts to ignore")
	if tests_env is not None:
		args = parser.parse_args([])
		load_dotenv(tests_env, override=True)
		print(os.environ)
	else:
		args = parser.parse_args()
		load_dotenv()
	config = dict()
	for key, val in vars(args).items():
		config[key] = os.environ.get(key) if (val is None or val is False) else val
	set_default(config, 'LDAP_SEARCH_SSH_KEY_ATTR', 'sshPublicKey')
	set_default(config, 'LDAP_SEARCH_SSH_UID_ATTR', 'uid')
	set_default(config, 'SSH_AUTHORIZED_KEYS_FILES', '')
	set_boolean(config, 'LDAP_STARTTLS')
	set_boolean(config, 'SSH_USER_OWNS_FILE')
	if len(config['IGNORED_ACCOUNTS']) == 0:
		config['IGNORED_ACCOUNTS'] = set(os.environ.get('IGNORED_ACCOUNTS', default='').split(','))
	else:
		config['IGNORED_ACCOUNTS'] = set(config['IGNORED_ACCOUNTS'])

	return config


def get_data_from_server(config):
	conn = ldap.initialize(config['LDAP_BIND_SERVER'])
	try:
		conn.protocol_version = ldap.VERSION3
		conn.simple_bind_s(config['LDAP_BIND_DN'], config['LDAP_BIND_PASSWORD'])
		if config['LDAP_STARTTLS']:
			conn.start_tls_s()
	except ldap.LDAPError as e:
		print(f"LDAP Error: {e}")
		exit(1)
	if config['LDAP_STARTTLS']:
		try:
			conn.start_tls_s()
		except ldap.LDAPError as e:
			print(f"LDAP Error: {e}")
			exit(1)
		finally:
			conn.unbind_s()
	add = dict()
	try:
		ldap_result_id = conn.search(config['LDAP_SEARCH_BASE'], ldap.SCOPE_SUBTREE, config['LDAP_FILTER'], [config['LDAP_SEARCH_SSH_KEY_ATTR'], config['LDAP_SEARCH_SSH_UID_ATTR']])
		while 1:
			result_type, result_data = conn.result(ldap_result_id, 0)
			if result_type == ldap.RES_SEARCH_ENTRY:
				if config['verbose']:
					print(f"Parsing result {result_data[0][0]}")
				if config['LDAP_SEARCH_SSH_UID_ATTR'] in result_data[0][1]:
					if config['LDAP_SEARCH_SSH_KEY_ATTR'] in result_data[0][1]:
						add[result_data[0][1][config['LDAP_SEARCH_SSH_UID_ATTR']][0].decode('ascii')] = [
							x.decode('ascii') for x in result_data[0][1][config['LDAP_SEARCH_SSH_KEY_ATTR']]]
					else:
						add[result_data[0][1][config['LDAP_SEARCH_SSH_UID_ATTR']][0].decode('ascii')] = []
						if config['verbose']:
							print(f"No attribute {config['LDAP_SEARCH_SSH_KEY_ATTR']} for user {result_data[0][0]}, SSH keys will be removed")
				else:
					if config['verbose']:
						print(f"No attribute {config['LDAP_SEARCH_SSH_UID_ATTR']} for user {result_data[0][0]}, ignoring")
			else:
				break
	except ldap.LDAPError as e:
		print(f"LDAP Error: {e}")
		exit(1)
	finally:
		conn.unbind_s()
	return add


def read_login_defs(config: dict):
	uid_min = 1000
	uid_max = 60000
	with open('/etc/login.defs', 'r') as file:
		for line in file:
			line = line.lstrip()
			if len(line) == 0 or line.startswith('#'):
				continue
			if line.startswith('UID_MIN') or line.startswith('UID_MAX'):
				split = line.split()
				if len(split) > 1:
					value = int(split[1])
					if line.startswith('UID_MIN'):
						uid_min = value
						if config['verbose']:
							print(f"Obtained UID_MIN: {str(uid_min)}")
					else:
						uid_max = value
						if config['verbose']:
							print(f"Obtained UID_MAX: {str(uid_max)}")
	return uid_min, uid_max


def ssh_authorized_keys_file(config, user: pwd.struct_passwd, create: bool = True):
	if len(config['SSH_AUTHORIZED_KEYS_FILES']) > 0:
		path = config['SSH_AUTHORIZED_KEYS_FILES'].replace('%u', user.pw_name)
	else:
		dotssh = os.path.join(user.pw_dir, '.ssh')
		if create and not os.path.exists(dotssh):
			os.mkdir(dotssh)
			os.chown(dotssh, user.pw_uid, user.pw_gid)
		path = os.path.join(user.pw_dir, '.ssh', 'authorized_keys')
	if config['verbose']:
		print(f"User {user.pw_name} file is {path}")

	if create and not os.path.exists(path):
		if config['verbose']:
			print(f"Creating {path}")
		with open(path, 'w'):
			pass
		if config['SSH_USER_OWNS_FILE']:
			if config['verbose']:
				print(f"Setting owner to {user.pw_uid}:{user.pw_gid} and mode to 600 for file {path}")
			os.chown(path, user.pw_uid, user.pw_gid)
		else:
			if config['verbose']:
				print(f"Setting mode to 600 for file {path}")
		os.chmod(path, 0o600)

	return path


def update_file(ssh_file, text) -> bool:
	with open(ssh_file, 'r') as file:
		current = file.read()
	if text != current:
		with open(ssh_file, 'w') as file:
			file.write(text)
			return True
	return False


def generate_text(keys: list[str]):
	keys_text = '\n'.join(keys) if len(keys) else '# No SSH keys for this user'
	write_this = f"#\n# This file is managed by Caco mela ({__file__})\n# All manual changes will be overwritten.\n#\n{keys_text}\n"
	return write_this


def main(tests_env: Optional[str] = None):
	config = parse_args(tests_env)
	results = get_data_from_server(config)
	uid_min, uid_max = read_login_defs(config)

	for user in pwd.getpwall():
		if uid_min <= user.pw_uid <= uid_max:
			if user.pw_name in config['IGNORED_ACCOUNTS']:
				if config['verbose']:
					print(f"Ignoring user {user.pw_name} due to IGNORED_ACCOUNTS")
				continue
			if user.pw_name in results:
				text = generate_text(results[user.pw_name])
				ssh_file = ssh_authorized_keys_file(config, user)
				if update_file(ssh_file, text):
					print(f"Updated user {user.pw_name} with {str(len(results[user.pw_name]))} SSH keys")
				elif config['verbose']:
					print(f"No change for user {user.pw_name} with {str(len(results[user.pw_name]))} SSH keys")
			else:
				ssh_file = ssh_authorized_keys_file(config, user, False)
				if os.path.exists(ssh_file):
					if config['verbose']:
						print(f"User {user.pw_name} not found in LDAP server, removing keys")
					text = generate_text([])
					if update_file(ssh_file, text):
						print(f"Updated user {user.pw_name} by removing all SSH keys")
					elif config['verbose']:
						print(f"No change for user {user.pw_name} with 0 SSH keys")


if __name__ == "__main__":
	main()
	exit(0)
