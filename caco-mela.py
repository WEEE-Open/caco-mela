#!/usr/bin/env python
import argparse
import os

import ldap
from dotenv import load_dotenv, dotenv_values, find_dotenv


def set_default(var: str, default: str):
	if var not in config or config[var] is None:
		config[var] = default


def parse_args() -> dict[str, str | bool]:
	global config
	parser = argparse.ArgumentParser(description='Provision SSH keys from a LDAP server, without syncing UIDs.', prog="caco-mela")
	parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')
	parser.add_argument('-l', '--ldap', dest='LDAP_BIND_SERVER', type=str, help="LDAP server address")
	parser.add_argument('-D', '--binddn', dest='LDAP_BIND_DN', type=str, help="LDAP bind DN")
	parser.add_argument('-w', '--bindpw', dest='LDAP_BIND_PASSWORD', type=str, help="LDAP bind password")
	parser.add_argument('-t', '--starttls', action='store_true', dest='LDAP_STARTTLS', help="Use LDAP_STARTTLS")
	parser.add_argument('-s', '--search', dest='LDAP_SEARCH_BASE', type=str, help="LDAP search base")
	parser.add_argument('-f', '--filter', dest='LDAP_FILTER', type=str, help="LDAP filter")
	parser.add_argument('-a', '--authorized', dest='AUTHORIZED_KEYS_FILES', type=str, help="Value of sshd option AuthorizedKeysFile")
	parser.add_argument('--key', dest='LDAP_SEARCH_SSH_KEY_ATTR', type=str, help="Attribute containing the SSH public key")
	parser.add_argument('--uid', dest='LDAP_SEARCH_SSH_UID_ATTR', type=str, help="Attribute containing the username")
	parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output")
	parser.add_argument('ignored_accounts', nargs='*', type=str, help="Accounts to ignore")
	args = parser.parse_args()
	load_dotenv(find_dotenv())
	config = dict()
	for key, val in vars(args).items():
		config[key] = os.environ.get(key) if val is None else val
	set_default('LDAP_SEARCH_SSH_KEY_ATTR', 'sshPublicKey')
	set_default('LDAP_SEARCH_SSH_UID_ATTR', 'uid')
	if isinstance(config['LDAP_STARTTLS'], str):
		config['LDAP_STARTTLS'] = config['LDAP_STARTTLS'].lower() not in ('0', 'no', 'false', 'n', 'off')
	return config


if __name__ == "__main__":
	config = parse_args()

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
						add[result_data[0][1][config['LDAP_SEARCH_SSH_UID_ATTR']][0].decode('ascii')] = [x.decode('ascii') for x in result_data[0][1][config['LDAP_SEARCH_SSH_KEY_ATTR']]]
					else:
						print(f"No attribute {config['LDAP_SEARCH_SSH_KEY_ATTR']}, ignoring")
				else:
					print(f"No attribute {config['LDAP_SEARCH_SSH_UID_ATTR']}, ignoring")
			else:
				break
	except ldap.LDAPError as e:
		print(f"LDAP Error: {e}")
		exit(1)
	finally:
		conn.unbind_s()

	print(add)
