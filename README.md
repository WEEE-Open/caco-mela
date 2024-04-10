# Caco mela
_Creatore Automatico di Chiavi Operante Mediante Estrazione da LDAP Artigianale_

Read SSH public keys from a LDAP server, add them to authorized_keys file for the corresponding user, without looking at uid and gid numbers.

Only user accounts (UID between UID_MIN and UID_MAX, read from /etc/login.defs) will be considered for update.  
All SSH keys will be replaced for all users, with no keys if the user is not found on the LDAP server: this is useful to lock accounts of users that should not be allowed to access the server anymore, just make sure they are excluded from the LDAP filter.  
Additionally, it is possible to set users that can be ignored with IGNORED_ACCOUNTS or with command line parameters: Caco mela will not modify the authorized_keys of those users. 

## Install

```shell
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configure

Three ways to pass options are possible:

1. Command line arguments, see `caco_mela.py --help` for details
2. Environment variables
3. A `.env` file, see `.env.example`

If a variable is set multiple times, the one higher in this list will take precedence.  
All UPPER_CASE names in `caco_mela.py --help` correspond to an environment variable with the same name.

## Run

Create a systemd unit and timer, a cron job or any other similar mechanism to run the program every X minutes.
