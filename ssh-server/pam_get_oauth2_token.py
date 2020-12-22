import site
site.main()

import requests
import time
import qrcode
import yaml
import syslog
import json
import secrets


def pam_sm_authenticate(pamh, flags, argv):

    syslog.syslog('pam_sm_authenticate')

    try:
        
        args = parse_args(argv)

        config = load_config(args['config_file'])

        authorization = ask_vault_dag_authorization_request(config)

        print_authentication_promt(pamh, config, authorization)

        syslog.syslog(str(authorization))

        vault_response = poll_vault_for_refresh_token(pamh, config, authorization)

        store_vault_token(vault_response)

        store_credkey(vault_response)

        store_refresh_token_vault(vault_response)

        bearer_token_response = get_bearer_token(vault_response)

        print_token(pamh, config, bearer_token_response)

        return pamh.PAM_SUCCESS

    except BaseException as e:
        print e
        return pamh.PAM_SUCCESS

def parse_args(argv):

    syslog.syslog('parse_args')
    
    args = {
        'config_file': argv[1] if len(argv) > 1 else None
    }
    return args


def load_config(file_name):

    syslog.syslog('load_config')
    
    if file_name is None:
        file_name = '/lib/security/config.yml'
    with open(file_name, 'r') as stream:
        return yaml.safe_load(stream)

def ask_vault_dag_authorization_request(config):

    syslog.syslog('ask_vault_dag_authorization_request')

    # Redirect uri, vault_role and vault url to config
    nonce = secrets.token_urlsafe()
    vaultdata = {
        'role': 'default',
        'client_nonce': nonce,
        'redirect_uri': 'http://172.18.1.7:8200/v1/auth/oidc-default/oidc/callback'
    }

    data = json.dumps(vaultdata)

    vault_response = requests.post(
        'http://172.18.1.7:8200/v1/auth/oidc-default/oidc/auth_url',
        data = data.encode()
    )

    if 'errors' in vault_response.json():
        raise Oauth2Exception(vault_response.json()['error'], vault_response.json()['error_description'])

    data_response = vault_response.json()
    data_response['client_nonce'] = nonce

    return data_response

def print_authentication_promt(pamh, config, authorization):

    syslog.syslog('print_authentication_promt')
    
    url = str(authorization['data']['auth_url'])

    qr_str = generate_qr(url, config)

    prompt(pamh, config['texts']['prompt'].format(url=url, qr=qr_str))


def poll_vault_for_refresh_token(pamh, config, authorization):

    syslog.syslog('poll_vault_for_refresh_token')
    
    # Meterlo en config tambien
    url = 'http://172.18.1.7:8200/v1/auth/oidc-default/oidc/poll'

    vaultdata = {
        'state': str(authorization['data']['state']),
        'client_nonce': str(authorization['client_nonce'])
    }

    timeout = 300
    interval = int(authorization['data']['poll_interval'])

    while True:
        time.sleep(interval)
        timeout -= interval

        vault_response = requests.post(
            url,
            data=json.dumps(vaultdata).encode()
        )

        if 'errors' in vault_response.json():

            if vault_response.json()['errors'][0] == 'authorization_pending':
                syslog.syslog('Authorization pending')
                pass

            elif vault_response.json()['errors'][0] == 'slow_down':
                syslog.syslog('Slow down')
                interval += 1
                pass

            else:
                raise Oauth2Exception(vault_response.json()['errors'], vault_response.json()['error_description'])

        else:
            break

        if timeout < 0:
            # send(pamh, 'Timeout, please try again')
            raise Oauth2Exception(vault_response.json()['errors'], vault_response.json()['error_description'])

    return vault_response.json()

def store_vault_token(vault_response):

    syslog.syslog('store_vault_token')

    vault_token = vault_response['auth']['client_token']

    file = open("/tmp/vault_token", "w")
    file.write(str(vault_token))
    file.close()

def store_credkey(vault_response):

    syslog.syslog('store_credkey')

    cred_key = vault_response['auth']['metadata']['credkey']

    file = open("/home/credkey-default-default", "w")
    file.write(str(cred_key))
    file.close()

def store_refresh_token_vault(vault_response):

    syslog.syslog('store_refresh_token_vault')

    cred_key = vault_response['auth']['metadata']['credkey']
    role = vault_response['auth']['metadata']['role']
    refresh_token = vault_response['auth']['metadata']['oauth2_refresh_token']
    url = 'http://172.18.1.7:8200/v1/secret/oauth-default/creds/' + cred_key +':' + role
    headers = {
        'X-Vault-Token': str(vault_response['auth']['client_token'])
    }

    body = {
        'refresh_token': str(refresh_token)
    }

    data_refresh = json.dumps(body)

    store_response = requests.post(
        url,
        headers = headers,
        data = data_refresh.encode()
    )


def get_bearer_token(vault_response):

    syslog.syslog('get_bearer_token')


    cred_key = vault_response['auth']['metadata']['credkey']
    role = vault_response['auth']['metadata']['role']

    url = 'http://172.18.1.7:8200/v1/secret/oauth-default/creds/' + cred_key +':' + role + '?minimum_seconds=60'
    headers = {'X-Vault-Token': vault_response['auth']['client_token']}

    # send(pamh, 'Getting bearer token at ' + url)

    get_response = requests.get(
        url,
        headers = headers
    )

    if 'errors' in get_response.json():
        raise Oauth2Exception(get_response.json()['error'], get_response.json()['error_description'])


    return get_response.json()

def print_token(pamh, config, token_response):

    syslog.syslog('print_token')

    send(pamh, 'bearer_token: '+str(token_response['data']['access_token']))
    raise Oauth2Exception('Display token', str(token_response['data']['access_token']))

def generate_qr(str, config):

    syslog.syslog('generate_qr')
    
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(str)
    qr.make()

    if config['qr']['big']:
        return generate_qr_big(qr.modules, config)
    else:
        return generate_qr_small(qr.modules, config)


def generate_qr_small(modules, config):

    syslog.syslog('generate_qr_small')
    
    before_line = config['qr']['before_line']
    after_line = config['qr']['after_line']

    qr_str = before_line
    qr_str += qr_half_char(False, False, config)
    for x in range(0, len(modules[0])):
        qr_str += qr_half_char(False, False, config)
    qr_str += qr_half_char(False, False, config) + after_line + '\n'

    for y in range(0, len(modules)//2+1):
        qr_str += before_line + qr_half_char(False, False, config)
        for x in range(0, len(modules[0])):
            qr_str += qr_half_char(
                modules[y*2][x],
                modules[y*2+1][x] if len(modules) > y*2+1 else False,
                config
            )
        qr_str += qr_half_char(False, False, config)
        if y != len(modules)//2:
            qr_str += after_line + '\n'

    return qr_str


def generate_qr_big(modules, config):

    syslog.syslog('generate_qr_big')
    
    before_line = config['qr']['before_line']
    after_line = config['qr']['after_line']

    qr_str = before_line

    qr_str += qr_full_char(False, config)
    for x in range(0, len(modules[0])):
        qr_str += qr_full_char(False, config)
    qr_str += qr_full_char(False, config) + after_line + '\n'

    for y in range(0, len(modules)):
        qr_str += before_line + qr_full_char(False, config)
        for x in range(0, len(modules[0])):
            qr_str += qr_full_char(modules[y][x], config)
        qr_str += qr_full_char(False, config) + after_line + '\n'

    qr_str += before_line + qr_full_char(False, config)
    for x in range(0, len(modules[0])):
        qr_str += qr_full_char(False, config)
    qr_str += qr_full_char(False, config) + after_line

    return qr_str


def qr_half_char(top, bot, config):

    syslog.syslog('qr_half_char')
    
    if config['qr']['inverse']:
        if top and bot:
            return '\033[40;97m\xE2\x96\x88\033[0m'
        if not top and bot:
            return '\033[40;97m\xE2\x96\x84\033[0m'
        if top and not bot:
            return '\033[40;97m\xE2\x96\x80\033[0m'
        if not top and not bot:
            return '\033[40;97m\x20\033[0m'
    else:
        if top and bot:
            return '\033[40;97m\x20\033[0m'
        if not top and bot:
            return '\033[40;97m\xE2\x96\x80\033[0m'
        if top and not bot:
            return '\033[40;97m\xE2\x96\x84\033[0m'
        if not top and not bot:
            return '\033[40;97m\xE2\x96\x88\033[0m'


def qr_full_char(filled, config):

    syslog.syslog('qr_full_char')
    
    if config['qr']['inverse']:
        if filled:
            return '\033[40;97m\xE2\x96\x88\xE2\x96\x88\033[0m'
        else:
            return '\033[40;97m\x20\x20\033[0m'
    else:
        if filled:
            return '\033[40;97m\x20\x20\033[0m'
        else:
            return '\033[40;97m\xE2\x96\x88\xE2\x96\x88\033[0m'


def send(pamh, msg):

    syslog.syslog('send')

    
    return pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, msg))


def prompt(pamh, msg):

    syslog.syslog('prompt')

    
    return pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_ON, msg))


class Oauth2Exception(Exception):
    pass


# Need to implement all methods to fulfill pam_python contract

def pam_sm_setcred(pamh, flags, argv):

    syslog.syslog('pam_sm_setcred')

    
    return pamh.PAM_SUCCESS


def pam_sm_acct_mgmt(pamh, flags, argv):

    syslog.syslog('pam_sm_acct_mgmt')

    
    return pamh.PAM_SUCCESS


def pam_sm_open_session(pamh, flags, argv):

    syslog.syslog('pam_sm_open_session')

    
    return pamh.PAM_SUCCESS


def pam_sm_close_session(pamh, flags, argv):

    syslog.syslog('pam_sm_close_session')

    
    return pamh.PAM_SUCCESS


def pam_sm_chauthtok(pamh, flags, argv):

    syslog.syslog('pam_sm_chauthtok')

    
    return pamh.PAM_SUCCESS