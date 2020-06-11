import argparse
import requests
import hvac
import os

TOKEN = "s.HQDsVo77FweYhB2yL7D14RxP" or os.getenv('VAULT_TOKEN')
URL_VAULT = "http://127.0.0.1:8200" or os.getenv('VAULT_ADDR')

data = dict()
arr_data = list()


def get_vault_client(vault_url, token_id):
    client = hvac.Client(url=vault_url, token=token_id)
    if not client.is_authenticated():
        print("Failed to autentificate with Vault ({}) or token ({}) is wrong, please check server URL or/and your token".format(vault_url, token_id))
        return None
    else:
        return client


def mount_vault(vault_url, token_id, mount_point, ttl, description_message, domain_name):
    client = get_vault_client(vault_url, token_id)
    try:
        client.sys.enable_secrets_engine(backend_type='pki', path=mount_point, description=description_message)
        print("Successfully allocated secret for mountpoint: {} for server_vault: {}".format(mount_point, vault_url))
        client.sys.tune_mount_configuration(mount_point, default_lease_ttl=ttl, max_lease_ttl=ttl*2)
        # curl -X PUT -H "X-Vault-Request: true" -H "X-Vault-Token: $(vault print token)" 
        # -d '{"allow_any_name":"false","allow_glob_domains":"true","allow_subdomains":"true","allowed_domains":"mycompany-internal.org",
        # "enforce_hostnames":"false","ttl":"8760"}' http://127.0.0.1:8200/v1/issuing
        vault_url = vault_url + '/v1/' + mount_point
        headers_req = {'X-Vault-Request': true, 'X-Vault-Token': token_id}
        payload_req = {"allow_any_name":"false","allow_glob_domains":"true","allow_subdomains":"true","allowed_domains":domain_name,
            "enforce_hostnames":"false","ttl":ttl}
        req = requests.put(vault_url, data=payload_req, headers=headers_req)
 
    except:
        print("The path is already exist or something goes wrong with allocation of mountpoint: {} for server_vault: {}".format(mount_point, vault_url))
        return None


# setting up the argument parser enities to apply
arg_parser = argparse.ArgumentParser(
    description='This tool is generating the CAs based on the config file, you can use also dry-run option')

arg_parser.add_argument('-config', metavar='path_to_conf', type=str, required=True,
                        help='please use the path to the correct config file')
arg_parser.add_argument('--dry-run', action='store_true', required=False, default=False,
                        help='please use it just to simulate the run')
args = arg_parser.parse_args()

# reading the content of file
try:
    try:
        cert_file = open(args.config, 'r')
        for line in cert_file.readlines():
            data['path'], data['domain'], data['issuer'], data['ttl'] = line.replace("\n", "").split("|")
            # data.copy() is because of the just data will be used every time at for, to alway get new items to array
            arr_data.append(data.copy())
    finally:
        cert_file.close()
except:
    print("The file cannot be opened or something goes worng, please check the file")
    exit()

# checking if dry-run is required, afterwards the EXIT will happen
if args.dry_run:
    print("By using dry-run option, we will be creating this secret for those autorieties, WITHOUT any real modifications:")
    for elem in arr_data:
        print("Mounting {} for {} with issuer {} by TTL: {}".format(
            elem['path'], elem['domain'], elem['issuer'], elem['ttl']))
    exit()

# client_hvac = hvac.Client(URL_VAULT, namespace=os.getenv('VAULT_NAMESPACE'))  # if we will require to set up namespace TEST purposes

for element in arr_data:
    mount_vault(URL_VAULT, TOKEN, element['path'], element['ttl'],"The secret for " + element['domain'] + " from " + element['issuer'],
        element['domain'])

# print(get_vault_client(URL_VAULT, TOKEN))
