import argparse
import requests
import hvac
import os

TOKEN = "s.zGIzd4rqvDFm0mlItFTKclyB" or os.getenv('VAULT_TOKEN')
URL_VAULT = "http://127.0.0.1:8200" or os.getenv('VAULT_ADDR')

data = dict()
arr_data = list()


def get_vault_client(vault_url, token_id):
    client_hvac = hvac.Client(url=vault_url, token=token_id)
    if not client_hvac.is_authenticated():
        print("Failed to autentificate with Vault ({}) or token ({}) is wrong, please check server URL or/and your token".format(vault_url, token_id))
        return None
    else:
        return client_hvac



def mount_vault(mount_point, ttl, description_message, domain_name, issuer):
    headers = {
        'X-Vault-Request': 'true',
        'X-Vault-Token': TOKEN,
    }
    try:
        if "/" in mount_point:
            mount_point, root = mount_point.split('/')[-1], mount_point.split('/')[-2]
            client.sys.enable_secrets_engine(backend_type='pki', path=mount_point, description=description_message)
            client.sys.tune_mount_configuration(mount_point, default_lease_ttl=ttl, max_lease_ttl=int(ttl)*2)
            
            # Vault CLI for generating a Certificate Signing Request
            data = '{"common_name":"' + domain_name + ' Intermediate Authority","ttl":"' + ttl + '"}'
            response = requests.put(URL_VAULT + '/v1/' + mount_point + '/intermediate/generate/internal', headers=headers, data=data)
            json_out = response.json()
            json_out_sign_req = json_out['data']['csr']

            # Sign the CSR, note the use of the pem_bundle format and the ttl
            data = '{"csr":"'+ json_out_sign_req + '","format":"pem_bundle","ttl":"' + ttl + '"}'
            response = requests.post(URL_VAULT + '/v1/' + root + '/root/sign-intermediate', headers=headers, data=data)
            
            json_out = response.json()
            json_out_sign_req = json_out['data']['certificate']
            
            data = '{"certificate":"' +  json_out_sign_req + '","format":"pem_bundle","ttl":"' + ttl + '"}'
            response = requests.post(URL_VAULT + '/v1/' + mount_point + '/intermediate/set-signed', headers=headers, data=data)
            

            # create a role based on raw REST call:

            data = '{"allow_any_name":"false","allow_glob_domains":"true","allow_subdomains":"true","allowed_domains": "' + domain_name + '","enforce_hostnames":"false","ttl": "' + str(ttl) +'"}'
            requests.put(URL_VAULT + '/v1/' + mount_point + '/roles/testrole', headers=headers, data=data)
            return None  #escape after configuration of intermediate CA

        client.sys.enable_secrets_engine(backend_type='pki', path=mount_point, description=description_message)
        client.sys.tune_mount_configuration(mount_point, default_lease_ttl=ttl, max_lease_ttl=int(ttl)*2)
        
        # create a role based on raw REST call:
        data = '{"allow_any_name":"false","allow_glob_domains":"true","allow_subdomains":"true","allowed_domains": "' + domain_name + '","enforce_hostnames":"false","ttl": "' + str(ttl) +'"}'
        requests.put(URL_VAULT + '/v1/' + mount_point + '/roles/testrole', headers=headers, data=data)
        
        #create the ROOT CA based on raw REST call
        data = '{"common_name":"' + issuer + '"}'
        requests.put(URL_VAULT + '/v1/' + mount_point + '/root/generate/internal', headers=headers, data=data)

    except:
        print("The path is already exist or something goes wrong with allocation of mountpoint: {}".format(mount_point))
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
    cert_file = open(args.config, 'r')
    for line in cert_file.readlines():
        data['path'], data['domain'], data['issuer'], data['ttl'] = line.replace("\n", "").split("|")
        # data.copy() is because of the just data will be used every time at for, to alway get new items to array
        arr_data.append(data.copy())  
except:
    print("The file cannot be opened or something goes worng, please check the file")
    exit()
finally:
        cert_file.close()
# checking if dry-run is required, afterwards the EXIT will happen
if args.dry_run:
    print("By using dry-run option, we will be creating this secret for those autorieties, WITHOUT any real modifications:")
    for elem in arr_data:
        print("Mounting {} for {} with issuer {} by TTL: {}".format(
            elem['path'], elem['domain'], elem['issuer'], elem['ttl']))
    exit()

# client_hvac = hvac.Client(URL_VAULT, namespace=os.getenv('VAULT_NAMESPACE'))  # if we will require to set up namespace TEST purposes

client = get_vault_client(URL_VAULT, TOKEN)

for element in arr_data:
    mount_vault(element['path'], element['ttl'],"The secret for " + element['domain'] + " from " + element['issuer'],element['domain'], element['issuer'])



