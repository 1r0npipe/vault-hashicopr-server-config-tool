import argparse
import requests
import hvac
import os

TOKEN = "s.yvfKzzbqFRSBZjCCeNVNe1Cl" or os.getenv('VAULT_TOKEN')
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


def mount_vault(mount_point, ttl, description_message, domain_name, common_name):
    headers = {
        'X-Vault-Request': 'true',
        'X-Vault-Token': TOKEN,
    }
    try:
        if "/" in mount_point:  # working with only intermediate entity if that is available with "/" character as of template
            mount_point, root = mount_point.split('/')[-1], mount_point.split('/')[-2]
            client.sys.enable_secrets_engine(backend_type='pki', path=mount_point, description=description_message)
            client.sys.tune_mount_configuration(mount_point, default_lease_ttl=ttl, max_lease_ttl=int(ttl)*2)
            
            # Vault CLI for generating a Certificate Signing Request
            generate_intermediate_response = client.secrets.pki.generate_intermediate(
                type='internal',
                common_name=common_name,
                mount_point=mount_point
            )
            
            # getting the CSR request entity
            csr_data=generate_intermediate_response['data']['csr']

            # Sign the CSR, note the use of the pem_bundle format and the ttl
            sign_intermediate = client.secrets.pki.sign_intermediate(
                csr=csr_data,
                common_name=common_name,
                mount_point=root
            )
            
            # getting cert entity
            data_cert=sign_intermediate['data']['certificate']
            
            # submitting the signed CA certificate
            set_signed_intermediate = client.secrets.pki.set_signed_intermediate(
                certificate = data_cert,
                mount_point=mount_point
            )

            #if option can be provided to check the status.

            # create a role based on raw REST call for intermedate entity:
            data = '{"allow_any_name":"false","allow_glob_domains":"true","allow_subdomains":"true","allowed_domains": "' + domain_name + '","enforce_hostnames":"false","ttl": "' + str(ttl) +'"}'
            requests.put(URL_VAULT + '/v1/' + mount_point + '/roles/testrole', headers=headers, data=data)

            return None  #escape after configuration of intermediate CA

        # working with ROOT entities
        client.sys.enable_secrets_engine(backend_type='pki', path=mount_point, description=description_message)
        client.sys.tune_mount_configuration(mount_point, default_lease_ttl=ttl, max_lease_ttl=int(ttl)*2)
        
        # create a role based on raw REST call for root entity:
        data = '{"allow_any_name":"false","allow_glob_domains":"true","allow_subdomains":"true","allowed_domains": "' + domain_name + '","enforce_hostnames":"false","ttl": "' + str(ttl) +'"}'
        requests.post(URL_VAULT + '/v1/' + mount_point + '/roles/testrole', headers=headers, data=data)
        
        #create the ROOT CA based on raw REST call
        data = '{"common_name":"' + common_name + '"}'
        requests.post(URL_VAULT + '/v1/' + mount_point + '/root/generate/internal', headers=headers, data=data)


    except:
        #print("The path is already exist or something goes wrong with allocation of common name: {}".format(mount_point))
        #can be added reasonable message if it tries to allocate once again
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
        if not line.startswith("#"):
            data['path'], data['domain'], data['common_name'], data['ttl'] = line.replace("\n", "").split("|")
            # data.copy() is because of the just data will be used every time at for, to alway get new items to array
            arr_data.append(data.copy())  
except:
    print("The file cannot be opened or something goes worng, please check the file format")
    exit()
finally:
        cert_file.close()
# checking if dry-run is required, afterwards the EXIT will happen
if args.dry_run:
    print("By using dry-run option, we will be creating this secret for those autorieties, WITHOUT any real modifications:")
    for elem in arr_data:
        print("Mounting {} for {} with common_name {} by TTL: {}".format(
            elem['path'], elem['domain'], elem['common_name'], elem['ttl']))
    exit()

# allocate client connection to the vault server
client = get_vault_client(URL_VAULT, TOKEN)

# processing with the all entities from config file 
for element in arr_data:
    mount_vault(element['path'], element['ttl'],"The secret for " + element['domain'] + " from " + element['common_name'],element['domain'], element['common_name'])



