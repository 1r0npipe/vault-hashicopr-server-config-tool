import argparse
import hvac
import os

TOKEN = "s.0veOHBqxzOHs8879A74NxWFq" or os.getenv('VAULT_TOKEN')
URL_VAULT = None or os.getenv('VAULT_ADDR')
DEFAULT_MAX_TTL = '320000'

data = dict()
arr_data = list()


def get_vault_client(vault_url, token_id):
    client_hvac = hvac.Client(url=vault_url, token=token_id)
    if not client_hvac.is_authenticated():
        print("Failed to autentificate with Vault ({}) or token ({}) is wrong, \
            please check server URL or/and your token".format(vault_url, token_id))
        return None
    else:
        return client_hvac


def allocate_cert_vault(mount_point, domain_name, common_name, ttl):

    SUCCESS_CODE = 204
    ROLE_NAME = 'testrole'
    ALT_NAMES = 'something.com'

    try:# working with only intermediate entity if that is available with "/" character as of template
        if "/" in mount_point:  
            mount_point, root = mount_point.split('/')[-1], mount_point.split('/')[-2]

            client.sys.enable_secrets_engine(
                backend_type = 'pki', 
                path = mount_point, 
                description = "The secret for " + domain_name + " from " + common_name
            )


            client.sys.tune_mount_configuration(mount_point, default_lease_ttl=ttl, max_lease_ttl=DEFAULT_MAX_TTL)
            
            # Vault CLI for generating a Certificate Signing Request
            generate_intermediate_response = client.secrets.pki.generate_intermediate(
                type = 'internal',
                common_name = common_name,
                mount_point = mount_point,
                extra_params = {
                    'alt_names': ALT_NAMES
                }
            )
            
            # Sign the CSR, note the use of the pem_bundle format and the ttl
            sign_intermediate = client.secrets.pki.sign_intermediate(
                csr = generate_intermediate_response['data']['csr'],
                common_name = common_name,
                mount_point = root
            )
                        
            # submitting the signed CA certificate
            set_signed_intermediate = client.secrets.pki.set_signed_intermediate(
                certificate = sign_intermediate['data']['certificate'],
                mount_point = mount_point
            )
            
            #if option can be provided to check the status.
            if set_signed_intermediate.status_code == SUCCESS_CODE:
                pass
            
            set_role = client.secrets.pki.create_or_update_role(
                name = ROLE_NAME,
                mount_point = mount_point,
                extra_params = {   
                    'allow_subdomains': 'true',
                    'allow_any_name': 'false',
                    'allow_glob_domains': 'true',
                    'enforce_hostnames': 'false',
                    'allowed_domains': domain_name
                }
            )

            #if option can be provided to check the status of role creation.
            if set_role.status_code == SUCCESS_CODE:
                pass

            return None  #escape after configuration of intermediate CA

        if not ttl:
            print('The TTL is not specified for Root cert, please make sure it is set up at file')
            exit()

        # working with ROOT entities
        client.sys.enable_secrets_engine(
            backend_type='pki', 
            path = mount_point, 
            description = "The secret for " + domain_name + " from " + common_name
            )
        client.sys.tune_mount_configuration(mount_point, default_lease_ttl=ttl, max_lease_ttl=DEFAULT_MAX_TTL)
        
        # create a role based on call for root entity:
        set_role = client.secrets.pki.create_or_update_role(
            name = ROLE_NAME,
            mount_point = mount_point,
            extra_params = {   
                'allow_subdomains': 'true',
                'allow_any_name': 'false',
                'allow_glob_domains': 'true',
                'enforce_hostnames': 'false',
                'allowed_domains': domain_name
            }
        )
        
        # stub for the set role status
        if set_role.status_code == SUCCESS_CODE:
            pass
        
        #create the ROOT CA based on raw call
        set_root = client.secrets.pki.generate_root(
            type = 'internal',
            common_name = common_name,
            mount_point = mount_point
        )
        
        # stub for the set root cert status
        if set_root.status_code == SUCCESS_CODE:
            pass
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
            elem['path'], \
            elem['domain'], \
            elem['common_name'], \
            elem['ttl']))
    exit()

# allocate client connection to the vault server
client = get_vault_client(URL_VAULT, TOKEN)

# processing with the all entities from config file 
for element in arr_data:
    allocate_cert_vault(
        element['path'], \
        element['domain'], \
        element['common_name'], \
        element['ttl']
    )



