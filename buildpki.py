import argparse

import sys

url_issuer = "http://127.0.0.1:8200"
data = dict()
arr_data = list()

arg_parser = argparse.ArgumentParser(
    description='This tool is generating the CAs based on the config file, you can use also dry-run option')

arg_parser.add_argument('-config', metavar='path_to_conf', type=str, required=True,
                        help='please use the path to the correct config file')
arg_parser.add_argument('--dry-run', action='store_true', required=False, default=False,
                        help='please use it just to simulate the run')
args = arg_parser.parse_args()

try:
    try:
        cert_file = open(args.config, 'r')
        for line in cert_file.readlines():
            data['path'], data['domain'], data['issuer'], data['hours'] = line.replace(
                "\n", "").split("|")
            # data.copy() is because of the just data will be used every time at for, to alway get new items to array
            arr_data.append(data.copy())
    finally:
        cert_file.close()
except:
    print("The file cannot be opened or something goes worng, please check the file")
    exit()

if args.dry_run:
    print("By using dry-run option we will be issuing this certificates for those autorieties:")
    for elem in arr_data:
        print("Mounting {} for {} with issuer {} by TTL: {}".format(
            elem['path'], elem['domain'], elem['issuer'], elem['hours']))
    exit()

print(arr_data)
