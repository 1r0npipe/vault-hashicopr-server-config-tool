import argparse
import sys

data = dict()
arr_data = []

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
            data['path'], data['domain'], data['issuer'], data['hours'] = line.split(
                '|')
            arr_data.append(data)
        print(arr_data)
    finally:
        cert_file.close()
except:
    print("The file cannot be opened or something goes worng, please check the file")
    exit()
