#!/usr/bin/python
from ConfigParser import ConfigParser
import urllib2
import urllib
import json
import ssl
import csv

ssl._create_default_https_context = ssl._create_unverified_context
parser = ConfigParser()
parser.read('sc.conf')


def byteify(input):
    if isinstance(input, dict):
        return {byteify(key):byteify(value) for key,value in input.iteritems()}
    elif isinstance(input, list):
        return [byteify(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input

def connect(module, action, input={}):
	data = {'module': module,
			'action': action,
			'input': json.dumps(input),
			'token': token,
			'request_id': 1}

	headers = {'Cookie': 'TNS_SESSIONID=' + cookie}

	url = 'https://' + server + '/request.php'

	try:
		request = urllib2.Request(url, urllib.urlencode(data),headers)
		response = urllib2.urlopen(request)
		content = json.loads(response.read())
		return content['response']

	except Exception , e:
		print "Error: " + str(e)
		return None

server = parser.get('core', 'address')
username = parser.get('core', 'account')
password = parser.get('core', 'password')
token = ''
cookie = ''
# First login to the server using the auth module with the login action. The
# server's response will include a token and a cookie that needs to be used on # subsequent requests.
input = {'username': username, 'password': password}
resp = connect('auth', 'login', input)
#print resp
token = resp['token']
cookie = resp['sessionID']

# After setting the token and cookie we can use the rest of the API as normal. # Query the SC server to get the first 10 critical and high vulnerabilities. 

filters = [{'filterName': 'repositoryIDs',
            'operator': '=',
            'value': '17'}]
input = {'tool': 'vulndetails',
         'sourceType': 'cumulative',
         'filters': filters,
         'startOffset': 0,
         'endOffset': 20}
vulns = connect('vuln', 'query', input)

results_json = vulns['results']

#x = json.dumps(results_json)

z = byteify(results_json)
# print z

header=[]
g=0
for doc in z:
	while g < 1 :
		for key, value in doc.iteritems():
			header.append(key)
		g +=1	



f = csv.writer(open("test.csv", "wb+"))
print header
# Write CSV Header, If you dont need that, remove this line
f.writerow(header)

header_c = len(header)
a=0
c=[]
for z in z :
	a = 0
	c = []
	while a < header_c :
		c +=  [z[header[a]]]
		a +=1
	f.writerow(c)
	
	




