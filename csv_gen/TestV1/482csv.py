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
         'endOffset': 2}
vulns = connect('vuln', 'query', input)

#print vulns

x = json.dumps(vulns,skipkeys=True)
print x
''''
f = csv.writer(open("test.csv", "wb+"))

# Write CSV Header, If you dont need that, remove this line
f.writerow(["ip", "port", "severity", "pluginID", "pluginName"])

for x in x :
    f.writerow([x["ip"], 
                x["port"], 
                x["severity"], 
                x["pluginID"],
                x["pluginName"]])

'''
'''
for vuln in vulns['results']:
    print 'IP: ' + vuln['ip']
    print 'Name: ' + vuln['pluginName']
    print 'Severity: ' + vuln['severity']
    print
'''