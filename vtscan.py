import json, requests, sys
def fetch_subdomains(domain):
	response = json.loads(requests.get('https://www.virustotal.com/ui/domains/'+domain+'/siblings?limit=40').content)
	if len(response['data']) == 0:
		response = json.loads(requests.get('https://www.virustotal.com/ui/domains/'+domain+'/subdomains?relationships=resolutions&limit=40').content)
	subdomains = []
	responses = []
	if len(response['data']) != 0:
		responses.append(response)
		while 'next' in response['links']:
			response = json.loads(requests.get(response['links']['next']).content)
			responses.append(response)
	for response in responses:
		for entry in response['data']:
			subdomains.append(str(entry['id']))
	return list(set(subdomains))
if len(sys.argv) == 2:
	domain = sys.argv[1]
	print(fetch_subdomains(domain))