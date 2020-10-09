import requests,json,base64
try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

domain ='domains'
ipAddress = 'ip_addresses'
hashes = 'hashes'
urls = 'urls'
search_type = ''

base_url = 'https://www.virustotal.com/api/v3/{0}/{1}'
hash_detection_url = 'https://www.virustotal.com/api/v3/monitor_partner/hashes/sha256/analyses'

api_key = "781e754b51c8c6d74a392526caab0faeb7a053fd85cbb6ac99904d734d21ad6e"
request_header = {'x-apikey': api_key}

#ask user for search type (url, ip_address, hash)
print('Which type do you want to search with:')
print('please enter your choice :')

#get which to detect about
_input = input('[1] ip_addresses  [2] domain   [3]hashes    [4]URLs\n')
if(_input == '1') :
    search_type = ipAddress
elif(_input == '2'):
    search_type = domain
elif(_input == '3') :
    search_type = hashes
else :
    search_type = urls

# get search query (ip input, domain input, URL input)
search_query = input('please enter your search query:')

#print all detections with result (clean || malicious)
def detect_input(type,query,url):
    url = url.format(type,query)
    try:
        response = requests.get(url,headers=request_header)
        result = json.loads(response.text)
        attributes = result['data']['attributes']
        last_analysis_result = attributes['last_analysis_results']
        last_analysis_stats = attributes['last_analysis_stats']
        clean_result =  int(last_analysis_stats['harmless'])
        malicious_result = int(last_analysis_stats['malicious'])
        total_detection = len(last_analysis_result)
        print('total detection: {0}  clean_detection: {1}   malicious_deteciton: {2}'.format(total_detection,clean_result,malicious_result))
        if(clean_result > (total_detection/2)):
            print("clean")
        else :
            print("malicious")
    except JSONDecodeError:
        print('error while parsing json result')
    except requests.exceptions.RequestException:
        print('error while requesting {0}'.format(query))

if (search_type == hashes):
    detect_input(search_type,search_query,hash_detection_url)
elif(search_type == urls):
    encoded_url = base64.urlsafe_b64encode(search_query.encode()).decode().strip("=")
    detect_input(search_type,encoded_url,base_url)
else:
    detect_input(search_type,search_query,base_url)
