import simplejson, optparse, mimetypes, httplib
import urllib
import urllib2

apikey = "f182df1bff1285e3315e734381a1109267f898c78ff01629d6539bf62db9b1fd"

# Banner
def Banner():
    print("="*72)
    print("pyVirusTotal v0.1                                ")
    print("="*72)

# Query VirusTotal with a hash
def query_hash(hash):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": hash, "apikey": apikey}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    json = response.read()
    response_dict = simplejson.loads(json)
    return response_dict

# Print a VirusTotal report
def format_report(result):
    scans = result.get("scans")
    print("SHA256: %s" % result['sha256'])
    print("MD5: %s" % result['md5'])
    print("Detection ratio: %s/%s" % (result['positives'], result['total']))
    print("Analysis date: %s" % result['scan_date'])
    print("-"*72)
    for k, v in scans.items():
        if v['detected'] == True:
            print ("%s: %s") % (k, v['result'])
        else:
            print ("%s: No Detection") % (k)
    print("-"*72)
    print("URL: %s" % result['permalink'])

def query_url(scanurl):
    url = "https://www.virustotal.com/vtapi/v2/url/report"
    parameters = {"resource": scanurl, "apikey": apikey}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    json = response.read()
    response_dict = simplejson.loads(json)
    return response_dict

def format_url_report(result):
    scans = result.get("scans")
    print("Detection ratio: %s/%s" % (result['positives'], result['total']))
    print("Analysis date: %s" % result['scan_date'])
    print("-"*72)
    for k, v in scans.items():
        if v['detected'] == True:
            print ("%s: %s") % (k, v['result'])
        else:
            print ("%s: No Detection") % (k)
    print("-"*72)
    print("URL: %s" % result['url'])
    print("Permalink: %s" % result['permalink'])

# Upload file support
def post_multipart(host, selector, fields, files):
    '''
    Post fields and files to an http host as multipart/form-data.
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return the server's response page.
    '''
    content_type, body = encode_multipart_formdata(fields, files)
    h = httplib.HTTP(host)
    h.putrequest('POST', selector)
    h.putheader('content-type', content_type)
    h.putheader('content-length', str(len(body)))
    h.endheaders()
    h.send(body)
    errcode, errmsg, headers = h.getreply()
    return h.file.read()

def encode_multipart_formdata(fields, files):
    '''
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTP instance
    '''
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        L.append('Content-Type: %s' % get_content_type(filename))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body

def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

# Upload on VirusTotal
def upload(filename):
    try:
        host = "www.virustotal.com"
        selector = "https://www.virustotal.com/vtapi/v2/file/scan"
        fields = [("apikey", apikey)]
        file_to_send = open(filename, "rb").read()
        files = [("file", filename, file_to_send)]
        json = post_multipart(host, selector, fields, files)
        result = simplejson.loads(json)
        return result
    except IOError:
        return "Error: can\'t find file or read data"

def scan_url(scanurl):
    url = "https://www.virustotal.com/vtapi/v2/url/scan"
    parameters = {"url": scanurl, "apikey": apikey}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    json = response.read()
    response_dict = simplejson.loads(json)
    return response_dict

if __name__ == '__main__':
    Banner()
    parser = optparse.OptionParser()
    parser.add_option('-s', '--search-hash', dest='hash', help='hash of <malware> must be MD5 or SHA-1 or SHA-256')
    parser.add_option('-f', '--upload', dest='upload', help='Name of uploaded file. <Name_of_File>')
    parser.add_option('-u', '--scan-url', dest='scanurl', help='Name of URL to scan. <url>')
    parser.add_option('-n', '--search-url', dest='url', help='Name of URL to search. <url>')
    
    (options,args) = parser.parse_args()
    
    if options.hash:
        szRes = query_hash(options.hash)
        if szRes!=None:
            format_report(szRes)
        else:
            print("There could be problem with the file.")
    elif options.upload:
        szRes = upload(options.upload)
        print szRes['permalink']
        print szRes['verbose_msg']
    elif options.scanurl:
        szRes = scan_url(options.scanurl)
        print szRes['url']
        print szRes['permalink']
        print szRes['scan_date']
        print szRes['verbose_msg']
    elif options.url:
        szRes = query_url(options.url)
        if szRes!=None:
            format_url_report(szRes)
        else:
            print("There could be problem with the file.")
    elif len(args) != 2:
        parser.error("wrong number of arguments")
        print options
        print args
