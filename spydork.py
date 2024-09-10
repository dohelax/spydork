

       #########################################
       # Author : Dohela                       #
       # Team   : Spyhackerz.org               #
       # Date   : 5 - 3 - 2020                 #
       # Github : https://github.com/dohelax #
       #########################################

import urllib.request as urllib2
import http.cookiejar as cookielib
import random
import re
import sys
import socket
import time
import ssl
import http.client as httplib

# Renkli konsol çıktıları (Linux/Windows platformlarına göre)
if sys.platform in ["linux", "linux2"]:
    R = ("\033[31m")
    W = ("\033[0;1m")
    B = ("\033[35m")
    G = ("\033[32m")
    glp = ("\033[2m")
    Y = ("\033[33;1m")
else:
    R = ""
    W = ""
    Y = ""
    B = ""
    G = ""
    glp = ""

filename = "vuln.txt"
vuln = open(filename, "a")
finallist = []

# User-Agent listesi
header = [
    'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.2pre) Gecko/20100207 Ubuntu/9.04 Namoroka/3.6.2pre',
    'Mozilla/5.0 (Windows NT 6.0; rv:1.9.0.6)',
    'Opera/8.00 (Windows NT 5.1; U; en)',
    'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
]

# SQL Hata Mesajları
errors = {
    'MySQL': 'error in your SQL syntax',
    'Oracle': 'ORA-01756',
    'MSSQL_OLEdb': 'Microsoft OLE DB Provider for SQL Server',
    'MS-Access_ODBC': 'ODBC Microsoft Access Driver',
    'Syntax error': 'Syntax error'
}

# Ülke kodları
sites = ['com', 'net', 'org', 'gov', 'edu', 'us', 'uk', 'de', 'fr', 'ru', 'cn']

# Web tarama işlemi
def cek():
    print(W + "-" * 43)
    hasil = []
    for url in finallist:
        print(R + "[!] " + W + "Web Vuln Taraniyor..\r", end="")
        sys.stdout.flush()
        EXT = "'"
        host = url + EXT
        try:
            source = urllib2.urlopen(host).read().decode('utf-8', 'ignore')
            for type, eMSG in errors.items():
                if re.search(eMSG, source):
                    print(B + "[+]" + G + " Vuln  " + W + ": " + host.replace("'", ""))
                    print(B + "[*]" + R + " Error " + W + ": " + glp + type + W)
                    hasil.append(host.replace("'", ""))
                else:
                    pass
        except:
            pass

    if len(hasil) > 0:
        print(W + "-" * 43)
        print(R + "[!] " + W + "Vuln web kaydediliyor..")
        for x in hasil:
            vuln.write(x + "\n")
        vuln.close()
        print(B + "[+] " + G + "Başarıyla kaydedildi: " + W + filename)
        print(B + "[*] " + G + "Toplam web vuln: " + W + str(len(hasil)))
    print(W + "-" * 43 + '\n')

# Web arama işlemi
def cari(inurl, site, maxc):
    print(R + "[!] " + W + "Lütfen Bekleyin..")
    urls = []
    page = 0
    try:
        while page < int(maxc):
            jar = cookielib.CookieJar()
            query = inurl + "+site:" + site
            results_web = f'http://www.search-results.com/web?q={query}&hl=en&page={page}&src=hmp'
            request_web = urllib2.Request(results_web)
            agent = random.choice(header)
            request_web.add_header('User-Agent', agent)
            opener_web = urllib2.build_opener(urllib2.HTTPCookieProcessor(jar))
            text = opener_web.open(request_web).read().decode('utf-8', 'ignore')
            stringreg = re.compile(r'(?<=href=")(.*?)(?=")')
            names = stringreg.findall(text)
            page += 1

            for name in names:
                if name not in urls:
                    if re.search(r'\(', name) or re.search("<", name) or re.search("\A/", name) or re.search("\A(http://)\d", name):
                        pass
                    elif re.search("google", name) or re.search("youtube", name):
                        pass
                    else:
                        urls.append(name)

            percent = int((1.0 * page / int(maxc)) * 100)
            urls_len = len(urls)
            sys.stdout.write(f"\r[*] Urls: {urls_len} | Yüzde: {percent}% | Sayfa: {page} [*]")
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    except urllib2.URLError as e:
        print(R + "\r-- " + W + "Hata " + R + "-- " + W + f": {e}")
        sys.exit()
    except socket.error as s:
        print(R + "\r-- " + W + "Hata " + R + "-- " + W + f": {s}")
        sys.exit()
    except httplib.IncompleteRead as h:
        print(R + "\r-- " + W + "Hata " + R + "-- " + W + f": {h}")
        sys.exit()

    tmplist = []
    for url in urls:
        try:
            host = url.split("/", 3)
            domain = host[2]
            if domain not in tmplist and "=" in url:
                finallist.append(url)
                tmplist.append(domain)
        except:
            pass

    print("\n" + W + "-" * 43)
    print(B + "[+] " + G + f"Urls (sorted): {len(finallist)} Url")
    return finallist

if __name__ == "__main__":
    print("SPYSQLi DorkScanner - Spyhackerz.org")
    print(W + "-" * 43)
    inurl = input(B + "[?]" + G + " Dork girin: " + W)
    site = input(B + "[?]" + G + " Site kodu girin: " + W)
    maxc = input(B + "[?]" + G + " Kaç Sayfa aratilacak: " + W)
    print(W + "-" * 43)
    cari(inurl, site, maxc)
    cek()
