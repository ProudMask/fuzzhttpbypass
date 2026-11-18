#!/usr/bin/python3

import argparse
import ipaddress
import os
import shlex
import socket
import sys
import tempfile
from urllib.parse import urlsplit

def parse_main_args(args=None):
    parser = argparse.ArgumentParser(description='HTTP variation checks for local CTF and authorized test environments.')
    parser.add_argument( '-u','--url', required=True,
                        help='HTTP(S) URL of the authorized test endpoint')
    parser.add_argument('-f','--filter', required=True,
                        help='Filter as contains,VALUE or notcontains,VALUE; quote text containing spaces')
    parser.add_argument('-i','--ip', default="",
                        help='Optional valid IP literal for the existing header variation set')
    #parser.add_argument('-p','--proxy', default="",
    #                    help='Add a proxy in WFUZZ format (-p 127.0.0.1:8080:HTML))')
    
    args = parser.parse_args(args)
    try:
        validate_url(args.url)
        build_filter(args.filter)
        if args.ip:
            ipaddress.ip_address(args.ip)
    except ValueError as exc:
        parser.error(str(exc))
    #return (args.url, args.ip, args.filter, args.proxy) #Proxy thing, read main function
    return (args.url, args.ip, args.filter)

def color_print(to_print):
    NoC = "\033[0m"
    Y = "\033[1;33;40m"
    G = "\033[1;32;40m"
    B = "\033[1;34;40m"
    R = "\033[0;31;47m"

    if "[i] " in to_print:
        print(Y+to_print+NoC)
    elif "[+] " in to_print:
        print(G+to_print+NoC)
    elif "[c] " in to_print:
        print(B+to_print+NoC)
    elif "[-] " in to_print:
        print(R+to_print+NoC)
    else:
        print(to_print)

def validate_url(url):
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise ValueError("Invalid URL or port") from exc
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username is not None or parts.password is not None or parts.fragment or any(c.isspace() for c in url):
        raise ValueError("Use an HTTP(S) URL without credentials, whitespace, or fragments")
    return parts

def build_filter(value):
    mode, separator, term = value.partition(",")
    if mode not in {"contains", "notcontains"} or not separator or not term:
        raise ValueError("Filter must be contains,VALUE or notcontains,VALUE")
    flag = "--s" if mode == "contains" else "--h"
    if term.isdigit():
        if not 100 <= int(term) <= 599:
            raise ValueError("HTTP status filter must be between 100 and 599")
        return flag + "c " + str(int(term))
    return flag + "s " + shlex.quote(term)

def getPartsFromUrl(url):
    parts = validate_url(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return parts.scheme + ":", parts.netloc, path

def getIPsFromDomain(domain):
    host = urlsplit("//" + domain).hostname
    ips = sorted({entry[4][0] for entry in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
    color_print("[i] Found IP(s) for domain " + host + ": " + ", ".join(ips))
    return ips

def isIP(param):
    try:
        ipaddress.ip_address(urlsplit("//" + param).hostname)
        return True
    except (ValueError, TypeError):
        return False


def fuzzPaths(url, filter2use, proxy):
    'Method to FUZZ paths'
    color_print("[+] Fuzzing Path variations...")
    paths = "%2e-%252e-%ef%bc%8f"
    url_l = url.split("/")
    url_l.insert(-1,"FUZZ")
    url = "/".join(url_l)
    wfuzz(["-z list,"+paths], filter2use, proxy, "", url)


def fuzzMethods(url, filter2use, proxy):
    'Method to FUZZ http methods'
    color_print("[+] Fuzzing HTTP Verbs (methods)...")
    methods = "GET-HEAD-POST-DELETE-CONNECT-OPTIONS-TRACE-PUT-INVENTED"
    #PATCH method doesnt work, the program gets stucked
    wfuzz(["-z list,"+methods], filter2use, proxy, " -X FUZZ", url)

    #If only 1 depth of file path, checks different indexes
    proto, domain, path = getPartsFromUrl(url)
    if path.count("/") == 1:
        for p in ["index.php", "index", "index.html", "index.asp", "index.aspx", ""]:
            if path.split("/")[1] != p:
                wfuzz(["-z list,"+methods], filter2use, proxy, "-X FUZZ", proto+"//"+domain+"/"+p)

def fuzzHeaders(url, ips, filter2use, proxy, cookies, passwords, user_agent_file):
    'Method to FUZZ http headers'
    color_print("[+] Fuzzing HTTP Headers...")
    color_print("\t[+] Forwarded")
    wfuzz(["-z list,"+ips+"_hidden-_secret-unknown", "-z list,"+ips, "-z list,"+ips, "-z list,http-https"], filter2use, proxy, "-H 'Forwarded:for=FUZZ;by=FUZ2Z;host=FUZ3Z;proto=FUZ4Z'", url)
    
    color_print("\t[+] X-Forwarded-For")
    wfuzz(["-z list,"+ips], filter2use, proxy, "-H X-Forwarded-For:FUZZ", url)

    color_print("\t[+] X-Originating-IP")
    wfuzz(["-z list,"+ips], filter2use, proxy, "-H X-Originating-IP:FUZZ", url)
    
    color_print("\t[+] X-Remote-IP")
    wfuzz(["-z list,"+ips], filter2use, proxy, "-H X-Remote-IP:FUZZ", url)
    
    color_print("\t[+] X-Remote-Addr")
    wfuzz(["-z list,"+ips], filter2use, proxy, "-H X-Remote-Addr:FUZZ", url)
    
    color_print("\t[+] X-ProxyUser-Ip")
    wfuzz(["-z list,"+ips], filter2use, proxy, "-H X-ProxyUser-Ip:FUZZ", url)

    color_print("\t[+] Referer")
    wfuzz(["-z list,"+url], filter2use, proxy, "-H Referer:FUZZ", url)

    color_print("\t[+] User-Agent")
    wfuzz(["-w " + shlex.quote(user_agent_file)], filter2use, proxy, "-H User-Agent:FUZZ", url)

    if len(cookies) > 0:
        wfuzz(["-z list,"+passwords], filter2use, proxy, " ".join([ "-b "+c.name+"=FUZZ" for c in cookies ]), url)

def fuzzAutehntication(url, filter2use, proxy, users, passwords):
    'Method to FUZZ HTTP Authentication'
    color_print("[+] Fuzzing HTTP Authentication...")
    color_print("\t[+] Basic")
    wfuzz(["-z list,"+users], filter2use, proxy, "--basic FUZZ:FUZZ", url)
    wfuzz(["-z list,"+users,"-z list,"+passwords], filter2use, proxy, "--basic FUZZ:FUZ2Z", url)

    color_print("\t[+] NTLM")
    wfuzz(["-z list,"+users], filter2use, proxy, "--ntlm FUZZ:FUZZ", url)
    wfuzz(["-z list,"+users,"-z list,"+passwords], filter2use, proxy, "--ntlm FUZZ:FUZ2Z", url)

def wfuzz(lists ,filter2use, proxy, extra, url):
    'Launch wfuzz with custom options'
    from wfuzz.api import get_session
    cmd = " ".join(lists)+" "+filter2use+" "+proxy+" "+extra+" "+" --req-delay 30 --conn-delay 30 "+shlex.quote(url)
    color_print("[c] Trying: "+cmd)
    for r in get_session(cmd).fuzz():
        print(r)

def main():
    #url, ip, f2u, proxy = parse_main_args(sys.argv[1:])
    url, ip, f2u = parse_main_args(sys.argv[1:])
    proxy = "" #If you use the proxy the HTTP methods POST and PUT stuck the program, so dont use a proxy until this is fixed!! (is all prepare for using it)

    filter2use = build_filter(f2u)

    if proxy is not None and proxy != "":
        proxy = "-p "+proxy
        
    users="admin-administrator-root-anonymous-ftp-guest-superadmin-tomcat-user-test-public-mysql"
    passwords="admin-administrator-password-123456-12345678-root-toor-qwerty-anonymous-True"
    useragents=[ "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 12_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1",
                "Mozilla/5.0 (Linux; U; Android 4.4.2; es-es; SM-T210R Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Safari/534.30",
                "Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.7.8) Gecko/20050511 Firefox/1.0.4",
                "Mozilla/5.0 (Linux; Android 9; SM-G960F Build/PPR1.180610.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.157 Mobile Safari/537.36",
                "Googlebot", "Bingbot", "admin" ]
        
    with tempfile.NamedTemporaryFile(mode="w", prefix="fuzzhttp-ua-", suffix=".txt", delete=False) as f:
        ua_path = f.name
        for ua in useragents:
            f.write(ua+"\n")

    try:
        import requests
        r = requests.get(url, timeout=30, allow_redirects=False)
        status_code = r.status_code
        body = r.text
        resp_length = len(body)
        cookies = r.cookies
        is_redir = r.is_redirect or r.is_permanent_redirect or (status_code > 299 and status_code < 400)
    
        color_print("[i] Making a simple GET request the returned code was "+str(status_code)+" and the length of the body was "+str(resp_length))
        if cookies is not None and len(cookies) > 0:
            color_print("[i] The web wanted to set these cookies: ")
            for c in cookies:
                print(c.name+"=<redacted>")
        if is_redir and resp_length > 0:
            color_print("[i] Hey, the web is redirecting us but it has some contet, take a look:")
            color_print(body)
    
        proto, domain, path = getPartsFromUrl(url)
        ips = ["127.0.0.1", "8.8.4.4"] + [ip] if ip != "" else ["127.0.0.1", "8.8.4.4"]
        ips = ips + getIPsFromDomain(domain) if not isIP(domain) else ips
        ips = "-".join(ips)
        color_print("[i] IPs that are going to be use for FUZZING: "+ips)
    
        print("")
        fuzzPaths(url, filter2use, proxy)
        fuzzMethods(url, filter2use, proxy)
        fuzzHeaders(url, ips, filter2use, proxy, cookies, passwords, ua_path)
        fuzzAutehntication(url, filter2use, proxy, users, passwords)
    
        return 0
    finally:
        os.unlink(ua_path)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ImportError, OSError, RuntimeError) as exc:
        print('Error: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)


#No funciona: espacios entre parametros o dentro de los parametros
#DIgest Auth
#Metodos post put patch nunca acaban

