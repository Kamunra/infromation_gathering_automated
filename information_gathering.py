import whois
import sys
import argparse
import textwrap
import re
import dns.resolver
import requests
from colorama import init, Fore

# Initialize colorama
init()

GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
BLUE = Fore.BLUE


class InfoGatherer:
    def __init__(self, domain):
        if not self.is_valid_domain(domain):
            raise ValueError("Invalid domain format")
        self.domain = domain

    @staticmethod
    def is_valid_domain(domain):
        """
        Check using regex whether the user input is a valid domain
        :param: a string, that is passed for the check whether it is domain-like in structure
        :return: Boolean - True in case the input matches the domain regex, False otherwise
        """
        domain_pattern = r'^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*\.[a-zA-Z]{2,}$'

        return re.match(domain_pattern, domain) is not None

    def get_domain_info(self):
        """
        Gather information about the domain using WHOIS module
        :return: None - printed stdout
        """
        domain_info = whois.whois(self.domain)
        print(domain_info)

    def get_dns_records(self):
        """
        Gather information about the domain from DNS records
        :return: None - printed stdout
        """
        try:
            a_records = dns.resolver.resolve(self.domain, 'A')
            print(f" {GREEN} IPv4 addresses records for {self.domain}:  {RESET}")
            for record in a_records:
                print(record)

            mx_records = dns.resolver.resolve(self.domain, 'MX')
            print(f" {GREEN} Mail Exchanger records for {self.domain}:  {RESET}")
            for record in mx_records:
                print(record)

            ns_records = dns.resolver.resolve(self.domain, 'NS')
            print(f" {GREEN} Name Server records for {self.domain} :  {RESET}")
            for record in ns_records:
                print(record)

        except dns.resolver.NXDOMAIN:
            print(f"{RED} Domain '{self.domain}' does not exist. {RESET}")
        except dns.resolver.Timeout:
            print(f"{BLUE} DNS query timeout. {RESET}")
        except Exception as e:
            print(f"{RED} An error occurred: {e} {RESET}")

    def check_subdomain_existence(self, subdomain):
        """
        Check whether a subdomain exists by making a dns request.
        :param: a string - a guessing option for subdomain
        :return: None - printed stdout
        """
        ip = dns.resolver.resolve(f"{subdomain}.{self.domain}", 'A')
        if ip:
            print(f"found subdomain:{subdomain}")

    def subdomain_enumeration(self, wordlist):
        """
        Check for existing subdomains using the passed wordlist.
        :param wordlist: a file with words, separated by new line - potential source for bruteforcing guesses
        :return: None - printed stdout
        """
        with open('subdomains.txt', 'r') as f:
            for sub in f:
                try:
                    self.check_subdomain_existence(sub.strip())
                except dns.resolver.NXDOMAIN:
                    pass

    def directory_bruteforcing(self, wordlist):
        """
        Check for existing directories using the passed wordlist.
        :param wordlist: a file with words, separated by new line - potential source for bruteforcing guesses
        :return: None - printed stdout
        """
        with open(f"{wordlist}", 'r') as f:
            for directory in f:
                try:
                    response = requests.get(f"{self.domain}/{directory.strip()}")
                    # print(response.url)
                    if response.status_code == 200:
                        print(f"Found directory: {directory}")
                    else:
                        pass
                except KeyboardInterrupt:
                    sys.exit()

    def gather_info(self, wordlist, wordlist_dir):
        """
        A funtion that combines the functionality of all the functions above.
        :param wordlist_dir:  a file with words, separated by new line - potential source
        for directory bruteforcing guesses
        :param wordlist: a file with words, separated by new line - potential source for subdomain bruteforcing guesses
        :return: None - printed stdout
        """
        self.get_domain_info()
        self.get_dns_records()
        self.subdomain_enumeration(wordlist)
        self.directory_bruteforcing(wordlist_dir)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Automated Infromation Gatherer',
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=textwrap.dedent(
            '''Example: python3 information_gathering.py -d epita.fr -w /path/to/wordlist.txt -dw /path/to/dirlist.txt
             python3 information_gathering.py -d scanner.parser.epita.fr -w /path/to/wordlist2.txt
            '''))
    parser.add_argument('-d', '--domain_name', help="the domain name that you would like to know more about")
    parser.add_argument('-w', '--wordlist', help="the wordlist to be used in bruteforcing subdomains, and directories "
                                                 "in case next argument not provided")
    parser.add_argument('-dw', '--directory_wordlist', help="the wordlist to be used in directory bruteforccing")
    args = parser.parse_args()
    info_gatherer = InfoGatherer(args.domain_name)
    if args.directory_wordlist is None:
        info_gatherer.gather_info(args.wordlist, args.wordlist)
    else:
        info_gatherer.gather_info(args.wordlist, args.directory_wordlist)