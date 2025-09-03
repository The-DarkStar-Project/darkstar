#!/usr/bin/env python3
"""
Mail Security Scanner - SPF and DMARC Vulnerability Detection
Checks for common SPF and DMARC misconfigurations and vulnerabilities
With database integration and Dutch translations
"""

import dns.resolver
import requests
import re
import ssl
import socket
import logging
import json
import os
from typing import List, Dict, Optional
from datetime import datetime
from dotenv import load_dotenv

from core.db_helper import insert_vulnerability_to_database
from core.models.vulnerability import Vulnerability

logger = logging.getLogger("main")

class MailSecurityScanner:
    def __init__(self, org_name, env_file: Optional[str] = None):
        self.vulnerabilities = []
        self.info_messages = []
        self.org_name = org_name
        
        # Load environment variables if specified
        if env_file and os.path.exists(env_file):
            load_dotenv(env_file)
            # self.setup_database()
            
        # Dutch vulnerability translations and detailed information
        self.vulnerability_translations = {
            'SPF_MISSING': {
                'title': 'Ontbrekend SPF Record',
                'description': 'Geen SPF (Sender Policy Framework) record gevonden voor het domein. Dit maakt het domein kwetsbaar voor email spoofing en phishing aanvallen.',
                'recommendation': 'Configureer een SPF record om te specificeren welke servers geautoriseerd zijn om email te verzenden voor uw domein. Voeg een TXT record toe zoals: "v=spf1 include:_spf.google.com ~all"',
                'references': 'RFC 7208, NIST Cybersecurity Framework, https://www.spf-record.com/'
            },
            'DMARC_MISSING': {
                'title': 'Ontbrekend DMARC Record', 
                'description': 'Geen DMARC (Domain-based Message Authentication) record gevonden. DMARC biedt bescherming tegen email spoofing door SPF en DKIM resultaten te combineren.',
                'recommendation': 'Configureer een DMARC record om bescherming tegen email spoofing en phishing aanvallen te bieden. Begin met "v=DMARC1; p=none; rua=mailto:dmarc@uwdomein.nl" voor monitoring.',
                'references': 'RFC 7489, NCSC Richtlijnen Email Beveiliging, https://dmarc.org/'
            },
            'SPF_SYNTAX_ERROR': {
                'title': 'SPF Syntaxfout',
                'description': 'Het SPF record bevat syntaxfouten die kunnen leiden tot incorrecte interpretatie door email servers en verminderde beveiliging.',
                'recommendation': 'Corrigeer de syntaxfouten in het SPF record. Zorg ervoor dat het record begint met "v=spf1" gevolgd door geldige mechanismen.',
                'references': 'RFC 7208 Section 4, SPF Record Syntax Guide'
            },
            'SPF_DEPRECATED_PTR': {
                'title': 'Verouderd PTR Mechanisme in SPF',
                'description': 'Het SPF record gebruikt het verouderde "ptr" mechanisme dat onbetrouwbaar is en email levering kan vertragen door DNS lookup problemen.',
                'recommendation': 'Vervang het "ptr" mechanisme door betrouwbaardere alternatieven zoals "ip4", "a", of "include" mechanismen die beter prestaties en betrouwbaarheid bieden.',
                'references': 'RFC 7208 Section 5.5, Best Practices for SPF'
            },
            'SPF_MULTIPLE_RECORDS': {
                'title': 'Meerdere SPF Records',
                'description': 'Er zijn meerdere SPF records gevonden voor dit domein. Dit is niet toegestaan en kan leiden tot onvoorspelbaar gedrag bij email validatie.',
                'recommendation': 'Voeg alle SPF mechanismen samen in één enkel geldig SPF record. Verwijder duplicate records en consolideer alle autorisaties.',
                'references': 'RFC 7208 Section 3.2, SPF Implementation Guidelines'
            },
            'SPF_RECORD_TOO_LONG': {
                'title': 'SPF Record Te Lang',
                'description': 'Het SPF record overschrijdt de maximale lengte van 512 karakters, wat kan leiden tot DNS problemen en incorrecte verwerking.',
                'recommendation': 'Verkort het SPF record door onnodige mechanismen te verwijderen of door gebruik te maken van include mechanismen voor complexe configuraties.',
                'references': 'RFC 1035 Section 2.3.4, DNS Message Format'
            },
            'SPF_MISSING_ALL': {
                'title': 'Ontbrekend "all" Mechanisme',
                'description': 'Het SPF record mist het "all" mechanisme dat bepaalt hoe om te gaan met servers die niet expliciet geautoriseerd zijn.',
                'recommendation': 'Voeg een geschikt "all" mechanisme toe aan het einde van uw SPF record. Gebruik "~all" voor soft fail of "-all" voor hard fail.',
                'references': 'RFC 7208 Section 5.1, SPF All Mechanism'
            },
            'SPF_PERMISSIVE_ALL': {
                'title': 'Te Permissief "all" Mechanisme',
                'description': 'Het SPF record gebruikt "+all" of "all" wat alle servers toestaat om email te verzenden, waardoor bescherming tegen spoofing wordt weggenomen.',
                'recommendation': 'Wijzig naar een restrictiever "all" mechanisme zoals "~all" (soft fail) of "-all" (hard fail) om ongeautoriseerde verzenders te blokkeren.',
                'references': 'SPF Best Practices, Email Security Guidelines'
            },
            'SPF_DOMAIN_TYPO': {
                'title': 'Mogelijke Typefout in SPF Domein',
                'description': 'Een potentiële typefout gedetecteerd in een include statement van het SPF record, wat kan leiden tot DNS lookup fouten en verminderde beveiliging.',
                'recommendation': 'Controleer en corrigeer de domeinnaam in het include statement om ervoor te zorgen dat deze correct gespeld is.',
                'references': 'SPF Record Validation Tools, DNS Best Practices'
            },
            'DMARC_MONITORING_ONLY': {
                'title': 'DMARC Alleen Monitoring Modus',
                'description': 'DMARC beleid staat ingesteld op monitoring modus (p=none) wat geen daadwerkelijke bescherming biedt tegen email spoofing aanvallen.',
                'recommendation': 'Wijzig het DMARC beleid naar "p=quarantine" of "p=reject" om daadwerkelijke bescherming tegen spoofing te implementeren na analyse van DMARC rapporten.',
                'references': 'RFC 7489 Section 6.3, DMARC Deployment Guide'
            },
            'DMARC_PARTIAL_ENFORCEMENT': {
                'title': 'DMARC Gedeeltelijke Handhaving',
                'description': 'DMARC percentage is ingesteld op minder dan 100%, waardoor sommige gespoofde emails nog steeds kunnen worden afgeleverd.',
                'recommendation': 'Stel pct=100 in of verwijder de pct tag voor volledige bescherming. Gedeeltelijke handhaving biedt geen complete beveiliging.',
                'references': 'DMARC Best Practices, Email Authentication Standards'
            },
            'DMARC_NO_SUBDOMAIN_POLICY': {
                'title': 'Geen DMARC Subdomain Beleid',
                'description': 'DMARC record mist een expliciet subdomain beleid (sp=), waardoor subdomeinen kwetsbaar kunnen zijn voor spoofing aanvallen.',
                'recommendation': 'Voeg "sp=reject" of "sp=quarantine" toe om subdomeinen te beschermen tegen spoofing aanvallen.',
                'references': 'RFC 7489 Section 6.3, Subdomain Policy Guidelines'
            },
            'DMARC_WEAK_SUBDOMAIN_POLICY': {
                'title': 'Zwak DMARC Subdomain Beleid',
                'description': 'DMARC subdomain beleid staat ingesteld op "sp=none" wat spoofing van subdomeinen toestaat.',
                'recommendation': 'Wijzig het subdomain beleid naar "sp=quarantine" of "sp=reject" voor betere beveiliging van subdomeinen.',
                'references': 'DMARC Security Guidelines, Subdomain Protection'
            },
            'DMARC_SPF_ALIGNMENT_RELAXED': {
                'title': 'Relaxed SPF Alignment',
                'description': 'SPF alignment is relaxed (aspf=r) of niet gespecificeerd, wat minder strikte verificatie betekent en potentiële beveiligingsrisicos kan introduceren.',
                'recommendation': 'Overweeg het instellen van "aspf=s" voor strikte SPF alignment voor betere beveiliging, mits dit geen legitieme email blokkeert.',
                'references': 'RFC 7489 Section 3.1, DMARC Alignment Modes'
            },
            'DMARC_DKIM_ALIGNMENT_RELAXED': {
                'title': 'Relaxed DKIM Alignment',
                'description': 'DKIM alignment is relaxed (adkim=r) of niet gespecificeerd, wat minder strikte verificatie betekent.',
                'recommendation': 'Overweeg het instellen van "adkim=s" voor strikte DKIM alignment voor betere beveiliging.',
                'references': 'RFC 7489 Section 3.1, DKIM Alignment Best Practices'
            },
            'DMARC_SYNTAX_ERROR': {
                'title': 'DMARC Syntaxfout',
                'description': 'DMARC record bevat syntaxfouten die kunnen leiden tot incorrecte verwerking door email servers.',
                'recommendation': 'Corrigeer de syntaxfouten in het DMARC record. Zorg ervoor dat het begint met "v=DMARC1".',
                'references': 'RFC 7489 Section 6.3, DMARC Record Format'
            },
            'DMARC_INCORRECT_ORDER': {
                'title': 'Incorrecte DMARC Tag Volgorde',
                'description': 'DMARC tags staan niet in de correcte volgorde, wat kan leiden tot parsing problemen bij sommige email servers.',
                'recommendation': 'Reorganiseer het DMARC record om te beginnen met "v=DMARC1;" gevolgd door het beleid en andere tags.',
                'references': 'DMARC Specification, Tag Ordering Guidelines'
            },
            'DMARC_NO_REPORTING': {
                'title': 'Geen DMARC Rapportage Configuratie',
                'description': 'DMARC record mist een aggregate rapportage adres (rua=), waardoor belangrijke feedback over email authenticatie ontbreekt.',
                'recommendation': 'Voeg "rua=mailto:dmarc@uwdomein.nl" toe om DMARC rapporten te ontvangen voor monitoring en analyse.',
                'references': 'RFC 7489 Section 7, DMARC Reporting Mechanisms'
            },
            'MTA_STS_MISSING': {
                'title': 'Ontbrekend MTA-STS Record',
                'description': 'Geen MTA-STS (Mail Transfer Agent Strict Transport Security) record gevonden. Dit maakt email transport kwetsbaar voor man-in-the-middle aanvallen.',
                'recommendation': 'Configureer een MTA-STS record om beveiligde email transport af te dwingen. Voeg een TXT record toe aan _mta-sts.yourdomain.com met "v=STSv1; id=timestamp"',
                'references': 'RFC 8461, MTA-STS Implementation Guide'
            },
            'MTA_STS_INVALID_FORMAT': {
                'title': 'Ongeldig MTA-STS Record Formaat',
                'description': 'Het MTA-STS DNS record heeft een ongeldig formaat of ontbreekt vereiste velden.',
                'recommendation': 'Corrigeer het MTA-STS record formaat. Het moet beginnen met "v=STSv1" en een "id" veld bevatten.',
                'references': 'RFC 8461 Section 3.1, MTA-STS DNS Record Format'
            },
            'MTA_STS_POLICY_FILE_MISSING': {
                'title': 'MTA-STS Policy Bestand Ontbreekt',
                'description': 'Het MTA-STS policy bestand is niet bereikbaar via HTTPS op de verwachte locatie /.well-known/mta-sts.txt',
                'recommendation': 'Maak het MTA-STS policy bestand beschikbaar op https://mta-sts.yourdomain.com/.well-known/mta-sts.txt',
                'references': 'RFC 8461 Section 3.2, MTA-STS Policy File'
            },
            'MTA_STS_POLICY_INVALID': {
                'title': 'Ongeldig MTA-STS Policy Bestand',
                'description': 'Het MTA-STS policy bestand bevat ongeldige syntax of ontbreekt vereiste velden.',
                'recommendation': 'Corrigeer het policy bestand om geldige STSv1 syntax te gebruiken met versie, mode, mx servers en max_age.',
                'references': 'RFC 8461 Section 3.2, Policy File Format'
            },
            'MTA_STS_WEAK_MODE': {
                'title': 'Zwakke MTA-STS Mode',
                'description': 'MTA-STS policy staat ingesteld op "testing" of "none" mode wat geen daadwerkelijke bescherming biedt.',
                'recommendation': 'Wijzig de MTA-STS mode naar "enforce" voor daadwerkelijke bescherming tegen downgrade aanvallen.',
                'references': 'MTA-STS Best Practices, RFC 8461'
            },
            'MTA_STS_SSL_ERROR': {
                'title': 'MTA-STS SSL Certificaat Probleem',
                'description': 'Het SSL certificaat voor de MTA-STS subdomain is ongeldig, verlopen of niet vertrouwd.',
                'recommendation': 'Installeer een geldig SSL certificaat voor mta-sts.yourdomain.com dat vertrouwd wordt door browsers.',
                'references': 'SSL/TLS Best Practices, Certificate Authority Guidelines'
            },
            'MTA_STS_CONTENT_TYPE_ERROR': {
                'title': 'Onjuist MTA-STS Content-Type',
                'description': 'Het MTA-STS policy bestand wordt niet geserveerd met het juiste content-type.',
                'recommendation': 'Configureer de webserver om mta-sts.txt te serveren met content-type "text/plain".',
                'references': 'RFC 8461 Section 3.2, HTTP Response Requirements'
            }
        }

    def log_vulnerability(self, domain: str, severity: str, code: str, description: str, recommendation: str):
        """Log a vulnerability with details and Dutch translation if available"""   
        vulnerability = Vulnerability(
            title=code,
            affected_item=domain,
            tool="MailSecurityScanner",
            confidence=100,
            severity=severity,
            host=domain,
            summary=description,
            solution=recommendation,
        )
        
        self.vulnerabilities.append(vulnerability)
        logger.warning(f"[{severity}] {domain} - {code}: {description} Recommendation: {recommendation}")
        
        insert_vulnerability_to_database(vulnerability, self.org_name)
    
    def log_info(self, message: str):
        self.info_messages.append(message)
        
    def get_txt_records(self, domain: str) -> List[str]:
        """Get TXT records for a domain"""
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            return [str(rdata).strip('"') for rdata in answers]
        except Exception as e:
            self.log_info(f"Could not retrieve TXT records for {domain}: {str(e)}")
            return []
            
    def get_spf_records(self, domain: str) -> List[str]:
        """Extract SPF records from TXT records"""
        txt_records = self.get_txt_records(domain)
        spf_records = [record for record in txt_records if record.startswith('v=spf1')]
        return spf_records
        
    def get_dmarc_records(self, domain: str) -> List[str]:
        """Extract DMARC records from TXT records"""
        dmarc_domain = f"_dmarc.{domain}"
        txt_records = self.get_txt_records(dmarc_domain)
        dmarc_records = [record for record in txt_records if record.startswith('v=DMARC1')]
        return dmarc_records
        
    def get_mx_records(self, domain: str) -> List[str]:
        """Get MX records for a domain"""
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            return [str(rdata) for rdata in answers]
        except Exception as e:
            self.log_info(f"Could not retrieve MX records for {domain}: {str(e)}")
            return []
        
    def check_spf_presence(self, domain: str) -> bool:
        """Check if SPF record is present"""
        spf_records = self.get_spf_records(domain)
        
        if not spf_records:
            self.log_vulnerability(
                domain,
                'High',
                'SPF_MISSING',
                f'No SPF record found for domain {domain}',
                'Configure an SPF record to specify which servers are authorized to send email for your domain'
            )
            return False
            
        return True
    
    def check_spf_presence_quiet(self, domain: str) -> bool:
        """Check if SPF record is present without logging vulnerabilities"""
        spf_records = self.get_spf_records(domain)
        return len(spf_records) > 0
        
    def check_dmarc_presence(self, domain: str) -> bool:
        """Check if DMARC record is present"""
        dmarc_records = self.get_dmarc_records(domain)
        
        if not dmarc_records:
            self.log_vulnerability(
                domain,
                'High',
                'DMARC_MISSING',
                f'No DMARC record found for domain {domain}',
                'Configure a DMARC record to protect against email spoofing and phishing attacks'
            )
            return False
            
        return True
    
    def check_dmarc_presence_quiet(self, domain: str) -> bool:
        """Check if DMARC record is present without logging vulnerabilities"""
        dmarc_records = self.get_dmarc_records(domain)
        return len(dmarc_records) > 0
        
    def check_spf_syntax(self, domain: str, spf_record: str):
        """Check SPF record for syntax errors"""
        # Check for basic syntax requirements
        if not spf_record.startswith('v=spf1'):
            self.log_vulnerability(
                domain,
                'High',
                'SPF_SYNTAX_ERROR',
                f'SPF record does not start with v=spf1: {spf_record}',
                'Ensure the SPF record starts with v=spf1 followed by a space'
            )
            return
            
        # Check for valid mechanisms
        valid_mechanisms = ['include:', 'a', 'mx', 'ip4:', 'ip6:', 'exists:', 'ptr', 'all', '~all', '-all', '+all', '?all']
        mechanisms = spf_record.split()[1:]  # Skip v=spf1
        
        for mechanism in mechanisms:
            # Remove qualifiers (+, -, ~, ?)
            clean_mechanism = mechanism.lstrip('+-~?')
            
            # Check if it's a valid mechanism
            is_valid = False
            for valid_mech in valid_mechanisms:
                if clean_mechanism.startswith(valid_mech) or clean_mechanism == valid_mech:
                    is_valid = True
                    break
                    
            if not is_valid:
                self.log_vulnerability(
                    domain,
                    'Medium',
                    'SPF_INVALID_MECHANISM',
                    f'Invalid mechanism "{mechanism}" in SPF record',
                    'Remove or correct the invalid mechanism'
                )
                
        # Check for IP address format
        ip4_pattern = r'ip4:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)'
        ip6_pattern = r'ip6:([0-9a-fA-F:]+(?:/\d{1,3})?)'
        
        for ip4_match in re.finditer(ip4_pattern, spf_record):
            ip = ip4_match.group(1)
            # Basic IPv4 validation
            parts = ip.split('/')[0].split('.')
            if len(parts) != 4 or any(int(part) > 255 for part in parts):
                self.log_vulnerability(
                    domain,
                    'Medium',
                    'SPF_MALFORMED_IP',
                    f'Malformed IPv4 address in SPF record: {ip}',
                    'Correct the IPv4 address format'
                )
                
    def check_spf_deprecated_mechanisms(self, domain: str, spf_record: str):
        """Check for deprecated or risky SPF mechanisms"""
        if 'ptr' in spf_record:
            self.log_vulnerability(
                domain,
                'Medium',
                'SPF_DEPRECATED_PTR',
                'SPF record uses deprecated "ptr" mechanism',
                'Replace "ptr" mechanism with more reliable alternatives like "ip4", "a", or "include"'
            )
            
        if 'exists:' in spf_record:
            self.log_vulnerability(
                domain,
                'Low',
                'SPF_RISKY_EXISTS',
                'SPF record uses complex "exists" mechanism',
                'Consider replacing "exists" with simpler mechanisms to avoid excessive DNS lookups'
            )
            
    def check_spf_multiple_records(self, domain: str, spf_records: List[str]):
        """Check for multiple SPF records"""
        if len(spf_records) > 1:
            self.log_vulnerability(
                domain,
                'High',
                'SPF_MULTIPLE_RECORDS',
                f'Multiple SPF records found ({len(spf_records)} records)',
                'Merge all SPF records into a single valid record'
            )
            
    def check_spf_length(self, domain: str, spf_record: str):
        """Check SPF record length limits"""
        if len(spf_record) > 512:
            self.log_vulnerability(
                domain,
                'Medium',
                'SPF_RECORD_TOO_LONG',
                f'SPF record exceeds 512 character limit (current: {len(spf_record)} characters)',
                'Reduce the SPF record length by consolidating or removing unnecessary mechanisms'
            )
            
        # Check for string length within 255 characters per DNS string
        parts = spf_record.split('" "')
        for i, part in enumerate(parts):
            if len(part) > 255:
                self.log_vulnerability(
                    domain,
                    'Medium',
                    'SPF_STRING_TOO_LONG',
                    f'SPF record string {i+1} exceeds 255 character limit',
                    'Split long strings or reduce content'
                )
                
    def check_spf_all_mechanism(self, domain: str, spf_record: str):
        """Check for proper 'all' mechanism"""
        all_mechanisms = ['+all', '-all', '~all', '?all', 'all']
        has_all = any(mechanism in spf_record for mechanism in all_mechanisms)
        
        if not has_all:
            self.log_vulnerability(
                domain,
                'Medium',
                'SPF_MISSING_ALL',
                'SPF record is missing the "all" mechanism',
                'Add an appropriate "all" mechanism (recommended: "~all" or "-all")'
            )
        elif '+all' in spf_record or spf_record.endswith(' all'):
            self.log_vulnerability(
                domain,
                'High',
                'SPF_PERMISSIVE_ALL',
                'SPF record uses permissive "+all" or "all" mechanism',
                'Change to more restrictive "~all" or "-all" to prevent unauthorized senders'
            )
            
    def check_spf_domain_typos(self, domain: str, spf_record: str):
        """Check for potential domain typos in include statements"""
        include_pattern = r'include:([^\s]+)'
        includes = re.findall(include_pattern, spf_record)
        
        for include_domain in includes:
            # Check for common typos in popular email providers
            common_domains = {
                'google.com': ['gooogle.com', 'googel.com', 'gogle.com'],
                'outlook.com': ['outloook.com', 'outlok.com'],
                'mailchimp.com': ['mailchmp.com', 'mailchipm.com']
            }
            
            for correct_domain, typos in common_domains.items():
                if include_domain in typos:
                    self.log_vulnerability(
                        domain,
                        'High',
                        'SPF_DOMAIN_TYPO',
                        f'Potential domain typo in SPF include: {include_domain} (should be {correct_domain}?)',
                        f'Correct the domain name to {correct_domain}'
                    )
                    
    def check_dmarc_policy_strength(self, domain: str, dmarc_record: str):
        """Check DMARC policy strength"""
        if 'p=none' in dmarc_record:
            self.log_vulnerability(
                domain,
                'High',
                'DMARC_MONITORING_ONLY',
                'DMARC policy is set to monitoring mode (p=none) - no protection against spoofing',
                'Change policy to "p=quarantine" or "p=reject" for actual protection'
            )
        elif 'p=quarantine' in dmarc_record:
            self.log_info('DMARC policy set to quarantine - good security posture')
        elif 'p=reject' in dmarc_record:
            self.log_info('DMARC policy set to reject - excellent security posture')
            
    def check_dmarc_percentage(self, domain: str, dmarc_record: str):
        """Check DMARC percentage setting"""
        pct_match = re.search(r'pct=(\d+)', dmarc_record)
        if pct_match:
            pct = int(pct_match.group(1))
            if pct < 100:
                self.log_vulnerability(
                    domain,
                    'Medium',
                    'DMARC_PARTIAL_ENFORCEMENT',
                    f'DMARC percentage is set to {pct}% - partial enforcement allows some spoofed emails through',
                    'Set pct=100 or remove the pct tag for full protection'
                )
                
    def check_dmarc_subdomain_policy(self, domain: str, dmarc_record: str):
        """Check DMARC subdomain policy"""
        if 'sp=' not in dmarc_record:
            self.log_vulnerability(
                domain,
                'Medium',
                'DMARC_NO_SUBDOMAIN_POLICY',
                'DMARC record lacks explicit subdomain policy (sp=)',
                'Add "sp=reject" or "sp=quarantine" to protect subdomains from spoofing'
            )
        elif 'sp=none' in dmarc_record:
            self.log_vulnerability(
                domain,
                'High',
                'DMARC_WEAK_SUBDOMAIN_POLICY',
                'DMARC subdomain policy allows spoofing (sp=none)',
                'Change subdomain policy to "sp=quarantine" or "sp=reject"'
            )
            
    def check_dmarc_alignment(self, domain: str, dmarc_record: str):
        """Check DMARC alignment settings"""
        if 'aspf=s' not in dmarc_record:
            self.log_vulnerability(
                domain,
                'Low',
                'DMARC_SPF_ALIGNMENT_RELAXED',
                'SPF alignment is relaxed (aspf=r) of niet gespecificeerd',
                'Overweeg het instellen van "aspf=s" voor strikte SPF alignment voor betere beveiliging'
            )
            
        if 'adkim=s' not in dmarc_record:
            self.log_vulnerability(
                domain,
                'Low',
                'DMARC_DKIM_ALIGNMENT_RELAXED',
                'DKIM alignment is relaxed (adkim=r) of niet gespecificeerd',
                'Overweeg het instellen van "adkim=s" voor strikte DKIM alignment voor betere beveiliging'
            )
            
    def check_dmarc_syntax_order(self, domain: str, dmarc_record: str):
        """Check DMARC record syntax and tag order"""
        if not dmarc_record.startswith('v=DMARC1'):
            self.log_vulnerability(
                domain,
                'High',
                'DMARC_SYNTAX_ERROR',
                'DMARC record does not start with v=DMARC1',
                'Ensure DMARC record starts with v=DMARC1'
            )
            
        # Check if policy comes after version
        parts = dmarc_record.split(';')
        if len(parts) > 1:
            version_part = parts[0].strip()
            if version_part != 'v=DMARC1':
                self.log_vulnerability(
                    domain,
                    'Medium',
                    'DMARC_INCORRECT_ORDER',
                    'DMARC tags are not in correct order - version should come first',
                    'Reorganize DMARC record to start with v=DMARC1; followed by policy'
                )
                
    def check_dmarc_reporting(self, domain: str, dmarc_record: str):
        """Check DMARC reporting configuration"""
        if 'rua=' not in dmarc_record:
            self.log_vulnerability(
                domain,
                'Medium',
                'DMARC_NO_REPORTING',
                'DMARC record lacks aggregate reporting address (rua=)',
                'Add "rua=mailto:dmarc@yourdomain.com" to receive DMARC reports'
            )
            
    def is_email_sending_domain(self, domain: str, from_emails_file: bool = False) -> bool:
        """
        Check if a domain should be scanned for email security issues based on:
        1. SPF record exists, OR
        2. DMARC record exists, OR
        3. Domain appears in emails.txt file
        
        Args:
            domain (str): Domain to check
            from_emails_file (bool): True if domain was extracted from emails.txt
            
        Returns:
            bool: True if domain should be scanned, False otherwise
        """
        # If domain came from emails.txt, it should always be scanned
        if from_emails_file:
            self.log_info(f"✓ Domain {domain} found in emails.txt - will be scanned")
            return True
        
        # Check 1: SPF Record Exists
        spf_exists = self.check_spf_presence_quiet(domain)
        if spf_exists:
            self.log_info(f"✓ SPF record found for {domain} - will be scanned")
            return True
        else:
            self.log_info(f"✗ No SPF record found for {domain}")
        
        # Check 2: DMARC Record Exists
        dmarc_exists = self.check_dmarc_presence_quiet(domain)
        if dmarc_exists:
            self.log_info(f"✓ DMARC record found for {domain} - will be scanned")
            return True
        else:
            self.log_info(f"✗ No DMARC record found for {domain}")
        
        # Domain should not be scanned if it has neither SPF nor DMARC records
        # and was not found in emails.txt
        self.log_info(f"✗ Domain {domain} does not meet criteria for email security scanning")
        return False
    
    def scan_domain(self, domain: str, force: bool = False, from_emails_file: bool = False) -> Dict:
        """Perform comprehensive mail security scan for a domain"""
        logger.info(f"\n[+] Scanning mail security for domain: {domain}")
        
        # Reset for new scan
        self.vulnerabilities = []
        self.info_messages = []
        
        # Pre-check: Determine if domain should be scanned (unless forced)
        if not force:
            logger.info(f"[*] Checking if {domain} should be scanned for email security...")
            if not self.is_email_sending_domain(domain, from_emails_file):
                logger.warning(f"[!] Skipping {domain} - does not meet criteria for email security scanning")
                logger.warning("[!] Domain must have SPF/DMARC records or be found in emails.txt")
                return {
                    'domain': domain,
                    'skipped': True,
                    'reason': 'Domain has no SPF/DMARC records and was not found in emails.txt',
                    'vulnerabilities': [],
                    'info_messages': []
                }
        
        logger.info(f"[+] Domain {domain} meets criteria - proceeding with security scan")
        
        # Check SPF
        spf_present = self.check_spf_presence(domain)
        if spf_present:
            spf_records = self.get_spf_records(domain)
            self.check_spf_multiple_records(domain, spf_records)
            
            for spf_record in spf_records:
                logger.info(f"[+] Found SPF record: {spf_record}")
                self.check_spf_syntax(domain, spf_record)
                self.check_spf_deprecated_mechanisms(domain, spf_record)
                self.check_spf_length(domain, spf_record)
                self.check_spf_all_mechanism(domain, spf_record)
                self.check_spf_domain_typos(domain, spf_record)
                
        # Check DMARC
        dmarc_present = self.check_dmarc_presence(domain)
        if dmarc_present:
            dmarc_records = self.get_dmarc_records(domain)
            
            for dmarc_record in dmarc_records:
                logger.info(f"[+] Found DMARC record: {dmarc_record}")
                self.check_dmarc_policy_strength(domain, dmarc_record)
                self.check_dmarc_percentage(domain, dmarc_record)
                self.check_dmarc_subdomain_policy(domain, dmarc_record)
                self.check_dmarc_alignment(domain, dmarc_record)
                self.check_dmarc_syntax_order(domain, dmarc_record)
                self.check_dmarc_reporting(domain, dmarc_record)
                
        # Check MTA-STS
        self.domain = domain  # Set domain for MTA-STS methods
        self.check_mta_sts_record()
        
        # Return results
        results = {
            'domain': domain,
            'scan_timestamp': datetime.now().isoformat(),
            'email_domain': True,
            'spf_present': spf_present,
            'dmarc_present': dmarc_present,
            'vulnerabilities': self.vulnerabilities,
            'info_messages': self.info_messages,
            'skipped': False
        }
        
        return results
        
    def print_results(self, results: Dict):
        """Print scan results in a readable format"""
        logger.info(f"\n{'='*60}")
        logger.info(f"MAIL SECURITY SCAN RESULTS FOR: {results['domain']}")
        logger.info(f"{'='*60}")
        
        # Check if scan was skipped
        if results.get('skipped', False):
            logger.info("\n⏭️  SCAN SKIPPED")
            logger.info(f"Reason: {results['info_messages'][0] if results['info_messages'] else 'Domain does not appear to be used for email'}")
            return
        
        logger.info(f"\nEmail Domain: {'✓' if results.get('email_domain', False) else '✗'}")
        logger.info(f"SPF Record Present: {'✓' if results['spf_present'] else '✗'}")
        logger.info(f"DMARC Record Present: {'✓' if results['dmarc_present'] else '✗'}")
        
        if results['vulnerabilities']:
            logger.info(f"\n🚨 VULNERABILITIES FOUND ({len(results['vulnerabilities'])}):")
            logger.info("-" * 50)
            
            # Group by severity
            high_vulns = [v for v in results['vulnerabilities'] if v['severity'] == 'High']
            medium_vulns = [v for v in results['vulnerabilities'] if v['severity'] == 'Medium']
            low_vulns = [v for v in results['vulnerabilities'] if v['severity'] == 'Low']
            
            for severity, vulns in [('High', high_vulns), ('Medium', medium_vulns), ('Low', low_vulns)]:
                if vulns:
                    logger.info(f"\n{severity} SEVERITY ({len(vulns)}):")
                    for vuln in vulns:
                        logger.info(f"  • {vuln['type']}: {vuln['description']}")
                        logger.info(f"    Recommendation: {vuln['recommendation']}")
        else:
            logger.info("\n✅ No vulnerabilities found!")
            
        if results['info_messages']:
            logger.info("\nℹ️  INFORMATION:")
            for msg in results['info_messages']:
                logger.info(f"  • {msg}")
                
    def export_results(self, results: Dict, filename: str):
        """Export results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"\n📄 Results exported to: {filename}")
    
    def run_all_checks(self):
        """Run all mail security checks"""
        self.check_spf_record()
        self.check_dmarc_record()
        self.check_bimi_record()
        self.check_mta_sts_record()  # Add MTA-STS check
        
    def check_mta_sts_record(self):
        """Check MTA-STS (Mail Transfer Agent Strict Transport Security) implementation"""
        try:
            mta_sts_domain = f"_mta-sts.{self.domain}"
            
            # Check for MTA-STS DNS record
            mta_sts_records = self.get_txt_records(mta_sts_domain)
            
            if not mta_sts_records:
                self.log_vulnerability(
                    self.domain, 'baseline', 'MTA_STS_MISSING',
                    f'No MTA-STS record found for {mta_sts_domain}',
                    'Configure an MTA-STS record to enforce secure email transport'
                )
                return
            
            # Use the first record found
            mta_sts_record = mta_sts_records[0]
            
            # Validate MTA-STS record format
            if not self._validate_mta_sts_record(mta_sts_record):
                self.log_vulnerability(
                    self.domain, 'baseline', 'MTA_STS_INVALID_FORMAT',
                    f'Invalid MTA-STS record format: {mta_sts_record}',
                    'Correct the MTA-STS record format to include v=STSv1 and id field'
                )
                return
            
            # Check MTA-STS policy file
            self._check_mta_sts_policy_file()
            
        except Exception as e:
            logging.error(f"Error checking MTA-STS for {self.domain}: {str(e)}")
    
    def _validate_mta_sts_record(self, record):
        """Validate MTA-STS DNS record format"""
        if not record.startswith('v=STSv1'):
            return False
        
        # Check for required 'id' field
        if 'id=' not in record:
            return False
        
        return True
    
    def _check_mta_sts_policy_file(self):
        """Check MTA-STS policy file availability and content"""
        policy_url = f"https://mta-sts.{self.domain}/.well-known/mta-sts.txt"
        
        try:
            # First check SSL certificate
            self._check_mta_sts_ssl_certificate()
            
            # Make HTTPS request to policy file
            response = requests.get(policy_url, timeout=10, verify=True)
            
            if response.status_code != 200:
                self.log_vulnerability(
                    self.domain, 'baseline', 'MTA_STS_POLICY_FILE_MISSING',
                    f'MTA-STS policy file not accessible at {policy_url} (HTTP {response.status_code})',
                    'Make the MTA-STS policy file available via HTTPS'
                )
                return
            
            # Check content-type
            content_type = response.headers.get('content-type', '').lower()
            if 'text/plain' not in content_type:
                self.log_vulnerability(
                    self.domain, 'baseline', 'MTA_STS_CONTENT_TYPE_ERROR',
                    f'MTA-STS policy file has incorrect content-type: {content_type}',
                    'Configure the web server to serve mta-sts.txt with content-type "text/plain"'
                )
            
            # Validate policy content
            self._validate_mta_sts_policy(response.text)
            
        except requests.exceptions.SSLError as e:
            self.log_vulnerability(
                self.domain, 'baseline', 'MTA_STS_SSL_ERROR',
                f'SSL certificate error for mta-sts.{self.domain}: {str(e)}',
                'Install a valid SSL certificate for the MTA-STS subdomain'
            )
        except requests.exceptions.RequestException as e:
            self.log_vulnerability(
                self.domain, 'baseline', 'MTA_STS_POLICY_FILE_MISSING',
                f'Cannot access MTA-STS policy file at {policy_url}: {str(e)}',
                'Ensure the MTA-STS policy file is accessible via HTTPS'
            )
        except Exception as e:
            logging.error(f"Error checking MTA-STS policy file for {self.domain}: {str(e)}")
    
    def _check_mta_sts_ssl_certificate(self):
        """Check SSL certificate for MTA-STS subdomain"""
        hostname = f"mta-sts.{self.domain}"
        port = 443
        
        try:
            context = ssl.create_default_context()
            sock = socket.create_connection((hostname, port), timeout=10)
            ssock = context.wrap_socket(sock, server_hostname=hostname)
            
            # Get certificate info
            cert = ssock.getpeercert()
            
            # Check if certificate is valid (not expired)
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            if datetime.now() > not_after:
                self.log_vulnerability(
                    self.domain, 'baseline', 'MTA_STS_SSL_ERROR',
                    f'SSL certificate for {hostname} is expired (expired: {cert["notAfter"]})',
                    'Install a valid SSL certificate for the MTA-STS subdomain'
                )
            
            ssock.close()
            
        except ssl.SSLError as e:
            self.log_vulnerability(
                self.domain, 'baseline', 'MTA_STS_SSL_ERROR',
                f'SSL error for {hostname}: {str(e)}',
                'Fix SSL certificate issues for the MTA-STS subdomain'
            )
        except socket.error as e:
            self.log_vulnerability(
                self.domain, 'baseline', 'MTA_STS_SSL_ERROR',
                f'Connection error to {hostname}: {str(e)}',
                'Ensure the MTA-STS subdomain is accessible and has proper SSL configuration'
            )
        except Exception as e:
            logging.error(f"Error checking SSL certificate for {hostname}: {str(e)}")
    
    def _validate_mta_sts_policy(self, policy_content):
        """Validate MTA-STS policy file content"""
        lines = [line.strip() for line in policy_content.split('\n') if line.strip()]
        
        required_fields = ['version', 'mode', 'mx', 'max_age']
        found_fields = {}
        
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                found_fields[key] = value
        
        # Check for required fields
        missing_fields = [field for field in required_fields if field not in found_fields]
        if missing_fields:
            self.log_vulnerability(
                self.domain, 'baseline', 'MTA_STS_POLICY_INVALID',
                f'MTA-STS policy missing required fields: {", ".join(missing_fields)}',
                'Add all required fields to the MTA-STS policy file'
            )
            return
        
        # Check version
        if found_fields.get('version') != 'STSv1':
            self.log_vulnerability(
                self.domain, 'baseline', 'MTA_STS_POLICY_INVALID',
                f'Invalid MTA-STS policy version: {found_fields.get("version")}',
                'Set version to STSv1 in the MTA-STS policy file'
            )
        
        # Check mode
        mode = found_fields.get('mode', '').lower()
        if mode in ['testing', 'none']:
            self.log_vulnerability(
                self.domain, 'baseline', 'MTA_STS_WEAK_MODE',
                f'MTA-STS policy is in weak mode: {mode}',
                'Change MTA-STS mode to "enforce" for actual protection'
            )
        elif mode not in ['enforce', 'testing', 'none']:
            self.log_vulnerability(
                self.domain, 'baseline', 'MTA_STS_POLICY_INVALID',
                f'Invalid MTA-STS policy mode: {mode}',
                'Set mode to one of: enforce, testing, or none'
            )
        
        # Check max_age (should be a number)
        try:
            max_age = int(found_fields.get('max_age', '0'))
            if max_age < 86400:  # Less than 1 day
                self.log_vulnerability(
                    self.domain, 'baseline', 'MTA_STS_POLICY_INVALID',
                    f'MTA-STS max_age too low: {max_age} seconds (recommended: >= 86400)',
                    'Set max_age to at least 86400 seconds (1 day) for proper caching'
                )
        except ValueError:
            self.log_vulnerability(
                self.domain, 'baseline', 'MTA_STS_POLICY_INVALID',
                f'Invalid MTA-STS max_age value: {found_fields.get("max_age")}',
                'Set max_age to a valid number of seconds'
            )
    
    def run(self, subdomains_file: str, emails_file: str):
        domains_to_scan = []
        email_file_domains = set()  # Track domains from emails.txt
        
        # Try to read domains from subdomains file
        if os.path.exists(subdomains_file):
            try:
                with open(subdomains_file, 'r') as f:
                    for line in f:
                        domain = line.strip()
                        if domain and not domain.startswith('#'):
                            # Clean domain name (remove protocol, ports, etc.)
                            if '://' in domain:
                                domain = domain.split('://')[1]
                            if ':' in domain:
                                domain = domain.split(':')[0]
                            if '/' in domain:
                                domain = domain.split('/')[0]
                            
                            # Skip localhost domains for email security (keep this filter)
                            if domain and '.' in domain and 'localhost' not in domain.lower():
                                domains_to_scan.append(domain.lower())
                
                logger.info(f"[*] [Email Security Thread] Found {len(domains_to_scan)} domains from subdomains file")
            except Exception as e:
                logger.error(f"[!] [Email Security Thread] Error reading subdomains file: {e}")
        
        # Also try to extract domains from emails.txt file
        if os.path.exists(emails_file):
            try:
                email_domains = []
                with open(emails_file, 'r') as f:
                    for line in f:
                        email = line.strip()
                        if email and '@' in email and not email.startswith('#'):
                            try:
                                # Extract domain from email address
                                domain = email.split('@')[1].lower()
                                # Additional cleaning for email domains
                                if '>' in domain:  # Handle cases like "user@domain.com>"
                                    domain = domain.split('>')[0]
                                if '<' in domain:  # Handle cases like "user@<domain.com"
                                    domain = domain.split('<')[-1]
                                    
                                # Skip localhost domains for email security and validate
                                if domain and '.' in domain and len(domain) > 3 and 'localhost' not in domain.lower():
                                    email_domains.append(domain)
                                    email_file_domains.add(domain)  # Track this domain came from emails.txt
                            except (IndexError, AttributeError):
                                # Skip malformed email addresses
                                continue
                
                # Add unique email domains to our list
                unique_email_domains = list(set(email_domains))
                for domain in unique_email_domains:
                    if domain not in domains_to_scan:
                        domains_to_scan.append(domain)
                
                logger.info(f"[*] [Email Security Thread] Found {len(unique_email_domains)} additional domains from emails file")
            except Exception as e:
                logger.warning(f"[!] [Email Security Thread] Error reading emails file: {e}")
        
        # Remove duplicates while preserving order
        domains_to_scan = list(dict.fromkeys(domains_to_scan))
        
        # Summary of domain sources
        if os.path.exists(subdomains_file) and os.path.exists(emails_file):
            logger.info("[*] [Email Security Thread] Domain sources: subdomains.txt + emails.txt")
        elif os.path.exists(subdomains_file):
            logger.info("[*] [Email Security Thread] Domain sources: subdomains.txt only")
        elif os.path.exists(emails_file):
            logger.info("[*] [Email Security Thread] Domain sources: emails.txt only")
        
        logger.info(f"[*] [Email Security Thread] Total unique domains to check: {len(domains_to_scan)}")
        
        # Show first few domains as examples (for debugging)
        if domains_to_scan:
            example_domains = domains_to_scan[:3]
            logger.info(f"[*] [Email Security Thread] Example domains: {', '.join(example_domains)}{'...' if len(domains_to_scan) > 3 else ''}")
        
        # Show count of domains from emails.txt
        if email_file_domains:
            logger.info(f"[*] [Email Security Thread] {len(email_file_domains)} domains from emails.txt will be scanned regardless of SPF/DMARC")
        
        if not domains_to_scan:
            logger.info("[!] [Email Security Thread] No domains found to scan")
            return
        
        successful_scans = 0
        failed_scans = 0
        skipped_scans = 0
        
        # Scan each domain
        for i, domain in enumerate(domains_to_scan, 1):
            try:
                logger.info(f"[*] [Email Security Thread] ({i}/{len(domains_to_scan)}) Scanning: {domain}")
                
                # Check if this domain came from emails.txt
                from_emails_file = domain in email_file_domains
                
                results = self.scan_domain(domain, from_emails_file=from_emails_file)
                
                # Check if scan was skipped
                if results.get('skipped', False):
                    skipped_scans += 1
                    logger.warning(f"[!] [Email Security Thread] Skipped {domain} - {results.get('reason', 'not used for email')}")
                    continue
                
                successful_scans += 1
                
                # Brief summary of findings
                vuln_count = len(results.get('vulnerabilities', []))
                if vuln_count > 0:
                    logger.warning(f"[!] [Email Security Thread] Found {vuln_count} email security issues for {domain}")
                else:
                    logger.info(f"[+] [Email Security Thread] No email security issues found for {domain}")
                    
            except Exception as e:
                logger.error(f"[-] [Email Security Thread] Error scanning {domain}: {e}")
                failed_scans += 1
                continue
        
        logger.info("[+] [Email Security Thread] Email security scanning completed")
        logger.info(f"[*] [Email Security Thread] Successfully scanned: {successful_scans}, Skipped: {skipped_scans}, Failed: {failed_scans}")
            
    

