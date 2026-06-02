THREAT_ACTORS: list[dict] = [
    {
        "name": "APT28",
        "aliases": ["Fancy Bear", "Sofacy", "Strontium", "Forest Blizzard"],
        "country": "Russia",
        "description": "Russian GRU-affiliated group known for targeting government, military, and critical infrastructure. Highly sophisticated, uses custom malware and zero-days.",
        "target_sectors": ["Government", "Military", "Defense", "Energy", "Media", "NGOs"],
        "target_vendors": ["Microsoft", "Cisco", "VMware", "Fortinet", "Palo Alto Networks"],
        "associated_cwes": ["CWE-89", "CWE-78", "CWE-287", "CWE-20"],
        "notable_campaigns": ["DNC hack (2016)", "Operation Pawn Storm", "Bundestag breach"],
        "mitre_id": "G0007",
    },
    {
        "name": "APT29",
        "aliases": ["Cozy Bear", "Midnight Blizzard", "The Dukes", "NOBELIUM"],
        "country": "Russia",
        "description": "Russian SVR-affiliated group executing long-dwell espionage campaigns. Known for the SolarWinds supply chain attack and targeting cloud and identity infrastructure.",
        "target_sectors": ["Government", "Healthcare", "Technology", "Finance", "Think Tanks"],
        "target_vendors": ["Microsoft", "SolarWinds", "VMware", "Citrix", "Okta"],
        "associated_cwes": ["CWE-502", "CWE-287", "CWE-306", "CWE-798"],
        "notable_campaigns": ["SolarWinds SUNBURST (2020)", "Microsoft Exchange breach (2024)", "TeamCity exploitation"],
        "mitre_id": "G0016",
    },
    {
        "name": "Lazarus Group",
        "aliases": ["Hidden Cobra", "Zinc", "Diamond Sleet", "Guardians of Peace"],
        "country": "North Korea",
        "description": "North Korean state-sponsored group primarily motivated by financial gain and espionage. Responsible for major financial heists including SWIFT banking attacks and crypto theft.",
        "target_sectors": ["Finance", "Cryptocurrency", "Defense", "Aerospace", "Healthcare"],
        "target_vendors": ["Microsoft", "Apple", "Adobe", "Oracle", "Google"],
        "associated_cwes": ["CWE-79", "CWE-502", "CWE-78", "CWE-119"],
        "notable_campaigns": ["WannaCry (2017)", "Bangladesh Bank heist", "Axie Infinity $625M theft"],
        "mitre_id": "G0032",
    },
    {
        "name": "APT41",
        "aliases": ["Double Dragon", "Winnti", "BARIUM", "Wicked Panda"],
        "country": "China",
        "description": "Chinese state-sponsored group conducting both espionage and financially motivated cybercrime. Known for supply chain attacks and exploitation of public-facing applications.",
        "target_sectors": ["Healthcare", "Technology", "Telecommunications", "Media", "Finance"],
        "target_vendors": ["Cisco", "Citrix", "Atlassian", "Apache", "Zoho"],
        "associated_cwes": ["CWE-78", "CWE-20", "CWE-89", "CWE-306"],
        "notable_campaigns": ["ShadowPad supply chain", "Citrix NetScaler exploitation", "COVID-19 research theft"],
        "mitre_id": "G0096",
    },
    {
        "name": "APT40",
        "aliases": ["TEMP.Periscope", "Kryptonite Panda", "Bronze Mohawk", "Leviathan"],
        "country": "China",
        "description": "Chinese MSS-affiliated group focusing on maritime, naval, and engineering sectors. Exploits N-day vulnerabilities aggressively within days of public disclosure.",
        "target_sectors": ["Maritime", "Defense", "Engineering", "Government", "Research"],
        "target_vendors": ["Microsoft", "Atlassian", "Apache", "SolarWinds", "Ivanti"],
        "associated_cwes": ["CWE-78", "CWE-22", "CWE-287", "CWE-434"],
        "notable_campaigns": ["Log4Shell mass exploitation", "Atlassian Confluence attacks", "Pulse Secure VPN exploitation"],
        "mitre_id": "G0065",
    },
    {
        "name": "Sandworm",
        "aliases": ["BlackEnergy", "Seashell Blizzard", "Voodoo Bear", "IRIDIUM"],
        "country": "Russia",
        "description": "Russian GRU Unit 74455 responsible for the most destructive cyberattacks in history including NotPetya and Ukrainian power grid attacks.",
        "target_sectors": ["Energy", "Critical Infrastructure", "Government", "Media", "Transportation"],
        "target_vendors": ["Microsoft", "Siemens", "GE", "Fortinet", "ASUS"],
        "associated_cwes": ["CWE-78", "CWE-20", "CWE-119", "CWE-416"],
        "notable_campaigns": ["NotPetya (2017)", "Ukraine power grid blackout", "Olympic Destroyer", "Industroyer2"],
        "mitre_id": "G0034",
    },
    {
        "name": "Scattered Spider",
        "aliases": ["Muddled Libra", "UNC3944", "Star Fraud", "Octo Tempest"],
        "country": "Unknown (English-speaking)",
        "description": "Financially motivated threat actor known for aggressive social engineering, SIM swapping, and targeting identity providers and cloud environments.",
        "target_sectors": ["Finance", "Technology", "Gaming", "Hospitality", "Retail"],
        "target_vendors": ["Microsoft", "Okta", "Citrix", "VMware", "Palo Alto Networks"],
        "associated_cwes": ["CWE-287", "CWE-306", "CWE-798"],
        "notable_campaigns": ["MGM Resorts breach (2023)", "Caesars Entertainment attack", "Twilio and Cloudflare phishing"],
        "mitre_id": "G1015",
    },
    {
        "name": "BlackCat/ALPHV",
        "aliases": ["ALPHV", "Noberus"],
        "country": "Unknown (Russian-speaking)",
        "description": "Sophisticated ransomware-as-a-service operation written in Rust. Known for double extortion and targeting healthcare and critical infrastructure.",
        "target_sectors": ["Healthcare", "Finance", "Manufacturing", "Government", "Energy"],
        "target_vendors": ["Microsoft", "Fortinet", "Citrix", "SolarWinds", "Ivanti"],
        "associated_cwes": ["CWE-287", "CWE-22", "CWE-502"],
        "notable_campaigns": ["MGM Resorts (via Scattered Spider)", "Change Healthcare (2024)", "Reddit breach attempt"],
        "mitre_id": "G1006",
    },
    {
        "name": "CL0P",
        "aliases": ["TA505", "Lace Tempest"],
        "country": "Unknown (likely Eastern European)",
        "description": "Ransomware group that pioneered mass exploitation of zero-day vulnerabilities in file transfer software for maximum victim count.",
        "target_sectors": ["Finance", "Healthcare", "Government", "Education", "Manufacturing"],
        "target_vendors": ["Ivanti", "Microsoft", "SolarWinds", "Zoho", "Fortra"],
        "associated_cwes": ["CWE-89", "CWE-22", "CWE-287", "CWE-434"],
        "notable_campaigns": ["MOVEit Transfer zero-day (2023)", "GoAnywhere MFT exploitation", "Accellion FTA attacks"],
        "mitre_id": "G0154",
    },
    {
        "name": "LockBit",
        "aliases": ["LockBit 3.0", "ABCD Ransomware"],
        "country": "Unknown (Russian-speaking)",
        "description": "The world's most prolific ransomware-as-a-service operation until law enforcement action in 2024. Known for speed of encryption and a sophisticated affiliate program.",
        "target_sectors": ["Manufacturing", "Healthcare", "Government", "Legal", "Finance"],
        "target_vendors": ["Citrix", "Fortinet", "Microsoft", "VMware", "Palo Alto Networks"],
        "associated_cwes": ["CWE-287", "CWE-798", "CWE-502"],
        "notable_campaigns": ["Boeing breach", "ICBC ransomware attack", "Royal Mail attack", "Operation Cronos takedown (2024)"],
        "mitre_id": "G0139",
    },
    {
        "name": "Volt Typhoon",
        "aliases": ["Bronze Silhouette", "Vanguard Panda", "Dev-0391"],
        "country": "China",
        "description": "Chinese state-sponsored group focused on pre-positioning within US critical infrastructure for potential disruptive attacks. Uses living-off-the-land techniques.",
        "target_sectors": ["Energy", "Water", "Transportation", "Communications", "Defense"],
        "target_vendors": ["Cisco", "Fortinet", "Ivanti", "QNAP", "D-Link"],
        "associated_cwes": ["CWE-306", "CWE-287", "CWE-78"],
        "notable_campaigns": ["US critical infrastructure pre-positioning", "Guam military network intrusion", "Pacific Islands targeting"],
        "mitre_id": "G1017",
    },
    {
        "name": "Salt Typhoon",
        "aliases": ["Earth Estries", "GhostEmperor", "FamousSparrow"],
        "country": "China",
        "description": "Chinese espionage group that compromised major US telecommunications providers to intercept communications of government officials and political figures.",
        "target_sectors": ["Telecommunications", "Government", "Technology", "Law Enforcement"],
        "target_vendors": ["Cisco", "Juniper", "Microsoft", "VMware", "Fortinet"],
        "associated_cwes": ["CWE-287", "CWE-78", "CWE-306"],
        "notable_campaigns": ["US Telecom wiretap compromise (2024)", "AT&T and Verizon breach", "Government official call interception"],
        "mitre_id": "G1045",
    },
    {
        "name": "APT1",
        "aliases": ["Comment Crew", "Comment Panda", "GIF89a"],
        "country": "China",
        "description": "Chinese PLA Unit 61398 conducting prolific intellectual property theft. Documented extensively by Mandiant in 2013, primarily targeting English-speaking organizations.",
        "target_sectors": ["Aerospace", "Defense", "Energy", "Technology", "Telecommunications"],
        "target_vendors": ["Microsoft", "Adobe", "Oracle", "Cisco", "Apple"],
        "associated_cwes": ["CWE-79", "CWE-20", "CWE-89"],
        "notable_campaigns": ["Operation Shady RAT", "Mandiant APT1 report targets", "Aerospace IP theft"],
        "mitre_id": "G0006",
    },
    {
        "name": "FIN7",
        "aliases": ["Carbon Spider", "Sangria Tempest", "ELBRUS"],
        "country": "Unknown (Russian-speaking)",
        "description": "Financially motivated cybercriminal group targeting point-of-sale systems, hospitality, and retail. Has evolved into a ransomware operation.",
        "target_sectors": ["Retail", "Hospitality", "Finance", "Restaurant", "Healthcare"],
        "target_vendors": ["Microsoft", "Oracle", "SAP", "Citrix", "VMware"],
        "associated_cwes": ["CWE-89", "CWE-79", "CWE-502", "CWE-287"],
        "notable_campaigns": ["Chipotle, Arby's, Chili's POS breaches", "Clop ransomware deployment", "POWERPLANT backdoor campaigns"],
        "mitre_id": "G0046",
    },
    {
        "name": "MuddyWater",
        "aliases": ["Static Kitten", "Seedworm", "TEMP.Zagros", "Mercury"],
        "country": "Iran",
        "description": "Iranian MOIS-affiliated group conducting espionage against Middle Eastern governments and telecom providers. Uses legitimate remote administration tools as malware.",
        "target_sectors": ["Government", "Telecommunications", "Defense", "Education", "Oil & Gas"],
        "target_vendors": ["Microsoft", "Fortinet", "Zoho", "Apache", "Atlassian"],
        "associated_cwes": ["CWE-78", "CWE-287", "CWE-20", "CWE-22"],
        "notable_campaigns": ["Middle East government targeting", "Telecom sector espionage", "Log4Shell exploitation"],
        "mitre_id": "G0069",
    },
]


def get_all() -> list[dict]:
    return THREAT_ACTORS


def get_by_vendor(vendor_name: str) -> list[dict]:
    q = vendor_name.strip().lower()
    return [
        ta for ta in THREAT_ACTORS
        if any(q in v.lower() for v in ta.get("target_vendors", []))
    ]


def get_by_sector(sector: str) -> list[dict]:
    q = sector.strip().lower()
    return [
        ta for ta in THREAT_ACTORS
        if any(q in s.lower() for s in ta.get("target_sectors", []))
    ]


def get_by_country(country: str) -> list[dict]:
    q = country.strip().lower()
    return [ta for ta in THREAT_ACTORS if q in ta.get("country", "").lower()]


def get_relevant_for_vendors(vendor_list: list[str]) -> list[dict]:
    results = []
    for ta in THREAT_ACTORS:
        matched = [
            v for v in vendor_list
            if any(
                v.lower() in tv.lower() or tv.lower() in v.lower()
                for tv in ta.get("target_vendors", [])
            )
        ]
        if matched:
            annotated = dict(ta)
            annotated["matched_vendors"] = matched
            results.append(annotated)
    return results
