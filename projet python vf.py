# -*- coding: utf-8 -*-

import feedparser
import requests
import re
import pandas as pd
import smtplib
from email.mime.text import MIMEText
import matplotlib.pyplot as plt
import seaborn as sns


# Étape 1 : Extraction des Flux RSS
def extract_rss_feed(url):
    print(f"Extraction des flux RSS depuis : {url}")
    try:
        rss_feed = feedparser.parse(url)
        entries = []
        for entry in rss_feed.entries:
            entries.append({#liste rss et syntaxe 
                "title": entry.title,
                "description": entry.description,
                "link": entry.link,
                "published": entry.published
            })
        print(f"{len(entries)} entrées extraites.")
        return entries
    except Exception as e:#message erreur
        print(f"Erreur lors de l'extraction RSS : {e}")
        return []

# Étape 2 : Extraction des CVE
def extract_cves_from_json(url):
    print(f"Extraction des CVE depuis le JSON : {url}")
    try:
        response = requests.get(url)
        if response.status_code != 200:#vérifie l'état de la requête 200 est la valeur pour bon
            print(f"Erreur lors de l'accès au JSON : {response.status_code}")
            return []

        data = response.json()

        # Extraire les CVE depuis la clé "cves"
        cves_from_key = [cve["name"] for cve in data.get("cves", [])]

        # Extraire les CVE avec une regex
        cve_pattern = r"CVE-\d{4}-\d{4,7}" #syntaxe prédéfinie d'une séquence de CVE-4chiffres-4 à 7 chiffres
        cves_from_regex = list(set(re.findall(cve_pattern, str(data))))

        # Fusionner les résultats uniques
        cves = list(set(cves_from_key + cves_from_regex))
        print(f"{len(cves)} CVE trouvées.")
        return cves
    except Exception as e:
        print(f"Erreur lors de l'extraction des CVE : {e}")
        return []

# Étape 3 : Enrichissement des CVE
def enrich_cve_with_mitre(cve_id):
    print(f"Enrichissement de la CVE via MITRE : {cve_id}")
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        response = requests.get(url)
        if response.status_code != 200:
            print(f"Erreur pour {cve_id}: {response.json().get('message', 'Erreur inconnue')}")
            return {
                "cve_id": cve_id,#syntaxe liste cve
                "cvss_score": None,
                "cwe": "Non disponible",
                "cwe_desc": "Non disponible",
                "affected_products": []
            }

        data = response.json()

        # Extraire le score CVSS
        cvss_score = None
        metrics = data["containers"]["cna"].get("metrics", [])#score qui sera utilisé pour envoyer les mails
        if metrics:
            cvss_score = metrics[0].get("cvssV3_1", {}).get("baseScore", None)

        # Extraire le type CWE
        cwe = "Non disponible"#valeurs par défaut
        cwe_desc = "Non disponible"
        problemtype = data["containers"]["cna"].get("problemTypes", [])
        if problemtype and "descriptions" in problemtype[0]:
            cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
            cwe_desc = problemtype[0]["descriptions"][0].get("description", "Non disponible")

        # Extraire les produits affectés
        affected_products = []
        for product in data["containers"]["cna"].get("affected", []):
            vendor = product["vendor"]
            product_name = product["product"]
            versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
            affected_products.append({
                "vendor": vendor,
                "product": product_name,
                "versions": versions
            })

        return {
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "cwe": cwe,
            "cwe_desc": cwe_desc,
            "affected_products": affected_products
        }
    except Exception as e:
        print(f"Erreur lors de l'enrichissement pour {cve_id} : {e}")
        return {
            "cve_id": cve_id,
            "cvss_score": None,
            "cwe": "Non disponible",
            "cwe_desc": "Non disponible",
            "affected_products": []
        }

def enrich_cve_with_epss(cve_id):
    print(f"Enrichissement de la CVE via EPSS : {cve_id}")
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        response = requests.get(url)
        if response.status_code != 200:
            print(f"Erreur pour {cve_id}: {response.status_code}")
            return {"cve_id": cve_id, "epss_score": None}

        data = response.json()

        # Extraire le score EPSS
        epss_data = data.get("data", [])
        epss_score = epss_data[0]["epss"] if epss_data else None

        return {"cve_id": cve_id, "epss_score": epss_score}
    except Exception as e:
        print(f"Erreur lors de l'enrichissement pour {cve_id} : {e}")
        return {"cve_id": cve_id, "epss_score": None}

def enrich_cve(cve_id):
    mitre_data = enrich_cve_with_mitre(cve_id)
    epss_data = enrich_cve_with_epss(cve_id)
    mitre_data.update(epss_data)  # Fusion des résultats
    return mitre_data

def limit_cve_enrichment(cve_list, limit=20):
    print(f"Enrichissement des CVE (limité à {limit})...")
    enriched_cves = []
    cve_list = list(cve_list)  # Convertir l'ensemble en liste pour permettre l'indexation
    for cve_id in cve_list[:limit]:  # Appliquer la limite
        enriched_cves.append(enrich_cve(cve_id))
    return enriched_cves

# Étape 4 : Consolidation des données
def consolidate_data(entries, enriched_cves):
    print("Consolidation des données dans un DataFrame...")
    data = []
    cve_to_entries = {cve["cve_id"]: [] for cve in enriched_cves}

    for entry in entries:
        json_url = entry["link"] + "/json/"
        cves_in_entry = extract_cves_from_json(json_url)
        for cve_id in cves_in_entry:
            if cve_id in cve_to_entries:
                cve_to_entries[cve_id].append(entry)

    for cve in enriched_cves:#organise les données
        if cve["cve_id"] in cve_to_entries:
            for entry in cve_to_entries[cve["cve_id"]]:
                data.append({
                    "Titre": entry["title"],
                    "Type": "Alerte" if "alerte" in entry["link"] else "Avis",
                    "Date": entry["published"],
                    "CVE": cve["cve_id"],
                    "CVSS": cve.get("cvss_score", None),
                    "CWE": cve.get("cwe", None),
                    "CWE_Desc": cve.get("cwe_desc", None),
                    "EPSS": cve.get("epss_score", None),
                    "Lien": entry["link"]
                })

    df = pd.DataFrame(data)
    print(f"DataFrame créé avec {len(df)} lignes après suppression des duplications.")
    return df

# Étape 6 : Envoi d'alertes email
def send_alert_email(to_email, subject, body):
    """
    Envoie une notification email en utilisant un serveur SMTP.
    """
    from_email = "projetpythonaesilv@gmail.com"
    password = "hdox cruv gwtn fvvo"  # Utilisez un mot de passe d'application (non le mot de passe normal)

    # Création de l'email
    msg = MIMEText(body)
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    try:
        # Connexion au serveur SMTP de Gmail
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Démarrer la connexion sécurisée
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())#Envoie l'email
        server.quit()
        print(f"Email envoyé avec succès à {to_email}")
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'email : {e}")

# Fonction principale
def main(limit=20):
    print("Début du programme...")
    url_avis = "https://www.cert.ssi.gouv.fr/avis/feed"
    url_alertes = "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-001/feed"
    
    # Extraction des flux RSS
    avis_entries = extract_rss_feed(url_avis)
    alertes_entries = extract_rss_feed(url_alertes)
    entries = avis_entries + alertes_entries

    # Extraction des CVE
    all_cves = []
    for entry in entries[:10]:
        json_url = entry["link"] + "/json/"
        all_cves.extend(extract_cves_from_json(json_url))

    # Enrichissement des CVE
    enriched_cves = limit_cve_enrichment(set(all_cves), limit)

    # Consolidation des données
    df = consolidate_data(entries, enriched_cves)
    
    # Exporter les données consolidées
    df.to_csv('consolidate_data.csv', index=False)
    print("Les données consolidées ont été enregistrées dans 'consolidate_data.csv'.")

    # Saisie de l'adresse e-mail
    email = input("Entrez l'adresse e-mail à laquelle envoyer les alertes critiques : ").strip()
    
    # Vérification basique de l'adresse e-mail
    if "@" not in email or "." not in email:
        print("Adresse e-mail invalide. Veuillez relancer le programme et entrer une adresse valide.")
        return

    # Envoi des alertes critiques
    critical_vulns = df[df["CVSS"] >= 9]  # Vulnérabilités critiques
    if critical_vulns.empty:
        print("Aucune vulnérabilité critique détectée.")
    else:
        for _, vuln in critical_vulns.iterrows():
            subject = f"ALERTE CRITIQUE : {vuln['CVE']}"
            body = f"""Vulnérabilité critique détectée :
            Titre : {vuln['Titre']}
            CVE : {vuln['CVE']}
            Score CVSS : {vuln['CVSS']}
            Type CWE : {vuln['CWE']} ({vuln['CWE_Desc']})
            Probabilité d'exploitation (EPSS) : {vuln['EPSS']}
            Lien : {vuln['Lien']}
            """
            send_alert_email(email, subject, body)
        print(f"Alertes critiques envoyées à {email}.")

if __name__ == "__main__":
    main(limit=500)