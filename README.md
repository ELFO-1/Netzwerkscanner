# Netzwerkscanner
Nwtzwerkscanner using nmap and visualation


  Ein kleiner Netzwerkscanner der nmap nutzt :
  
  # Normale Ausführung mit interaktiver Eingabe:
sudo ./netzwerkscan.py

# Mit automatischem Reporting:
sudo ./netzwerkscan.py -o scan_ergebnisse

# Im Verbose-Modus:
sudo ./netzwerk_scan.py -v


Die generierten Dateien werden im aktuellen Verzeichnis gespeichert:

    scan_ergebnisse.html (HTML-Report)
    scan_ergebnisse.json (Rohdaten)
    scan_ergebnisse_devices.csv (Geräteliste)
    scan_ergebnisse_vulnerabilities.csv (Sicherheitslücken)
    nmap_scan.log (Log-Datei)
