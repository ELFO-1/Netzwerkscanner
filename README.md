# Netzwerkscanner
Nwtzwerkscanner using nmap and visualation


  Ein kleiner Netzwerkscanner der nmap nutzt :
  
  # Normale Ausführung mit interaktiver Eingabe:
sudo ./netzwerk_scanner.py

# Mit automatischem Reporting:
sudo ./netzwerk_scanner.py -o scan_ergebnisse

# Im Verbose-Modus:
sudo ./netzwerk_scanner.py -v


Die generierten Dateien werden im aktuellen Verzeichnis gespeichert:

    scan_ergebnisse.html (HTML-Report)
    scan_ergebnisse.json (Rohdaten)
    scan_ergebnisse_devices.csv (Geräteliste)
    scan_ergebnisse_vulnerabilities.csv (Sicherheitslücken)
    nmap_scan.log (Log-Datei)
