# Tanium ATT&CK Coverage Report
Python script which takes in a JSON export of Tanium Threat Response signals & creates a coverage report mapped to ATT&CK.

For visual representations of MITRE ATT&CK coverage, use Excel to create charts based on the coverage metrics generated by this script.

# Installation
This script requires Python 3 to run.

1. Initialise a new virtual environment.
```
python3 -m venv "venv/"
```
2. Activate the virtual environment.
```
source venv/bin/activate
```
3. Install the necessary Python packages.
```
python3 -m pip install -r requirements.txt
```

# Help
## Usage
```
usage: ATTACK_ThreatResponse_Coverage_Checker.py [-h] [--outpath OUTPATH] [--url URL] path

Maps an export of Tanium Threat Response signals to MITRE ATT&CK.

positional arguments:
  path               Path to the export of Tanium Threat Response signals in JSON format.

options:
  -h, --help         show this help message and exit
  --outpath OUTPATH  Sets the output folder path (default = current directory)
  --url URL          MITRE ATT&CK Techniques URL - see Excel documents under https://attack.mitre.org/resources/working-with-attack/.
```

## Getting Threat Response JSON Data
1. Navigate to your Tanium console.
2. Navigate to Modules > Threat Response > Intel > Documents
3. Filter down via labels to the currently deployed Threat Response rules.
4. Set "Type" to "Tanium Signal"
5. Select all entries then click the "Actions" dropdown & choose "Export"

## Common Issues
1. If you receive an error trying to download the MITRE ATT&CK Excel Spreadsheet, please navigate to https://attack.mitre.org/resources/working-with-attack/ & pass the URL for the **techniques** spreadsheet listed under "ATT&CK in Excel", currently this link is:
> https://attack.mitre.org/docs/enterprise-attack-v13.1/enterprise-attack-v13.1-techniques.xlsx
