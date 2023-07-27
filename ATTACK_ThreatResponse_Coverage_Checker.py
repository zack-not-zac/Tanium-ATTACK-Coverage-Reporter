#!/usr/bin/python3
import json
import argparse
from pandas import read_excel, DataFrame
from requests import get
from pathlib import Path
from os import getcwd, chdir

def parse_json(path):
    with open(path,"r") as file:
        print("Loading Tanium Threat Response signal information from: " + path)
        data = json.load(file)
    
    return data

def parse_mitre_techniques(path):
    techniques = dict()
    indexes = list()
    
    df = read_excel(path)
    df = df.reset_index()

    for index, row in df.iterrows():                    # For loop creates the dictionary of techniques & their associated tactics.
        tactics = list()
        for tactic in row["tactics"].split(","):
                tactics.append(tactic.strip())
        techniques.update({row["ID"]:tactics})

    tacticList = df["tactics"].to_list()
    tactics = set()
    for tactic in tacticList:                           # Creates a set of tactics present in the MITRE ATT&CK version imported.
        temp = tactic.split(",")
        for item in temp:
            tactics.add(item.strip())

    return techniques, tactics

def format_signal(signal,mitre_data,mitre_tactics):
    item = dict()
    # Retrieve the desired fields from the signal data & place into temp_dict
    item["name"] = signal["data"]["name"]

    # Creates a tactic entry for every MITRE ATT&CK tactic
    for tactic in mitre_tactics:
        item[tactic] = []

    # Maps the techniques of the alert to the relevant tactic column
    for technique in signal["data"]["mitreAttack"]["techniques"]:
        mitre_id = technique["id"]
        tactics = mitre_data[mitre_id]
        for tactic in tactics:
            item[tactic].append(mitre_id)
        
    return item

def get_args():
    parser = argparse.ArgumentParser(
        description="Maps an export of Tanium Threat Response signals to MITRE ATT&CK."
    )
    parser.add_argument("path",help="Path to the export of Tanium Threat Response signals in JSON format.")
    parser.add_argument("--outpath",help="Sets the output folder path (default = current directory)", default=getcwd()+"/output")
    parser.add_argument("--url",help="MITRE ATT&CK Techniques URL - see Excel documents under https://attack.mitre.org/resources/working-with-attack/.",default="https://attack.mitre.org/docs/enterprise-attack-v13.1/enterprise-attack-v13.1-techniques.xlsx")

    return parser.parse_args()

def append_dict_to_df(item,df):# Appends a dict item to a dataframe, using keys as columns & values as cells
    l = list()

    for key in item:
        l.append(item[key])
    
    df.loc[len(df)] = l

    return df

def write_to_csv(df,folder_path,file_name):
    if folder_path.exists() and folder_path.is_dir():
        chdir(folder_path)
    else:
        folder_path.mkdir(parents=True)
        chdir(folder_path)
    
    df.to_csv(file_name, index=False)

    return file_name

def main():
    # Parses commandline arguments
    args = get_args()

    # Sets variables
    signals_path = args.path
    mitre_techniques_url = args.url
    mitre_techniques_path = mitre_techniques_url.split("/")[-1]
    outpath = Path(args.outpath)

    # Checks if mitre xlsx file exists, downloads it if not.
    if not Path(mitre_techniques_path).is_file():
        print("MITRE ATT&CK techniques Excel sheet not found, downloading a fresh copy...")
        response = get(mitre_techniques_url)
        if response.status_code > 299:
            print("MITRE ATT&CK Techniques spreadsheet URL returned a " + str(response.status_code) + " error. Please check https://attack.mitre.org/resources/working-with-attack/ for an updated URL.")
            exit()
        else:
            with open(mitre_techniques_path, "wb") as f:
                f.write(response.content)

    # Loads the Tanium Signals JSON file as a dictionary
    signal_library = parse_json(signals_path)["signals"]

    # Loads a dictionary of all techniques from the MITRE ATT&CK spreadsheet & maps them to tactics using a dict, returns a set of listed tactics
    mitre_data, mitre_tactics = parse_mitre_techniques(mitre_techniques_path)

    temp_cols=list(mitre_tactics)
    temp_cols.insert(0,"Signal Name")

    alert_report = DataFrame(columns=temp_cols)                                                     # Creates a new dataframe for signal name & all MITRE tactics & techniques (classic report)

    tactic_coverage = dict.fromkeys(mitre_tactics, 0)                                               # Creates a dict object for all tactics & an integer to count the number of alerts covering this tactic         
    technique_coverage = dict.fromkeys(mitre_tactics,set())                                         # Creates a dict object for all tactics & a set to store all techniques covered under that tactic

    for signal in signal_library:
        item = format_signal(signal,mitre_data,mitre_tactics)                                       # Item is a dict object containing the name & MITRE tactics as keys, then the alert name & MITRE technique ID's as values.
        alert_report = append_dict_to_df(item,alert_report)

        for tactic in item:
            if len(item[tactic])!=0:
                if tactic in mitre_tactics:                                                         # Ensures misc fields such as "name" do not end up classed as tactics
                    tactic_coverage[tactic] += 1

                    temp_set = set(item[tactic])                                                    # converts the list to a set
                    technique_coverage[tactic] = technique_coverage[tactic].union(temp_set)         # Joins the temp_set to the set of keys for the tactic.    
        
    technique_coverage_df = DataFrame(columns=["Tactic","Techniques Covered","Number of Rules"])    # Create dataframe to hold coverage report metrics

    for tactic in technique_coverage:
        technique_coverage_df.loc[len(technique_coverage_df)] = [tactic,len(technique_coverage[tactic]),tactic_coverage[tactic]] # Adds the tactic name, number of unique techniques covered per tactic, & the total number of rules per tactic

    print(technique_coverage_df)

    # Write CSV outputs
    print("\nWrote the following files under: " + args.outpath)
    print("> " + write_to_csv(alert_report,outpath,"alert_report.csv"))
    print("> " + write_to_csv(technique_coverage_df,outpath,"technique_coverage.csv"))

if __name__ == "__main__":
    main()