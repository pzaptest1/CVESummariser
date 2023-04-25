import requests
import sys
import pandas as pd

def get_cve_details(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    r = requests.get(url)
    data = r.json()
    if "result" in data and "CVE_Items" in data["result"]:
        cve_item = data["result"]["CVE_Items"][0]
        configurations = cve_item["configurations"]["nodes"]
        products = []
        for config in configurations:
            if "cpe_match" in config:
                for cpe in config["cpe_match"]:
                    products.append(cpe["cpe23Uri"])
        base_score = cve_item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
        access_vector = cve_item["impact"]["baseMetricV3"]["cvssV3"]["attackVector"]
        severity = cve_item["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
        description = cve_item["cve"]["description"]["description_data"][0]["value"]
        return {"products": products, "base_score": base_score, "access_vector": access_vector, "severity": severity, "description": description}
    else:
        return {}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Please provide the path to the input spreadsheet as an argument.")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = "output.xlsx"
    df = pd.read_excel(input_file)

    for index, row in df.iterrows():
        cve_id = row["CVE ID"]
        if cve_id.startswith("CVE-"):
            cve_details = get_cve_details(cve_id)
            if cve_details:
                df.at[index, "Affected Products"] = ", ".join(cve_details["products"])
                df.at[index, "CVSSv3 Base Score"] = cve_details["base_score"]
                df.at[index, "CVSSv3 Access Vector"] = cve_details["access_vector"]
                df.at[index, "Severity Score"] = cve_details["severity"]
                df.at[index, "Description"] = cve_details["description"]
            else:
                print(f"CVE ID {cve_id} not found.\n")
        else:
            print(f"Invalid ID format for row {index+1}. Please use a CVE ID.\n")

    df.to_excel(output_file, index=False)
    print(f"Results saved to {output_file}")
