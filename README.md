# CVESummariser
parse cves from a spreadsheet and store the result 


This code uses the get_cve_details() function that we defined earlier to fetch the affected products, severity score, vulnerability description, CVSSv3 base score, and access vector for each CVE ID in the input spreadsheet. It then uses the at method of the DataFrame object to add these details as new columns in the DataFrame. Finally, it writes the updated DataFrame to a new Excel file called "output.xlsx".

You can save this code in a Python file (e.g. cve_details.py) and run it with the input spreadsheet as an argument:


python cve_details.py input.xlsx

The script will read the CVE IDs from the input spreadsheet and fetch the affected products, severity score, vulnerability description, CVSSv3 base score, and access vector for each CVE ID. It will then add these details as new columns in the DataFrame and write
