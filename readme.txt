This program leverages Algosec API in retrieving risky rules from firewalls based on Algosec risk codes
and further streamline by providing custom risk codes in populated in crit_risk_codes.txt and 
high_risk_codes.txt.

Requirements

- in the "risky_rules_domains" folder, create a text file with the name of your environment

- list the names of the firewalls to analyze in that environment (as used in Algosec web interface)

- you can have as many environments in the folder as desired.

- you can also have as many firewalls listed in the environment text file.

- fill out the blank string quotes in config.py (username, password, email, url etc...)



Usage

- then run riskStatusReport.py (or riskStatusCaller.ipynb in ipython nodtebook)


Result

- The output of these program is an excel workbook (one for each environment) with list of risky rules, 
	including trafficCount, riskCodes, comments (if available) that are contributing to the risks 
		on each firewall listed in the environment.

- Also, the first sheet on each workbook contains a summation of the total counts 
	of each rule type per firewall, per environment.

- Finally, a copy odf the report is sent to the TEST_email address entered in config.py 
	while another copy resides in the risky_rules_domains folder. 



Please contact shittuayobami@yahoo.com for any concerns.