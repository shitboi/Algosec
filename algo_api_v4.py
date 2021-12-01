#!/usr/bin/env python
# coding: utf-8

# In[64]:


try:  
    import json
    import sys
    import config
    import pandas as pd
    import requests
    from datetime import date
except:
    import pip
    pip.main(['install', 'pandas'])
    pip.main(['install', 'requests'])
    import json
    import sys
    import config
    import pandas as pd
    import requests
    from datetime import date

requests.packages.urllib3.disable_warnings()


with open('crit_risk_codes.txt', 'r') as f:
    crit_risk_codes = [i.strip() for i in f.readlines()]
    
with open('high_risk_codes.txt', 'r') as f:
    high_risk_codes = [i.strip() for i in f.readlines()]


class Algosec:
    def __init__(self, environment: str = 'prod'):
        if environment == 'dev':
            self.url = config.ALGOSEC_API_URL_DEV
        else:  # TODO: Algosec in prod environment # have to update this info/or maybe make the user pass it?
            self.url = config.ALGOSEC_API_URL_PROD
#         print(self.url)
        self.username = config.ALGOSEC_API_USERNAME
        self.password = config.ALGOSEC_API_PASSWORD
#         print(self.username)
#         print(self.password)
        self.wsdl_url = f"{self.url}/AFA/php/ws.php?wsdl"
        self.wsdl_ffa = f"{self.url}/WebServices/FireFlow.wsdl"
        self._token = ""
        self._soap_client = None
        self._soap_session_id = ""


        
    def afa_login(self):
        url = '/fa/server/connection/login'
        status = requests.post(self.url + url,
                               data=json.dumps({"username": self.username, "password": self.password}),
                               headers={"Content-Type": "application/json"}, verify=False)
        response = json.loads(status.content.decode('utf8'))
#         print(response)
        if not response['status']:
            print(f"Authentication Failure   {response['message']}")
            sys.exit(-1000)
        else:
            self.afa_token = response.get('SessionID')
#         print(self.afa_token)
        
    def afa_logout(self):
        url = '/fa/server/connection/logout'
        response = requests.post(self.url + url,
                                 data=json.dumps({"session": self.afa_token}),
                                 headers={"Content-Type": "application/json"}, verify=False)
        # print(f"logout from AFA: {response.status_code}")
        
        
        
    def retrieve_rules(self, device_name):

        head = ['device', 'ruleId', 'comments']
        
        try:
            response = requests.get(self.url + "/fa/server/rules/read",
                                    params=({"session": self.afa_token, "entity": device_name, "entity_type": "device"}),
                                    verify=False)
        except Exception as e:
            return (device_name, 'request_error', 'request_error')
        
        result = json.loads(response.content.decode('utf8'))

        if not result['status']:

            if (("Backend error:") or ("Failed to find rules data")) in result["message"]:
                return {'No_rules':(device_name, 0, 0)}
        
            if (("Not found") or ("Unknown firewall")) in result["message"]:
                return {'Exception':(device_name, 'Unknown firewall', 'Unknown firewall')}

            return {'Exception':(device_name, 'Unknown_error', 'Unknown_error')}


        else:
            try:
                if len(result['0'])<1:
                    return {'No_rules':(device_name, 0, 0)}
                
#                 Added this else statement and commented out the last the last return n line #126
                else:
                    all_rules = pd.DataFrame(result['0']['rules'])
                    return(device_name,all_rules)                
            except:
                return {'No_rules':(device_name, 0, 0)}
            
#.....................................................................................................................      


    def retrieve_risky_rules(self, device_name):
        # device name to be passed, returns rule_id, maybe comment?
        
        filtered_rules = []
        fw_exceptions = []
        no_risky_rules = []
        head = ['device','ruleId','ruleNum','source','destination','service','action','trafficCount','severity','riskCode']
        
        try:
            response = requests.get(self.url + "/fa/server/risks/riskyRules",
                                    params=({"session": self.afa_token, "entity": device_name, "entity_type": "device"}),
                                    verify=False)
#             print(result['riskyRules'][0])
        except Exception as e:
            return (device_name, 'request_error', 'request_error')
        
        result = json.loads(response.content.decode('utf8'))
        
        if not result['status']:

            if (("Backend error:") or ("Failed to find risky rules data")) in result["message"]:
                return {'No_risky_rules':(device_name, 0, 0)}
        
            if (("Not found") or ("Unknown firewall")) in result["message"]:
                return {'Exception':(device_name, 'Unknown firewall', 'Unknown firewall')}

            return {'Exception':(device_name, 'Unknown_error', 'Unknown_error')}


        else:
            try:
                if len(result['riskyRules'])<1:
                    return {'No_risky_rules':(device_name, 0, 0)}
                
            except:
                return {'No_risky_rules':(device_name, 0, 0)}
            
            all_risks=[item for item in result['riskyRules']]

            for risky_rule in all_risks:
                rule = [risky_rule.get(i) for i in head[:8]]

                avail_codes = [i['code'] for i in risky_rule['risks']]

                if set(avail_codes).intersection(set(crit_risk_codes)):
                    rule.append('Critical')
                    rule.append("".join(list(set(avail_codes))))
                    filtered_rules.append(rule)

                elif set(avail_codes).intersection(set(high_risk_codes)):
                    rule.append('High')
                    rule.append(",".join(list(set(avail_codes))))
                    filtered_rules.append(rule)                    
            
            total = pd.DataFrame(tuple(filtered_rules), columns=head)
            summary = (len(total[total['severity']=='Critical']), len(total[total['severity']=='High']))
# #             total.excel(f'{device_name}.xlsx')        
            
            return {'Risky_rules':(device_name,total,summary)} if filtered_rules else {'Exception':fw_exceptions[0]}

        


        
        
# algo = Algosec('prod')
# algo.afa_login()
# # fw26_toronto63_IaaS-IntDmz
# # print(algo.rule_based_summary('fw26_toronto63_IaaS-IntDmz'))
# algo.retrieve_risky_rules('fw26_toronto63_IaaS-IntDmz')
# # ffff= algo.retrieve_rules('fw26_toronto63_IaaS-IntDmz')

