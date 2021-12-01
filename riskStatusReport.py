#!/usr/bin/env python
# coding: utf-8

# In[26]:


import pandas as pd
import algo_api_v4
import glob
import os
from datetime import date
import concurrent.futures
import time
import email_remediation
import config
t1 =time.perf_counter()


def main(receiver=None,critical_only=False):
    
    risky_rules_domains = [file for file in glob.glob(f"{os.getcwd()}\\risky_rules_domains\\*txt")]
    report_date = date.today().strftime('%d_%m_%Y')
    attachments=[]


    def main_1(file):


        with open(file_name, 'r') as f:
            fw_group=f.name.split('\\')[-1].split('.')[0]
            fws = [line.strip() for line in f.readlines()]

        algo = algo_api_v4.Algosec('prod')
        algo.afa_login()


        with concurrent.futures.ThreadPoolExecutor() as executor:
            capture = executor.map(algo.retrieve_risky_rules, fws)
            capture2 = executor.map(algo.retrieve_rules, fws)
            all_results = [i for i in capture]
            all_results2 = {i[0]:i[1] for i in capture2 if type(i)!=dict}


        Risky_rules = [[list(i.values())[0][0],list(i.values())[0][1]] for i in all_results if list(i.keys())[0]=='Risky_rules']
        Risk_sum = [(list(i.values())[0][0],list(i.values())[0][2][0],list(i.values())[0][2][1]) for i in all_results if list(i.keys())[0]=='Risky_rules']
        

        No_risky_rules = [list(i.values())[0] for i in all_results if list(i.keys())[0]=='No_risky_rules']
        Exceptions = [list(i.values())[0] for i in all_results if list(i.keys())[0]=='Exception']

        Risky_rules = [(i[0],i[1],all_results2.get(i[0])) for i in Risky_rules]        
        report_name = f"{os.getcwd()}\\risky_rules_domains\\{fw_group}_Risky_Rules_Report_{report_date}.xlsx"

        with pd.ExcelWriter(report_name) as writer:

            pd.DataFrame(Risk_sum, columns=['Device','Critical','High']).to_excel(writer,sheet_name='Summary',index=False)
  
            for i in Risky_rules:

                if not critical_only:
                    if not 'comments' in i[2].columns:
                        i[2]['comments'] = None
                    r_merge = i[1].merge(i[2][['ruleId', 'comments']], how='left', on='ruleId')

                    try:
                        r_merge.to_excel(writer, sheet_name=i[0], index=False)
                    except:# InvalidWorksheetName:
                        r_merge.to_excel(writer, sheet_name=i[0][:30], index=False)

                else:    
                    if not 'comments' in i[2].columns:
                        i[2]['comments'] = None
                    r_merge = i[1].merge(i[2][['ruleId', 'comments']], how='left', on='ruleId')
                    r_merge = r_merge[r_merge.severity=='Critical']

                    try:
                        r_merge.to_excel(writer, sheet_name=i[0], index=False)
                    except:# InvalidWorksheetName:
                        r_merge.to_excel(writer, sheet_name=i[0][:30], index=False)


            if No_risky_rules:
                pd.DataFrame(No_risky_rules,columns=['Fws','Critical','High']).to_excel(writer, sheet_name='No_risky_rules',index=False)
            if Exceptions:
                pd.DataFrame(Exceptions,columns=['Fws','Critical','High']).to_excel(writer, sheet_name='Exceptions', index=False)


        print(f'      - Fetching data for {fw_group}')
        attachments.append(report_name)


    print('\nin progress...')
    for file_name in risky_rules_domains:    
        main_1(file_name)
    
    print(f'\nCompleted in {round(((time.perf_counter()-t1)/60),2)} Mins')
    if receiver:
        email_remediation.outlook_email(to=receiver, attachments=attachments)
        return

    else:
        email_remediation.outlook_email(attachments=attachments)

        return


if __name__=="__main__":
    main()
#     main('example@email.com')

