#!/usr/bin/env python
# coding: utf-8

# In[4]:


import config
import win32com.client as win32
# # from campaign import campaign
# # h_body = campaign()

def outlook_email(to=None, attachments=None):
#     """Takes attachment parameter which is equal to path to attachment\n\n\
#     Example:\n\natt=r'C:\D-Drive\PM Routine\pm routine\Tasks assigned.txt\n\n\
#     outlook_email(attachment)"""
    to=to
    outlook = win32.Dispatch('outlook.application')
    mail = outlook.CreateItem(0)
    mail.To = config.TEST if not to else to
#     mail.Cc = config.CC
    mail.Subject = 'Risk Report'
    mail.HTMLBody = '<h3>Hello, <br/>Please find attached risk report.<br/>    Kindly report any errors or missing data in this file.<br/><br/>Thanks<br/>Remediation Team</h3>'
    
    # To attach a file to the email (optional):
#     if attachment:
#         mail.Attachments.Add(attachment)
        
    if attachments:     #Testing loop through attachments
        [mail.Attachments.Add(attachment) for attachment in attachments]

    mail.Send()
    print('\nEmail sent!')
    return

# path = r"C:\Users\foo.bar\Desktop\Risk score\Severity\severity_v1\\"
# file = 'W0575NtEpsFwsD0_MobDmz 533618.csv'
# attachment=f'{path}{file}'
# outlook_email(attachment)

