# APT-36

## APT Attributes about APT36

1. APT 36 ( aka: APT 36, APT36, C-Major, COPPER FIELDSTONE, Earth Karkaddan, Green Havildar, Mythic Leopard, ProjectM, Storm-0156, TMP.Lapis, Transparent Tribe )
2. Group targeting Indian Army or related assets in India, as well as activists and civil society in Pakistan. Attribution to a Pakistani connection has been made by TrendMicro and others.
3. It has been active since at least 2013, primarily targeting diplomatic, defense, and research organizations in India and Afghanistan.
4. On feb 11, 2016: 2 attacks a min apart from each other was directed towards at Indian enbassies in both Saudi Arabia and Kazakhstan.
5. Both e-mails were sent from the same originating IP (`5[.]189.170.84`) address ([link - github](https://github.com/BRANDEFENSE/IoC/blob/main/IoC-YARA-rules-apt36.txt#L58)). \
All Ip addresses can be found from here - [link - github](https://github.com/BRANDEFENSE/IoC/blob/main/IoC-YARA-rules-apt36.txt#L46)
6. The mails were likely via MailGun tool ([link](https://www.proofpoint.com/sites/default/files/proofpoint-operation-transparent-tribe-threat-insight-en.pdf) search: "MailGun").
7. Another Email Campaign using "2016 Pathankot attack" Lure Lure (url: https://www.proofpoint.com/sites/default/files/proofpoint-operation-transparent-tribe-threat-insight-en.pdf (search: "Email Campaign using "2016 Pathankot attack" Lure``"))
8. In that particular Incident attachment was a weaponised RTF document utilizing [CVE-2012-0158 (BufferOverflow Vuln)](https://securelist.com/the-curious-case-of-a-cve-2012-0158-exploit/37158/) to drop an embedded, encoded portable exeutable (PE).
9. To decode the embedded PE:
    - the document's shellcode first searches for the `0xBABABABA` marker that, when found, will indicate the beginning positon of the PE. The PE is then decoded using the key `0xCAFEBABE`.
    - A final marker indicates the end of the PE file, which in this case, is the marker `0xBBBBBBBB`.
    
10. Fake Blog post named, "blogspot.com" site (`intribune.blogspot[.]com`) was created by same actor to lure Indian Military to become infected by `Crimson`, `njrat` and others. \
More Softwares that are used by APT36 can be found [here - MITRE attack groups](https://attack.mitre.org/groups/G0134/) (search: "Software").
11. The actors used hyperlinks via an image or text or via an iframe to redirect victims to download malicious payloads.
12. Lure Articles:
    
    1. 
    <img width="1416" height="334" alt="image" src="https://github.com/user-attachments/assets/e9f00ac5-f680-47ad-abb0-53be8957de94" />
    <img width="1521" height="62" alt="image" src="https://github.com/user-attachments/assets/801eb6b7-5a8a-462e-903a-47a17b71aa36" />

    2. 
    <img width="1442" height="495" alt="image" src="https://github.com/user-attachments/assets/3fc1ca14-ef9f-4c67-b8f8-4b51fb1379aa" />

    3.
    <img width="1339" height="290" alt="image" src="https://github.com/user-attachments/assets/929b5d6b-0597-4f6a-be99-1586bc0b7039" />

    4. 
    <img width="1480" height="383" alt="image" src="https://github.com/user-attachments/assets/21153b49-a725-4266-9277-468f14e8724e" />

    5.
    <img width="1220" height="135" alt="image" src="https://github.com/user-attachments/assets/abe1333c-2487-435e-8f78-dbd61c588c40" />

    6.
    <img width="1159" height="305" alt="image" src="https://github.com/user-attachments/assets/0eaca889-8259-4d1e-8ed5-07a1f7b7206d" />
    <img width="1431" height="107" alt="image" src="https://github.com/user-attachments/assets/d71bc917-8381-43cb-b81b-14ade774e24e" />
    <img width="1453" height="1233" alt="image" src="https://github.com/user-attachments/assets/f9bc320f-2a8e-4a16-8aa1-4e0582eb4254" />


    7.
    
    



    
