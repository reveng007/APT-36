# APT-36

## APT Attributes about APT36

1. APT 36 ( aka: APT 36, APT36, C-Major, COPPER FIELDSTONE, Earth Karkaddan, Green Havildar, Mythic Leopard, ProjectM, Storm-0156, TMP.Lapis, Transparent Tribe )
2. Group targeting Indian Army or related assets in India, as well as activists and civil society in Pakistan. Attribution to a Pakistani connection has been made by TrendMicro and others.
3. It has been active since at least 2013, primarily targeting diplomatic, defense, and research organizations in India and Afghanistan.
4. On feb 11, 2016: 2 attacks a min apart from each other was directed towards at Indian enbassies in both Saudi Arabia and Kazakhstan.
5. Both e-mails were sent from the same originating IP (`5[.]189.170.84`) address ([link - github](https://github.com/BRANDEFENSE/IoC/blob/main/IoC-YARA-rules-apt36.txt#L58)). \
All Ip addresses can be found from here - [link - github](https://github.com/BRANDEFENSE/IoC/blob/main/IoC-YARA-rules-apt36.txt#L46)
6. The mails were likely via MailGun tool ([link](https://www.proofpoint.com/sites/default/files/proofpoint-operation-transparent-tribe-threat-insight-en.pdf) search: "MailGun").
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


13. Cluster Analysis on MSIL/Crimson Implant (including only `APT36 Operations`):
    1. Samples dating back to 2012. Begins with embassy phishing and the fake Indian‐news blog (`intribune[.]blogspot[.]com`). Tools include Crimson plus _Luminosity Link RAT_, _njRAT_, _Bezigate_, _Meterpreter_, and a closely related _Python/Peppy RAT_; _Andromeda_ downloaders also appear.
    2. Infra patterns: Mix of compromised and actor-owned domains (e.g., `sahirlodhi[.]com` and `bbmsync2727[.]com`). Naming tells: “sync” strings, repeated use of “bb/bbm,” and second-level domains ending in 4 digits. Heavy use of Contabo GmbH hosted C2.
    3. Another Email Campaign using "2016 [Pathankot attack](https://en.wikipedia.org/wiki/2016_Pathankot_attack)" Lure ([link](https://www.proofpoint.com/sites/default/files/proofpoint-operation-transparent-tribe-threat-insight-en.pdf)) (search: "`Email Campaign using "2016 Pathankot attack" Lure`")
    - <img width="1459" height="650" alt="image" src="https://github.com/user-attachments/assets/ba9031a8-ad2c-43e8-a34f-c678ec598e21" />
    - <img width="1421" height="235" alt="image" src="https://github.com/user-attachments/assets/fa9e9365-0a2d-418c-9c52-ba8a3f3e1b27" />
    - <img width="1526" height="1160" alt="image" src="https://github.com/user-attachments/assets/839af7d4-86f3-47e6-afd1-f590587d55f9" />
    - <img width="859" height="153" alt="image" src="https://github.com/user-attachments/assets/5374726e-7b1f-41f3-8e83-da14d72032ef" />
    - <img width="1319" height="1219" alt="image" src="https://github.com/user-attachments/assets/4cf4cbf5-c974-4eca-8e34-e10d98d623e7" />
    1. **ATTACHMENT.BIZ domain**
      - fileshare.attachment[.]biz
      - comdtoscc.attachment[.]biz
      - ceengrmes.attachment[.]biz
      - email.attachment[.]biz (no links discovered) \
    All of the domains resolve to the same IP, 91.194.91[.]203 (Contabo GmbH). So far three separate campaigns was detected.

        <img width="1267" height="455" alt="image" src="https://github.com/user-attachments/assets/510d5ef8-dad4-4592-9669-c529dc118352" />

    2. **AFOWOBLOG.IN Domain**
       - The domain was registered on or near February 24th, 2016 using the email address `thefriendsmedia@gmail.com`, which is also close to the same day that the “AFOWO Broucher 2016.xls” attachment was uploaded to VT.
       - We have detected potentially connected activity as far back as June 2013 using the domain `thefriendsmedia[.]com`, where it was used as an Andromeda C&C.
       - _Andromeda payload_ communicate with `brooksidebiblefellowship[.]org` to retrieve an _additional Andromeda payload_ from `lolxone[.]com` that then used `thefriendsmedia[.]com` as its C&C.
       - The original _Andromeda_ also retrieved a _Bezigate payload_.
         <img width="1388" height="1188" alt="image" src="https://github.com/user-attachments/assets/22c10861-36fb-49b8-83bd-d831ad9fa1a2" />
       - It was observed `lolxone[.]com` hosting additional _Bezigate payloads_ as well as the _Python/Peppy malware_.
         <img width="1318" height="698" alt="image" src="https://github.com/user-attachments/assets/426c6d45-cb02-4d03-8082-99009cd129ce" />
         
    More Cluster Analysis on _MSIL/Crimson_ Implant can be found here:
    https://www.proofpoint.com/sites/default/files/proofpoint-operation-transparent-tribe-threat-insight-en.pdf (search: "`Cluster 2 — guddyapps / appstertech / sajid`" and "`Cluster 3 — “Nadra attack in Mardan” lures`" and "`Cluster 4 — DDNS & Pakistan`")

14. Technical Analysis:
    - Crimson is modular in the sense that additional payloads downloaded by the main RAT module are often utilized to perform functions such as keylogging and browser credential theft.
    - Crimson infections also typically occur in stages. Crimson’s first stage is a downloader component whose primary purpose is to download a more fully featured RAT, typically being the Crimson RAT component. The RAT component will then send system information to the C&C while the C&C will likely respond with additional module payloads.
    - Crimson utilizes a custom TCP protocol for communicating to C&C. Some of Crimson’s optionally downloaded modules have no C&C capability and instead rely on the RAT component for information exfiltration.
    - <img width="1186" height="117" alt="image" src="https://github.com/user-attachments/assets/c2a619cc-d467-4945-8531-b18a9eebb939" />
    - Some Crimson RAT variants support at least 40 individual commands, while all the individual commands throughout the different versions of the RAT we researched are listed.

| Table 1 | Table 2 |
| ------- | ------- |
| <img width="1030" height="1323" alt="image" src="https://github.com/user-attachments/assets/12a983fc-7db1-4172-84df-ba3823ccd50b" /> | <img width="1025" height="1051" alt="image" src="https://github.com/user-attachments/assets/c67f52a9-1065-467f-afd6-df920c404be1" /> | 

15. **MSIL/Crimson Module Analysis**:
    - These modules include :
        - keylogging,
        - browser credential theft,
        - automatic searching
        - and stealing of files on removable drives, and two different payload update modules.
        - Lastly, there appears to be a module referred to as “remvUser” that we have not been able to locate.
     
    - More can be found here: https://www.proofpoint.com/sites/default/files/proofpoint-operation-transparent-tribe-threat-insight-en.pdf (search: "MSIL/Crimson Module Analysis")

16. **Crimson Server** ([link](https://securelist.com/transparent-tribe-part-1/98127/)):
- It was found two different server versions. The one being a version that we named “A”, compiled in 2017, 2018 and 2019, and including a feature for installing the USBWorm component and executing commands on remote machines.
- The version that was named “B” was compiled in 2018 and again at the end of 2019. The existence of two versions confirms that this software is still under development and the APT group is working to enhance it.
- Securelist, analysed the .NET binary, and were able to set up a working environment and communicate with samples previously detected on victims’ machines.

**Crimson Server version “A”**:

1. Main Panel:
<img width="1149" height="278" alt="image" src="https://github.com/user-attachments/assets/4a91745f-77f7-42ec-8be9-2c45887623ee" />

Geolocation information is retrieved from a legitimate website using a remote IP address as the input. The URL used by the server is: `http://ip-api.com/xml/<ip>`

The server uses an embedded configuration specified inside a class named “settings”.

<img width="330" height="289" alt="image" src="https://github.com/user-attachments/assets/0777b933-728b-449a-ad26-6ba395517697" />

2. Bot panel:
The main features are accessible from the “bot panel”, an interface with twelve tabs, which can be used to manage a remote system and collect information.

- Update module:
  - The first tab is used for checking the client configuration, uploading Crimson components and executing these on remote system.
  - <img width="1063" height="486" alt="image" src="https://github.com/user-attachments/assets/e1e12211-5cf6-41f2-872c-2f8add2bc35f" />
  - The Crimson framework is composed of seven client components:
    - **Thin Client**: It is usually dropped during the infection process by which Transparent Tribe is distributed.
        - It contains a limited number of features and can typically be used to:
        - collect information about infected system
        - collect screenshots
        - manage the remote filesystem
        - download and upload files
        - get a process list
        - kill a process
        - execute a file
    - **Main Client**: the full-featured RAT. It can handle all “Thin Client” features, but it can also be used to:
        - install the other malware components
        - capture webcam images
        - eavesdrop using a computer microphone
        - send messages to the victim
        - execute commands with COMSPEC and receive the output.
    - **USB Driver**: a USB module component designed for stealing files from removable drives attached to infected systems.
    - **USB Worm**: This is the USBWorm component developed for stealing files from removable drives, spread across systems by infecting removable media, and download and execute the “Thin Client” component from a remote Crimson server.
    - **Pass Logger**: A credential stealer, used for stealing credentials stored in the Chrome, Firefox and Opera browsers.
    - **KeyLogger**: this is simple malware used for recording keystrokes.
    - **Remover**: Not much information regarding this.
    - Transparent Tribe tries to circumvent certain vendors’ security tools by configuring the Server to prevent installation of some of the malware components, specifically the “USB Driver” and the “Pass Logger”, on systems protected with ***Kaspersky products*** and prevent installation of the “Pass Logger” on systems protected by ***ESET***.
    - <img width="883" height="214" alt="image" src="https://github.com/user-attachments/assets/d83f75aa-102f-4ece-9664-2fec86a03dc7" />
    - 



Resources:
1. https://www.proofpoint.com/sites/default/files/proofpoint-operation-transparent-tribe-threat-insight-en.pdf
2. 


    
    
    



    
