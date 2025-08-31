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

### Crimson Server version “A”:

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
        - On January 2020, there was an Ongoing Campaign launched by Transparent Tribe to distribute the Crimson malware. The attacks started with malicious Microsoft Office documents, which were sent to victims using spear-phishing emails ([link](https://securelist.com/transparent-tribe-part-1/98127/)).
        - The documents typically have malicious VBA code embedded, and sometimes protected with a password, configured to drop an encoded ZIP file which contains a malicious payload.
        - Decoy document used in an attack against Indian entities:
            - <img width="738" height="426" alt="image" src="https://github.com/user-attachments/assets/f3afbdff-9b21-4a8a-ba3d-97816be9170a" />
        - User form with encoded payloads:
            - <img width="630" height="467" alt="image" src="https://github.com/user-attachments/assets/fd1da111-e31a-4d64-8494-e226c885f11f" />
        - The macro drops the ZIP file into a new directory created under %ALLUSERPROFILE% and extracts the archive contents at the same location. The directory name can be different, depending on the sample:
            - `%ALLUSERSPROFILE%\Media-List\tbvrarthsa.zip`
            - `%ALLUSERSPROFILE%\Media-List\tbvrarthsa.exe`
            - <img width="878" height="468" alt="image" src="https://github.com/user-attachments/assets/1f106f1f-553f-4602-807d-55743d945460" />
        - During the analysis of by securelist: they found one of the file path name combinations observed was `‘C:\ProgramData\Dacr\macrse.exe’`, also configured in a Crimson “Main Client” sample and used for saving the payload received from the C2 when invoking the usbwrm command.
        - <img width="1274" height="665" alt="image" src="https://github.com/user-attachments/assets/c2bba99f-ba40-459a-81d3-6c681867ddb7" />
        - **USB Worm description**:
        1. Usually, the component is installed by the Crimson “Main Client”, and when started, it checks if its execution path is the one specified in the embedded configuration and if the system is already infected with a Crimson client component (Probably used Mutex of some kind to check this: what reveng007 think!).
        2. If these conditions are met, it will start to monitor removable media, and for each of these, the malware will try to infect the device and steal files of interest.
        3. The infection procedure lists all directories. Then, for each directory, it creates a copy of itself in the drive root directory using the same directory name and changing the directory attribute to “hidden”. This results in all the actual directories being hidden and replaced with a copy of the malware using the same directory name.
        4. Moreover, **USBWorm** uses an icon that mimics a Windows directory, tricking the user into executing the malware when trying to access a directory.
        5. USBWorm icon:
            - <img width="96" height="113" alt="image" src="https://github.com/user-attachments/assets/0640f5bf-a50e-44e1-a032-7f470e899eb9" />
        6. This simple trick works very well on default Microsoft Windows installations, where file extensions are hidden and hidden files are not visible.
        7. The victim will execute the worm every time he tries to access a directory. Moreover, the malware does not delete the real directories and executes “explorer.exe” when started, providing the hidden directory path as argument. The command will open the Explorer window as expected by the user.
        8. View of infected removable media with default Windows settings:
            - <img width="168" height="168" alt="image" src="https://github.com/user-attachments/assets/491933f5-2bde-4c83-9785-6ef03887c07b" />
        9. View of infected removable media with visible hidden files and file extensions:
            - <img width="150" height="150" alt="image" src="https://github.com/user-attachments/assets/89ef444f-7fee-403c-bef3-54a5ced8041b" />
        10. The data theft procedure lists all files stored on the device and copies those with an extension matching a predefined list:
            - File extensions of interest: .pdf, .doc, .docx, .xls, .xlsx, .ppt, .pptx, .pps, .ppsx, .txt
            - If the file is of interest, i.e. if the file extension is on the predefined list, the procedure checks if a file with the same name already has been stolen. The malware has a text file with a list of stolen files, which is stored in the malware directory under a name specified in the embedded configuration.
            - This approach is a little buggy, because if the worm finds two different files with the same name, it will steal only the first one.
            - Anyway, if the file is of interest and is not on the list of stolen files, it will be copied from the USB to a local directory usually named “data” or “udata”, although the name could be different.
        11. If the worm is executed from a _removable media_, the behavior is different.
            - In this case, it will check if the “Thin Client” or the “Main Client” is running on the system. If the system is not infected, it will connect to a remote Crimson Server and try to use a specific “USBW” command to download and execute the “Thin Client” component.
            - Snippet of code used to build USBW request:
                - <img width="442" height="232" alt="image" src="https://github.com/user-attachments/assets/45345e6f-61b8-481f-af56-586b1dc0bc13" />
        12. **Persistence**: \
          1. It checks if the malware directory exists as specified in an embedded configuration and then copies the malware executable inside it. \
          2. It also creates a registry key under “`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`” to execute the worm automatically. 

        13. **USB Worm distribution**:
            - link: https://securelist.com/transparent-tribe-part-1/98127/ (search: "USB Worm distribution")

    - **Pass Logger**: A credential stealer, used for stealing credentials stored in the Chrome, Firefox and Opera browsers.
    - **KeyLogger**: this is simple malware used for recording keystrokes.
    - **Remover**: Not much information regarding this.
        - Transparent Tribe tries to circumvent certain vendors’ security tools by configuring the Server to prevent installation of some of the malware components, specifically the “USB Driver” and the “Pass Logger”, on systems protected with ***Kaspersky products*** and prevent installation of the “Pass Logger” on systems protected by ***ESET***.
        - <img width="883" height="214" alt="image" src="https://github.com/user-attachments/assets/d83f75aa-102f-4ece-9664-2fec86a03dc7" />
    - **File Manager & Auto Download tabs**: The file manager allows the attacker to explore the remote file system, execute programs, download, upload and delete files.
        - <img width="811" height="243" alt="image" src="https://github.com/user-attachments/assets/6f89ea7d-2a58-4d9b-b0f8-420b8bec2072" />
        - The most interesting ones are “USB Drive” and “Delete USB”, used for accessing data stolen by the USB Driver and USB Worm components and the “Auto File Download” feature. This feature opens another window, which can also be accessed via the second last tab. It allows the attacker to configure the bot to search files, filter results and upload multiple files.
        - <img width="392" height="417" alt="image" src="https://github.com/user-attachments/assets/e5522bce-cb96-4676-ba42-f29e4d18e89d" />
    - **Screen and Webcam monitoring tabs**:
        - Screen monitoring tab: \
            <img width="319" height="95" alt="image" src="https://github.com/user-attachments/assets/460f65e1-3ecf-423b-bb71-84a8acc92896" />
        - Webcam monitoring tab: \
            <img width="354" height="99" alt="image" src="https://github.com/user-attachments/assets/05b5a38b-32a1-4ed5-82b6-356fecc0378f" />
        - The other tabs are used for managing the following features:
            - Audio surveillance: The malware uses the NAudio library to interact with the microphone and manage the audio stream. The library is stored server-side and pushed to the victim’s machine using a special command.
            - Send message: The attacker can send messages to victims. The bot will display the messages using a standard message box.
            - Keylogger: Collects keyboard data. The log includes the process name used by the victim, and keystrokes. The attacker can save the data or clear the remote cache.
            - Password Logger: The malware includes a feature to steal browser credentials. The theft is performed by a specific component that enumerates credentials saved in various browsers. For each entry, it saves the website URL, the username and the password.
            - Process manager: The attacker can obtain a list of running processes and terminate these by using a specific button.
            - Command execution: This tab allows the attacker to execute arbitrary commands on the remote machine.
         
### Crimson Server version “B”:

- The other version is quite similar to the previous one. Most noticeably, in this “B” version, the graphical user interface is different.
- <img width="625" height="66" alt="image" src="https://github.com/user-attachments/assets/20fb5331-576c-49f6-88a9-62d8836c559a" />
- “Update USB Worm” is missing from the Update Bot tab, which means that the USB Worm feature is not available in these versions.
- <img width="1056" height="491" alt="image" src="https://github.com/user-attachments/assets/ee505f9e-d19f-4495-bff8-0eacfdd6b32b" />
- This version does not include the check that prevents installation of certain components on systems protected with Kaspersky products, and the Command execution tab is missing. At the same position, we find a different tab, used for saving comments about the infected machine.
- <img width="660" height="195" alt="image" src="https://github.com/user-attachments/assets/580bcc15-d7d0-4eb2-a424-6c807d4d73de" />


## APT Attributes about APT36 related to Sindoor Dropper: New Phishing Campaign

1. Nextron's analysis uncovered a phishing campaign targeting organizations in India, leveraging spear-phishing techniques reminiscent of Operation Sindoor.
2. It is a Linux-focused infection method that relies on weaponized **.desktop** files.
3. This technique has been linked to APT36 (aka Transparent Tribe, Mythic Leopard, G0134) in the past, suggesting the same group may be behind the campaign while also adapting its methods.
4. When opened, these `.desktop` files trigger a heavily obfuscated execution chain built to evade both static and dynamic detection. The chain ultimately delivers a [MeshAgent](https://github.com/Ylianst/MeshAgent) payload, which gives the attacker full remote access to the system. This access includes the ability to monitor activity, move laterally, and potentially exfiltrate data.
5. By combining localized spear-phishing lures with advanced obfuscation techniques, the adversaries increase their chances of bypassing defenses and gaining footholds in sensitive networks.
6. The malicious `.desktop` file is crafted to appear harmless by masquerading as a legitimate document. On the victim’s desktop, it displays an icon resembling a PDF file (image below), luring the user into executing it.
    - <img width="246" height="203" alt="image" src="https://github.com/user-attachments/assets/4b4860e6-a930-4abd-b766-b995d157aa81" />
    - Upon launch, the file opens a benign-looking decoy PDF (image below) to reinforce the illusion of legitimacy.
7. While the user is focused on the opened document, a background process silently runs the obfuscated routines that initiate the deployment chain, ultimately installing the MeshAgent payload. This approach blends social engineering with stealth, hiding malicious activity behind what appears to be a harmless file.
    - <img width="1280" height="821" alt="image" src="https://github.com/user-attachments/assets/328a5393-0a58-4d85-b08b-ff96d00fde20" />
8. By using a `.desktop` file, the attacker can place executable files on the victim’s system without needing elevated privileges (chmod).
9. Infection Chain Overview:
    - The following schema outlines the infection process from the initial .desktop file launch to the final MeshAgent deployment.
       - <img width="1283" height="1060" alt="image" src="https://github.com/user-attachments/assets/46d4c094-4876-4ed7-aa70-447e298e6529" />
10. Process Analysis:
    - The original desktop file downloads the `decoy document`, a `corrupted decryptor`, and an `encrypted downloader`.
        - <img width="2146" height="233" alt="image" src="https://github.com/user-attachments/assets/8098dcfe-a5fd-4b9d-8e6e-b4aee3a87146" />
    - 












Resources:
1. https://www.proofpoint.com/sites/default/files/proofpoint-operation-transparent-tribe-threat-insight-en.pdf
2. https://malpedia.caad.fkie.fraunhofer.de/actor/operation_c-major
3. https://securelist.com/transparent-tribe-part-1/98127/
4. https://github.com/BRANDEFENSE/IoC/blob/main/IoC-YARA-rules-apt36.txt
5. 

Other Resources:
1. https://securelist.com/transparent-tribe-part-2/98233/
2. https://attack.mitre.org/groups/G0134/
3. https://blog.talosintelligence.com/transparent-tribe-infra-and-targeting/
    
    
    



    
