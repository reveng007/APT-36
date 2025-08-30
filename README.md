# APT-36

## APT Attributes about APT36

1. APT 36 ( aka: APT 36, APT36, C-Major, COPPER FIELDSTONE, Earth Karkaddan, Green Havildar, Mythic Leopard, ProjectM, Storm-0156, TMP.Lapis, Transparent Tribe )
2. Group targeting Indian Army or related assets in India, as well as activists and civil society in Pakistan. Attribution to a Pakistani connection has been made by TrendMicro and others.
3. It has been active since at least 2013, primarily targeting diplomatic, defense, and research organizations in India and Afghanistan.
4. On feb 11, 2016: 2 attacks a min apart from each other was directed towards at Indian enbassies in both Saudi Arabia and Kazakhstan.
5. Both e-mails were sent from the same originating IP (`5[.]189.170.84`) address ([link - github](https://github.com/BRANDEFENSE/IoC/blob/main/IoC-YARA-rules-apt36.txt#L58)). All Ip addresses can be found from here - [link - github](https://github.com/BRANDEFENSE/IoC/blob/main/IoC-YARA-rules-apt36.txt#L46)
6. The mails were likely via MailGun tool ([link](https://www.proofpoint.com/sites/default/files/proofpoint-operation-transparent-tribe-threat-insight-en.pdf) search: "MailGun").
7. In that particular Incident attachment was a weaponised RTF document utilizing [CVE-2012-0158 (BufferOverflow Vuln)](https://securelist.com/the-curious-case-of-a-cve-2012-0158-exploit/37158/) to drop an embedded, encoded portable exeutable (PE).
8. To decode the embedded PE:
    - the document's shellcode first searches for the `0xBABABABA` marker that, when found, will indicate the beginning positon of the PE. The PE is then decoded using the key `0xCAFEBABE`.
    - A final marker indicates the end of the PE file, which in this case, is the marker `0xBBBBBBBB`.
    
9. Fake Blog post named, "blogspot.com" site (`intribune.blogspot[.]com`) was created by same actor to lure Indian Military to become infected by `Crimson`, `njrat` and others. More Softwares that are used by APT36 can be found [here]()
