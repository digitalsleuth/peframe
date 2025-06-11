  ------------------------------
  peframe (peframe-ds on pypi)
  ------------------------------

peframe is an open source tool to perform static analysis on [Portable
Executable](http://en.wikipedia.org/wiki/Portable_Executable) malware
and generic suspicious files. It can help malware researchers to detect
packers, xor, digital signatures, mutex, anti-debug, anti-virtual
machine, suspicious sections and functions, macros and much more.

Prerequisites

The following prerequisites are necessary before you can install and use
peframe.

``` {.}
python >= 3.6.6
python3-pip
python3-dev
build-essential
libmagic-dev
libssl-dev
swig
```

**Install Methods**

**Manual Download and Install**

``` {.}
sudo apt install git
git clone https://github.com/digitalsleuth/peframe.git
cd peframe
sudo python3 -m pip install .
```

**One-step Install**

``` {.}
sudo python3 -m pip install git+https://github.com/digitalsleuth/peframe.git
```

OR

``` {.}
sudo python3 -m pip install peframe-ds
```

Usage
=====

peframe -h

``` {.}
peframe filename            Short output analysis
peframe -i filename         Interactive mode
peframe -j filename         Full output analysis JSON format
peframe -x STRING filename  Search xored string
peframe -s filename         Strings output
```

**Note**

You can edit \"config-peframe.json\" file in \"config\" folder to
configure virustotal API key. After installation you can use \"peframe
-h\" to find api\_config path.

**How it works**

**MS Office (macro) document analysis with peframe 6.0.1**

[![image](https://asciinema.org/a/mbLd5dChz9iI8eOY15fC2423X.svg)](https://asciinema.org/a/mbLd5dChz9iI8eOY15fC2423X?autoplay=1)

**PE file analysis with peframe 6.0.1**

[![image](https://asciinema.org/a/P6ANqp0bHV0nFsuJDuqD7WQD7.svg)](https://asciinema.org/a/P6ANqp0bHV0nFsuJDuqD7WQD7?autoplay=1)

Talk about\...
==============

> -   [A Longitudinal Analysis of Brazilian Financial
>     Malware](https://www.lasca.ic.unicamp.br/paulo/papers/2020-TOPS-marcus.botacin-brazilian.bankers.pdf)
>     *(Federal University of Paraná, Marcus Botacin, Hojjat Aghakhani,
>     Stefano Ortolani, Christopher Kruegel, Giovanni Vigna, Daniela
>     Oliveira, Paulo Lício de Geus, André Grégio 2020)*
> -   [Building a smart and automated tool for packed malware detections
>     using machine
>     learning](https://dial.uclouvain.be/memoire/ucl/en/object/thesis%3A25193)
>     *(Ecole polytechnique de Louvain, Université catholique de
>     Louvain, Minet, Jeremy; Roussieau, Julian 2020)*
> -   [Revealing Packed
>     Malware](https://www.researchgate.net/publication/220496734_Revealing_Packed_Malware)
>     *(Department of Electrical and Computer Engineering, Nirwan
>     Ansari, New Jersey Institute of Technology - NJIT)*
> -   [Critical Infrastructures Security: Improving Defense Against
>     Novel Malware and Advanced Persistent Threats
>     (PDF)](https://iris.uniroma1.it/retrieve/handle/11573/1362189/1359415/Tesi_dottorato_Laurenza.pdf)
>     *(Department of Computer, Control, and Management Engineering
>     Antonio Ruberti, Sapienza -- University of Rome)*
> -   [Anatomy on Malware Distribution Networks
>     (PDF)](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=9057639)
>     *(Department of Intelligent Systems Engineering, Cheju Halla
>     University, Jeju 63092, South Korea)*
> -   [Intel Owl
>     0.4.0](https://github.com/certego/IntelOwl/releases/tag/0.4.0)
>     *(certego platform - threat intelligence data about a file, an IP
>     or a domain)*
> -   [Integration of Static and Dynamic Analysis for Malware Family
>     Classification with Composite Neural
>     Network](https://www.groundai.com/project/integration-of-static-and-dynamic-analysis-for-malware-family-classification-with-composite-neural-network/)
>     *(Yao Saint, Yen Institute of Information Science, Academia
>     Sinica, Taiwan)*
> -   [Machine Learning Aided Static Malware Analysis: A Survey and
>     Tutorial](https://www.researchgate.net/publication/324702503_Machine_Learning_Aided_Static_Malware_Analysis_A_Survey_and_Tutorial)
>     *(Sergii Banin, Andrii Shalaginov, Ali Dehghantanha, Katrin
>     Franke, Norway)*
> -   [Multinomial malware classification, research of the Department of
>     Information Security and Communication Technology
>     (NTNU)](https://www.sciencedirect.com/science/article/pii/S1742287618301956)
>     *(Sergii Banin and Geir Olav Dyrkolbotn, Norway)*
> -   [SANS DFIR Poster
>     2016](http://digital-forensics.sans.org/media/Poster_SIFT_REMnux_2016_FINAL.pdf)
>     *(PEframe was listed in the REMnux toolkits)*
> -   [Tools for Analyzing Static Properties of Suspicious Files on
>     Windows](http://digital-forensics.sans.org/blog/2014/03/04/tools-for-analyzing-static-properties-of-suspicious-files-on-windows)
>     *(SANS Digital Forensics and Incident Response, Lenny Zeltser).*
> -   [Automated Static and Dynamic Analysis of
>     Malware](http://www.cyberdefensemagazine.com/newsletters/august-2013/index.html#p=26)
>     *(Cyber Defence Magazine, Andrew Browne, Director Malware Lab
>     Lavasoft).*
> -   [Suspicious File Analysis with
>     PEframe](https://eforensicsmag.com/download/malware-analysis/)
>     *(eForensics Magazine, Chintan Gurjar)*
> -   [CERT FR Security
>     Bulletin](https://www.cert.ssi.gouv.fr/actualite/CERTFR-2014-ACT-030/)
>     *(PEframe was mentioned in the security bulletin
>     CERTFR-2014-ACT-030)*
> -   [Infosec CERT-PA Malware
>     Analysis](https://infosec.cert-pa.it/analyze/submission.html)
>     *(PEframe is used in the malware analysis engine of Infosec
>     project)*

Other
=====

This version of peframe is currently maintained by [Corey
Forman](https://github.com/digitalsleuth) and includes the recent and
relevant pull requests from the original repo.

The originator of this software is [Gianni \'guelfoweb\'
Amato](http://guelfoweb.com), who can be contacted at
<guelfoweb@gmail.com> or twitter
[\@guelfoweb](http://twitter.com/guelfoweb). Suggestions and criticism
are welcome.
