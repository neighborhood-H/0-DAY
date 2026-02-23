# 0-DAY(zero-day)

[![Repo Status](https://img.shields.io/badge/Status-Research-critical.svg)]()
[![Last updated](https://img.shields.io/badge/Last%20update-2025--10--25-lightgrey.svg)]()

---

>## **purpose**  
> This repository is a standard README in the repository that is configured for vulnerability research.  
> Each vulnerability folder simply contains only **Analytic Reports ('report.md ')**, **PoC ('exploit.py ')**, and **Display Video ('video.mp4')**, and environmental deployment (lab, VM, emulation) is omitted from the repository.  


---

## Safety and Responsibility Regulations
- Data in the repository shall be executed only in **isolated experimental environments**.
- It is prohibited from running on public networks or equipment owned by others.
- Make sure to prepare an experimental environment (snapshot generation, external network blocking, etc.) before executing PoC.
- Strictly prohibit the use of abuse purposes.

---

## Current Baseline Repository Structure
```
repository-root/
├── Venders/
│   └── Product/
│        └── IssueName/
│           ├── exploit.py
│           ├── report.md
│           └── video.mp4 
└── README.md
```

> The above structure is an example reflecting the folder and file naming rules currently in use.

---

## File/Folder Rules
- Each vulnerability is organized in a dedicated folder (e.g., `Vendor/Product/IssueName/`).  
- Files to include without fail:
  - `report.md` : Description of vulnerabilities (subject, summary, impact, version to be tested, Root Cause, recommended amendments, references, disclosure logs, etc.). User-supplied text shall be placed in this file. 
  - `exploit.py` : PoC script (default disabled).  
  - `video.mp4` or `demo.webm` : demonstration video (sensitivity information edited).

---

## PoC Rules 
- It does not hardcode operational credentials, internal IP, or secret keys within PoC.
- Auto-executable RCE PoC is not uploaded to public storage. Only reproduction procedures and vulnerable points are disclosed, and execution codes are managed in internal storage or in access-controlled branches.


---

## Repository Usage Flow (Simple)
1. Vulnerability Identification → Folder Creation(`Vendor/Product/Issue`)  
2. Prepare the body of analysis (summary, cause, and recommendation) in `report.md` (including the body file provided by the user)
3. Place PoC in `PoC/` or same folder but remain inactive 
4. After editing the sensitive information, save the demonstration video as `video.mp4`


---

## Appendix — Quick Checklist
- [ ] Check `report.md` for the extent of impact and the inclusion of a sugary fix
- [ ] Remove or edit sensitive information (token, internal IP, etc.) from demo video  
- [ ] Create snapshots and block external networks before the experiment

---      
         
© 2025 neighborhood-H.
