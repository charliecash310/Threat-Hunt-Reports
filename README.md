# Threat-Hunt-Event-Assistance
Threat Hunt Event: Assistance


# 🛡️ Threat Hunt Report – Assistance Incident (October 2025)

**Analyst:** Grisham DelRosario 
**Environment:** Log Analytics Workspace   
**Host Investigated:** `gab-intern-vm`  
**Time Window:** **October 1 – October 15, 2025**

---

# 📌 Scenario

A routine support request should have ended with a reset and reassurance. Instead, the so- called "help" left behind a trail of anomalies that don't add up. 
What was framed as troubleshooting looked more like an audit of the system itself probing, cataloging, leaving subtle traces in its wake. Actions chained together in 
suspicious sequence: first gaining a foothold, then expanding reach, then preparing to linger long after the session ended. And just when the activity should have raised questions, a neat explanation appeared — a story planted in plain sight, designed to justify the very behavior that demanded scrutiny. 
This wasn't remote assistance. It was a misdirection.


---

# 🎯 Objective

Your mission this time is to reconstruct the timeline, connect the scattered remnants of this "support session", and decide what was legitimate, and what was staged. The evidence is here. The question is whether you'll see through the story or believe it.
****
---

# 🏁 Starting Point

Suspicious machine identified:

**`gab-intern-vm`**

Using keyword analysis:
- desk  
- help  
- support  
- tool  

And detection of processes originating in **Downloads**.



---

# 🧠 Scenario Summary

The attacker impersonated support activity, leveraging:

- LOLBins  
- Deception artifacts  
- Short-lived PowerShell commands  
- Staged ZIP archives  
- Outbound network tests  
- Persistence mechanisms  

…to create the illusion of legitimate assistance while performing reconnaissance and staging operations.

---

# 🔍 Key Findings

- Full LOTL tradecraft  
- Deception artifacts to obscure activity  
- Data staging and exfil attempt  
- Persistence artifacts  
- Support narrative planted intentionally  

---

# 📁 Repo Structure

```
/
├── README.md
├── evidence/
├── kql/
├── timeline/
└── report/
```

---

# ✔ End of Report
