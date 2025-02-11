# Cross-Tenant Lateral Movement in Entra ID - PoC

## Overview
This Proof of Concept (PoC) demonstrates a previously uncovered attack vector in **Entra ID**, where **cross-tenant lateral movement** is possible by leveraging existing functionalities that allow traversal across trust and security boundaries. The research highlights how attackers can exploit these features to **compromise multiple tenants**.

## Key Findings
- Entra ID provides functionality that enables interactions between tenants.
- Trust relationships such as **GDAP, external guest accounts, and enterprise applications** can be abused.
- The unified API structure of Entra ID allows for **automation and recursive execution**, enabling attackers to **script and scale** cross-tenant compromises.

## Purpose
This PoC serves as a demonstration for my talk at **Disobey.fi** to highlight the risks associated with cross-tenant security in Entra ID. By understanding these weaknesses, security professionals can better **detect and mitigate** potential attacks before they become widespread.

## Mitigations & Recommendations
- **Monitor cross-tenant API activity** for suspicious behavior.
- **Restrict external access** to privileged accounts and applications.
- **Audit trust relationships** (GDAP, guest accounts, enterprise apps) regularly.
- **Implement Conditional Access policies** to limit cross-tenant access.

## License
This project is released under the MIT License.

## Disclaimer
This PoC is intended for security research and educational purposes only. The author is not responsible for any misuse or unauthorized activity.

---

🚀 Stay tuned for the talk at **Disobey.fi** where we will dive deeper into these security challenges!
