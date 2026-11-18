# Cipher Code Components

```mermaid
flowchart BT
    A[CORE<br/>- math implementation<br/>- lattice implementation<br/>- serialization] --> B[PKE<br/> -SIMD FHE];
    A --> C[BINFHE<br/>- binary FHE];
    B --> D[Application<br/>- encrypted data analysis<br/>- privacy-compliant data sharing];
    C --> D;
```

# binFHE

- Boolean arithmetic, comparisons, and aribtrary function evaluation based on DM and CGGI schemes

# core

- underlying implementation providing the base that `binFHE` and `pke` are built off of

# pke

- integer and real-number arithmetic based on BGV, BFV, and CKKS schemes

## Warning

Although the Cipher team has provided various utility functions to make Cipher accessible to
non-cryptographers, it is still necessary for the end-users to carefully consider how they are using the code. Improper
use can result in leaked information.
Use of Cipher in production environments should be reviewed by homomorphic encryption experts.

Additionally, see our [Security Considerations](../static_docs/Security.md) for considerations that should be taken into account
in your work.
