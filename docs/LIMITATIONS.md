# Release limitations

This is an experimental code snapshot. The following source-level findings limit what can be claimed about privacy enforcement and deployment readiness. They have not been resolved by the documentation cleanup.

| Area | Current limitation | Required boundary |
| --- | --- | --- |
| Role assignment | Signup accepts the requested role | Assign roles through a trusted authorization process |
| Token configuration | A default signing-secret fallback exists | Require a configured secret and appropriate token validation |
| Policy retrieval | Missing role matches can use a different retrieved policy | Reject unmatched roles |
| Policy parsing | Patient permissions use prose that the bullet-list parser does not consume | Use an explicit, validated policy schema |
| Mask construction | Empty restricted lists and subword matching need handling | Define behavior and test role-specific boundary cases |
| Query construction | Model-generated filters and projection values lack full validation | Enforce record ownership and a validated inclusive projection independently of the model |
| Sanitization | Generated text may retain or invent sensitive content | Evaluate with synthetic adversarial and ordinary requests |
| Answer assembly | Database values are inserted after sanitization | Validate the final returned fields and response |
| Logging | Signup debug output includes the supplied user object; inference logs contain detailed content | Remove credential logging and minimize retained request/response data |
| Service exposure | Broad CORS settings and detailed error responses | Configure a restricted deployment boundary and non-sensitive errors |

Requests and intermediate responses are sent to the configured OpenAI service. The API also persists interaction data in MongoDB. Use synthetic inputs only while investigating these issues; do not treat model instructions, attention masks, or a JWT alone as a complete access-control system.

No clinical suitability, security certification, regulatory compliance, or guaranteed privacy claim is made by this release.

[Back to PrivAware](../README.md)
