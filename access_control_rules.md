
# Access Control Rules for Privacy Preserving HealthCare System

## Role: Admin

**Allowed Fields**:
- id
- patientname
- age
- gender
- mobilenumber
- city
- state
- doctor
- treatment
- disease
- emergency_contact
- insurance_provider

**Restricted Fields**:
- ssn
- allergies
- family_medical_history
- mental_health_status
- height
- weight
- blood_type
<!-- - s
- sn
- social security number -->

---

## Role: Doctor

**Allowed Fields**:
- patientname
- age
- gender
- disease
- chronic_conditions
- allergies
- blood_type
- height
- weight
- treatment
- vaccination_status
- family_medical_history
- mental_health_status

**Restricted Fields**:
- id
- ssn
- emergency_contact
- insurance_provider
- mobilenumber
- city
- state

---

## Role: Patient

**Allowed Fields**: All fields related to their own data  
**Restricted Fields**: None
