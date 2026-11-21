"""Decision criteria for security event assessment."""

import dspy
from dspy.experimental import Choice, Noul, Score

Investigate = Noul[
    (True, "Evidence warrants investigation"),
    (False, "Insufficient evidence of suspicious activity"),
]
Risk = Score["Benign", "Low risk", "Moderate risk", "High risk", "Critical risk"]
Category = Choice[
    ("credential_attack", "Evidence of brute force or password spraying"),
    ("malware", "Evidence of malicious software activity"),
    ("lateral_movement", "Evidence of suspicious internal movement"),
    ("benign", "Normal authorized activity"),
]


class AssessEvent(dspy.Signature):  # type: ignore[misc]  # DSPy has no typing marker.
    """Assess the activity described in a security event."""

    event: str = dspy.InputField(desc="The observed security event.")
    investigate: Investigate = dspy.OutputField(  # type: ignore[valid-type]
        desc="Does the observed activity warrant investigation?"
    )
    risk: Risk = dspy.OutputField(  # type: ignore[valid-type]
        desc="How severe is the security risk indicated by this event?"
    )
    category: Category = dspy.OutputField(  # type: ignore[valid-type]
        desc="Which category best describes the observed activity?"
    )
