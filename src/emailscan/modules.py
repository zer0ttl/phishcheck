"""DSPy example program."""

import dspy

from .signatures import AssessEvent


class EventAssessor(dspy.Module):  # type: ignore[misc]  # DSPy has no typing marker.
    """Assess one event while preserving DSPy metadata and usage."""

    def __init__(self) -> None:
        """Construct the predictor."""
        super().__init__()
        self.predictor = dspy.Predict(AssessEvent)

    def forward(self, event: str) -> dspy.Prediction:
        """Return the DSPy prediction with its metadata intact.

        Args:
            event: The security event description.

        Returns:
            The three typed judgments and their DSPy metadata.
        """
        return self.predictor(event=event)
