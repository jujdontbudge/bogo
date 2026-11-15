# BOGO has its own relay and sends its own pushes

BOGO does not use Apple Bridge's gateway or relay, even though the approver lives in the Apple Bridge iPhone app and that path already reaches the phone. It runs its own relay at `bogo.eilmer.si` on the same VPS, with its own port, service and state, and nothing shared with Apple Bridge's relay. BOGO on the Mac sends APNs pushes itself with the owner's existing key. The owner ruled out touching any Apple Bridge Mac part. Every decision is signed end to end, so the relay is trusted with nothing and only passes ciphertext along.
