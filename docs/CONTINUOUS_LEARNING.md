# Controlled Continuous Learning

CyberShield records user-confirmed and false-positive detections into a learning queue. Feedback is **not** allowed to alter the production model immediately. Verified samples are exported, merged into the training corpus, and a candidate model is trained. The candidate must pass the evaluation gate and outperform the current model before promotion.

Unknown malware is not executed by CyberShield. Malware behaviour learning should use labelled telemetry or an isolated disposable analysis environment whose outputs are imported as features. This prevents a malicious sample from compromising the Kali host.

Recommended promotion gates:
- no material regression on the fixed test set
- F1 >= current model
- recall on the security-critical class must not fall
- false-positive rate must remain within the project threshold
- model artifact checksum recorded
- dataset version and training timestamp recorded
