# Llama + ExecuTorch

CyberShield treats Llama as the explanation/advisory layer. Detector verdicts remain independent and grounded in structured evidence.

Official workflow:
1. Obtain a permitted Llama 3.2 checkpoint and tokenizer.
2. Install the current ExecuTorch toolchain in a dedicated environment.
3. Set `LLAMA_CHECKPOINT` and `LLAMA_PARAMS`.
4. Run `scripts/export_llama.sh` to create the `.pte`.
5. Build/configure an ExecuTorch LLM runner for the target platform.
6. Set `CYBERSHIELD_LLAMA_RUNNER` to that local runner executable.
7. Verify generation from the `.pte` with the internet disabled.

For Arm CPU targets, XNNPACK is the relevant ExecuTorch CPU backend. The exact runner/build commands are intentionally kept version-specific; record the tested ExecuTorch version in the final report.
