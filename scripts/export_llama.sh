#!/usr/bin/env bash
set -euo pipefail
: "${LLAMA_CHECKPOINT:?Set LLAMA_CHECKPOINT to a permitted Llama 3.2 checkpoint (.pth)}"
: "${LLAMA_PARAMS:?Set LLAMA_PARAMS to params.json}"
OUT="${LLAMA_OUTPUT:-models/llama/cybershield-llama.pte}"
CONFIG="${LLAMA_CONFIG:-models/llama/export_config.yaml}"
mkdir -p "$(dirname "$OUT")"
cat > "$CONFIG" <<EOF
base:
  model_class: llama3_2
  checkpoint: ${LLAMA_CHECKPOINT}
  params: ${LLAMA_PARAMS}
  metadata: '{"get_bos_id":128000,"get_eos_ids":[128009,128001]}'
model:
  use_kv_cache: true
  use_sdpa_with_kv_cache: true
quantization:
  qmode: 8da4w
EOF
python -m executorch.extension.llm.export.export_llm --config "$CONFIG"
echo "Export completed. Verify the generated .pte and run it with an ExecuTorch LLM runner on the target."
