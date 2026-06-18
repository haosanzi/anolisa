"""Model manager – lazy loading, caching, and device selection.

Models are downloaded separately via ``download_model`` (e.g. ``scan-prompt warmup``)
and loaded on demand by ``load_model``.  Supports both sequence-classification
models (L2 PromptGuard) and causal-LM models (L4 multi-intent TurnGate).

ModelScope model IDs for Llama Prompt Guard 2:
    22M fast model : ``LLM-Research/Llama-Prompt-Guard-2-22M``
    86M accurate   : ``LLM-Research/Llama-Prompt-Guard-2-86M``
"""

import contextlib
import logging
import os
import threading
from pathlib import Path
from typing import Any, TYPE_CHECKING

from agent_sec_cli.prompt_scanner.exceptions import ModelLoadError
from agent_sec_cli.prompt_scanner.result import ThreatType
from pydantic import BaseModel

if TYPE_CHECKING:
    import torch

log = logging.getLogger(__name__)


class ClassifierResult(BaseModel):
    """Unified result returned by any ML classifier wrapper.

    ``threat_type`` carries the model-specific label already translated to
    a domain ``ThreatType``.  This translation is the responsibility of the
    classifier wrapper (e.g. ``PromptGuardClassifier``) that understands
    the model's label schema; callers such as ``MLClassifier`` should use
    this field directly rather than re-mapping ``label`` themselves.
    """

    label: str  # Raw model label, e.g. "JAILBREAK", "BENIGN"
    confidence: float  # Probability of the predicted label (0.0–1.0)
    probabilities: dict[str, float]  # Full label -> prob mapping
    threat_type: ThreatType  # Domain type translated by the classifier wrapper


class ModelManager:
    """Centralized model lifecycle management.

    Responsibilities:
    - Lazy-load models on first use.
    - Cache loaded (model, tokenizer) pairs in memory.
    - Auto-detect best available device (CPU / CUDA / MPS).
    - Provide ``clear_cache()`` for memory reclamation.

    Each cache entry is a ``(model, tokenizer)`` tuple so callers
    never need to manage the tokenizer separately.
    """

    _DEFAULT_CACHE_DIR = "~/.cache/prompt_scanner/models"

    def __init__(self, cache_dir: str | None = None, device: str | None = None) -> None:
        self._cache_dir = cache_dir or self._DEFAULT_CACHE_DIR
        # Defer device detection until first inference to avoid importing torch
        # at module load time (which would slow down non-ML subcommands like code-scan).
        self._device_cached: str | None = device
        # cache: model_name -> (model, tokenizer)
        self._loaded_models: dict[str, tuple[object, object]] = {}
        self._load_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def download_model(self, model_name: str) -> str:
        """Download a model via ModelScope and return the local path.

        Progress output (tqdm bars) is **visible** — intended for the
        ``warmup`` CLI command where users expect to see download progress.

        Idempotent: if the model is already cached locally, ModelScope
        returns immediately from the file-system cache.

        Args:
            model_name: ModelScope model ID, e.g.
                ``"LLM-Research/Llama-Prompt-Guard-2-86M"``.

        Returns:
            Absolute path to the local model directory.

        Raises:
            ModelLoadError: if the download fails.
        """
        from modelscope import snapshot_download

        cache_dir = Path(self._cache_dir).expanduser()
        try:
            return snapshot_download(model_name, cache_dir=str(cache_dir))
        except Exception as exc:
            raise ModelLoadError(
                f"ModelScope download failed for '{model_name}': {exc}"
            ) from exc

    def load_model(
        self, model_name: str, model_type: str = "classification"
    ) -> tuple[object, object]:
        """Return a cached ``(model, tokenizer)`` pair, loading on demand.

        Thread-safe: concurrent calls for the same model will block on the
        lock and reuse the result of the first successful load.

        Args:
            model_name: Model identifier (ModelScope ID or local relative path).
            model_type: ``"classification"`` for SequenceClassification models
                (e.g. PromptGuard), ``"causal_lm"`` for CausalLM generative
                models (e.g. TurnGate multi-intent).

        Returns:
            ``(model, tokenizer)`` tuple ready for inference.

        Raises:
            agent_sec_cli.prompt_scanner.exceptions.ModelLoadError: if the
                model cannot be loaded (missing deps, not downloaded, etc.).
        """
        # Fast path: model already loaded (no lock needed for dict reads under GIL).
        if model_name in self._loaded_models:
            return self._loaded_models[model_name]

        with self._load_lock:
            # Double-check after acquiring the lock.
            if model_name in self._loaded_models:
                return self._loaded_models[model_name]
            pair = self._do_load(model_name, model_type)
            self._loaded_models[model_name] = pair
            return pair

    def get_model(self, model_name: str) -> tuple[object, object] | None:
        """Return the cached ``(model, tokenizer)`` pair if already loaded."""
        return self._loaded_models.get(model_name)

    def clear_cache(self) -> None:
        """Release all loaded models from memory."""
        self._loaded_models.clear()

    @property
    def device(self) -> str:
        """The compute device used for inference (``cpu``, ``cuda``, ``mps``).

        Lazily detected on first access to avoid importing torch at module
        load time when non-ML subcommands (e.g. code-scan) are invoked.
        """
        if self._device_cached is None:
            self._device_cached = self.detect_device()
        return self._device_cached

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def detect_device() -> str:
        """Auto-detect the best available compute device.

        Priority: CUDA > MPS (Apple Silicon) > CPU.
        """
        import torch  # lazy import: only needed when actually running ML inference

        if torch.cuda.is_available():
            return "cuda"
        if torch.backends.mps.is_available():
            return "mps"
        return "cpu"

    # ------------------------------------------------------------------

    def _resolve_local_model_path(self, model_name: str) -> str:
        """Return the local cache path for *model_name* without triggering a download.

        Raises:
            ModelLoadError: if the model has not been downloaded yet, with a
                user-friendly message pointing to ``scan-prompt warmup``.
        """
        cache_dir = Path(self._cache_dir).expanduser()
        candidate = cache_dir / Path(model_name)

        if candidate.is_dir() and (candidate / "config.json").exists():
            return str(candidate)

        raise ModelLoadError(
            f"Model '{model_name}' is not available locally.\n"
            "Please run the following command to download it first:\n"
            "  agent-sec-cli scan-prompt warmup"
        )

    # ------------------------------------------------------------------

    def _do_load(self, model_name: str, model_type: str) -> tuple[object, object]:
        """Load a model+tokenizer from the local cache (no download).

        Args:
            model_name: Relative path under cache dir.
            model_type: ``"classification"`` or ``"causal_lm"``.

        Raises:
            ModelLoadError: if the model is not on disk or fails to load.
        """
        import torch
        from transformers import AutoTokenizer

        local_model_path = self._resolve_local_model_path(model_name)

        log.info(
            "Loading model '%s' (type=%s) from '%s' onto device '%s'.",
            model_name,
            model_type,
            local_model_path,
            self.device,
        )

        tf_logger = logging.getLogger("transformers")
        saved_level = tf_logger.level
        try:
            if os.environ.get("AGENT_SEC_DEBUG") != "1":
                tf_logger.setLevel(logging.ERROR)
            with open(os.devnull, "w") as _devnull, contextlib.redirect_stdout(
                _devnull
            ), contextlib.redirect_stderr(_devnull):
                tokenizer = AutoTokenizer.from_pretrained(local_model_path)
                model = self._load_model_by_type(
                    local_model_path, model_type, torch
                )
        except ModelLoadError:
            raise
        except Exception as exc:
            raise ModelLoadError(
                f"Failed to load model from '{local_model_path}': {exc}"
            ) from exc
        finally:
            tf_logger.setLevel(saved_level)

        model.to(torch.device(self.device))
        model.eval()
        log.info("Model '%s' loaded successfully.", model_name)
        return model, tokenizer

    @staticmethod
    def _load_model_by_type(
        local_model_path: str, model_type: str, torch: Any
    ) -> Any:
        """Instantiate the correct Auto model class based on *model_type*."""
        if model_type == "causal_lm":
            from transformers import AutoModelForCausalLM

            device = (
                "cuda" if torch.cuda.is_available()
                else "mps" if torch.backends.mps.is_available()
                else "cpu"
            )
            dtype = torch.float32 if device == "cpu" else torch.float16
            return AutoModelForCausalLM.from_pretrained(
                local_model_path,
                torch_dtype=dtype,
                low_cpu_mem_usage=True,
            )

        # Default: classification
        from transformers import AutoModelForSequenceClassification

        return AutoModelForSequenceClassification.from_pretrained(
            local_model_path
        )
