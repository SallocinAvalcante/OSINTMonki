from utils.common.config_loader import load_config
from dotenv import load_dotenv
import os

load_dotenv()


class ProviderManager:
    def __init__(self):
        self.config = load_config()

        blockchain_cfg = self.config.get("blockchain", {})

        self.default = blockchain_cfg.get("default_provider", {})
        self.fallback = blockchain_cfg.get("fallback_provider", {})
        self.supported = blockchain_cfg.get("supported_chains", [])
        self.api_keys = blockchain_cfg.get("api_keys", {})

    # -------------------------
    # VALIDAR CHAIN
    # -------------------------
    def is_supported(self, chain: str) -> bool:
        return chain in self.supported

    # -------------------------
    # OBTER PROVIDER PRINCIPAL
    # -------------------------
    def get_default_provider(self, chain: str) -> str:
        return self.default.get(chain)

    # -------------------------
    # OBTER FALLBACK
    # -------------------------
    def get_fallback_provider(self, chain: str) -> str:
        return self.fallback.get(chain)

    # -------------------------
    # RESOLVER API KEY
    # -------------------------
    def get_api_key(self, provider: str) -> str | None:
        key_path = self.api_keys.get(provider)

        if not key_path:
            return None

        # formato: ".env.ETHERSCAN_API_KEY"
        if key_path.startswith(".env."):
            env_key = key_path.replace(".env.", "")
            return os.getenv(env_key)

        return None

    # -------------------------
    # PROVIDER DISPONÍVEL?
    # -------------------------
    def is_provider_available(self, provider: str) -> bool:
        api_key = self.get_api_key(provider)

        # provider que não precisa de API (ex: blockstream)
        if api_key is None:
            return True

        return bool(api_key)

    # -------------------------
    # RESOLVER PROVIDER FINAL
    # -------------------------
    def resolve_provider(self, chain: str) -> str:
        if not self.is_supported(chain):
            raise ValueError(f"Chain não suportada: {chain}")

        primary = self.get_default_provider(chain)

        if self.is_provider_available(primary):
            return primary

        fallback = self.get_fallback_provider(chain)

        if fallback and self.is_provider_available(fallback):
            return fallback

        raise RuntimeError(f"Nenhum provider disponível para {chain}")