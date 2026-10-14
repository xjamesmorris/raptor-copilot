"""Provider-neutral LLM accounting and route-policy primitives.

The legacy LLM surfaces expose numeric ``cost`` fields. Those fields stay
numeric for compatibility, but a number alone cannot say whether it came from
an invoice, catalog arithmetic, an operator rate, a CLI estimate, or no usable
USD signal at all. This module carries that missing provenance without
depending on provider SDKs or configuration machinery.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Iterable, Literal


MODEL_COST_CATALOG_VERSION = "2026-08-15"


class CostBasis(str, Enum):
    """Origin and authority class of a per-attempt cost observation."""

    PROVIDER_BILLED = "provider_billed"
    CATALOG_PRICED = "catalog_priced"
    CONFIGURED_RATE = "configured_rate"
    CLI_REPORTED = "cli_reported"
    SUBSCRIPTION = "subscription"
    UNKNOWN = "unknown"


class AccountingMode(str, Enum):
    """Provider capability for USD accounting."""

    AUTHORITATIVE = "authoritative"
    SUBSCRIPTION = "subscription"
    UNKNOWN = "unknown"


class UsdBudgetContract(str, Enum):
    """Strength requested from a USD budget."""

    ADVISORY = "advisory"
    AUTHORITATIVE_REQUIRED = "authoritative_required"
    HARD_LIMIT_REQUIRED = "hard_limit_required"


class ModelKeyAggregation(str, Enum):
    """Whether model-name-only aggregation is safe for a route."""

    LEGACY_MODEL_NAME = "legacy_model_name"
    REFUSE = "refuse"


_LEGACY_MODEL_KEY_PROVIDERS = frozenset({
    "anthropic",
    "bedrock",
    "claudecode",
    "claudecode-resumable",
    "claude-code",
    "claude-code-resumable",
    "claude_code",
    "claude_code_resumable",
    "gemini",
    "mistral",
    "ollama",
    "openai",
})


class LLMPolicyError(RuntimeError):
    """Base class for explicit model/accounting policy refusals."""


class LLMAccountingUnavailableError(LLMPolicyError):
    """A requested authoritative accounting contract cannot be satisfied."""

    def __init__(
        self,
        *args: Any,
        accounting: "AccountingSummary | None" = None,
        messages: list[Any] | None = None,
        tool_calls_made: int = 0,
    ) -> None:
        super().__init__(*args)
        self.accounting = accounting or AccountingSummary()
        self.messages = list(messages) if messages else []
        self.tool_calls_made = tool_calls_made


class LLMHardLimitUnsupportedError(LLMAccountingUnavailableError):
    """No current provider can enforce a preemptive hard USD limit."""


class PinnedRouteViolation(LLMPolicyError):
    """The effective model route drifted from its immutable pin."""


class ScorecardAggregationRefused(LLMPolicyError):
    """A model-only scorecard key cannot safely represent this route."""


class AttemptSettlementError(RuntimeError):
    """An accounting attempt was settled more than once or not at all."""


def _clean_nonempty(value: str, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field_name} must be non-empty")
    return cleaned


def _cost_amount(value: float, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{field_name} must be a finite non-negative number")
    amount = float(value)
    if not math.isfinite(amount) or amount < 0:
        raise ValueError(f"{field_name} must be a finite non-negative number")
    return amount


@dataclass(frozen=True)
class RouteIdentity:
    """Canonical non-secret routing identity."""

    provider: str
    model: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "provider",
            _clean_nonempty(self.provider, "provider").lower(),
        )
        object.__setattr__(
            self, "model", _clean_nonempty(self.model, "model"),
        )

    def as_dict(self) -> dict[str, str]:
        return {"provider": self.provider, "model": self.model}


@dataclass(frozen=True, repr=False)
class PinnedRouteSnapshot:
    """Immutable route fields copied from a mutable ModelConfig.

    The repr deliberately omits endpoint/profile values. They are compared for
    drift but must not leak through policy errors or logs.
    """

    provider: str
    model: str
    api_base: str | None = None
    bedrock_api: str = "mantle"
    aws_profile: str | None = None
    aws_region: str | None = None
    enabled: bool = True

    def __post_init__(self) -> None:
        route = RouteIdentity(self.provider, self.model)
        object.__setattr__(self, "provider", route.provider)
        object.__setattr__(self, "model", route.model)

    @classmethod
    def from_model_config(cls, config: Any) -> "PinnedRouteSnapshot":
        return cls(
            provider=getattr(config, "provider", ""),
            model=getattr(config, "model_name", ""),
            api_base=getattr(config, "api_base", None),
            bedrock_api=getattr(config, "bedrock_api", "mantle") or "mantle",
            aws_profile=getattr(config, "aws_profile", None),
            aws_region=getattr(config, "aws_region", None),
            enabled=bool(getattr(config, "enabled", True)),
        )

    def __repr__(self) -> str:
        return (
            "PinnedRouteSnapshot("
            f"provider={self.provider!r}, model={self.model!r}, "
            f"api_base_pinned={self.api_base is not None}, "
            f"bedrock_api={self.bedrock_api!r}, "
            f"aws_profile_pinned={self.aws_profile is not None}, "
            f"aws_region_pinned={self.aws_region is not None}, "
            f"enabled={self.enabled})"
        )


@dataclass(frozen=True)
class TrustedUsdRoute:
    """Operator trust declaration for one exact route and estimated basis."""

    provider: str
    model: str
    basis: CostBasis

    def __post_init__(self) -> None:
        route = RouteIdentity(self.provider, self.model)
        object.__setattr__(self, "provider", route.provider)
        object.__setattr__(self, "model", route.model)
        try:
            basis = CostBasis(self.basis)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid trusted cost basis: {self.basis!r}") from exc
        if basis not in (
            CostBasis.CATALOG_PRICED,
            CostBasis.CONFIGURED_RATE,
        ):
            raise ValueError(
                "trusted USD routes may declare only catalog_priced "
                "or configured_rate bases"
            )
        object.__setattr__(self, "basis", basis)

    @property
    def route(self) -> RouteIdentity:
        return RouteIdentity(self.provider, self.model)

    def as_dict(self) -> dict[str, str]:
        return {
            "provider": self.provider,
            "model": self.model,
            "basis": self.basis.value,
        }


@dataclass(frozen=True)
class AccountingCapability:
    """Static provider capability used before a fresh dispatch."""

    mode: AccountingMode = AccountingMode.UNKNOWN
    hard_limit_supported: bool = False
    model_key_aggregation: ModelKeyAggregation = ModelKeyAggregation.REFUSE

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", AccountingMode(self.mode))
        object.__setattr__(
            self,
            "model_key_aggregation",
            ModelKeyAggregation(self.model_key_aggregation),
        )
        if not isinstance(self.hard_limit_supported, bool):
            raise TypeError("hard_limit_supported must be bool")


@dataclass(frozen=True)
class CostObservation:
    """One attempt's USD evidence, separated from legacy numeric cost."""

    basis: CostBasis
    provider_billed_usd: float | None = None
    estimated_usd: float | None = None
    catalog_version: str | None = None
    route: RouteIdentity | None = None

    def __post_init__(self) -> None:
        basis = CostBasis(self.basis)
        object.__setattr__(self, "basis", basis)
        if self.provider_billed_usd is not None:
            object.__setattr__(
                self,
                "provider_billed_usd",
                _cost_amount(
                    self.provider_billed_usd, "provider_billed_usd",
                ),
            )
        if self.estimated_usd is not None:
            object.__setattr__(
                self,
                "estimated_usd",
                _cost_amount(self.estimated_usd, "estimated_usd"),
            )
        if self.catalog_version is not None:
            object.__setattr__(
                self,
                "catalog_version",
                _clean_nonempty(self.catalog_version, "catalog_version"),
            )
        if self.route is not None and not isinstance(
            self.route, RouteIdentity,
        ):
            raise TypeError("route must be RouteIdentity or None")

        if basis is CostBasis.PROVIDER_BILLED:
            if self.provider_billed_usd is None:
                raise ValueError(
                    "provider_billed requires provider_billed_usd",
                )
            if self.estimated_usd is not None:
                raise ValueError(
                    "provider_billed cannot also carry estimated_usd",
                )
        elif basis in (
            CostBasis.CATALOG_PRICED,
            CostBasis.CONFIGURED_RATE,
            CostBasis.CLI_REPORTED,
        ):
            if self.estimated_usd is None:
                raise ValueError(f"{basis.value} requires estimated_usd")
            if self.provider_billed_usd is not None:
                raise ValueError(
                    f"{basis.value} cannot carry provider_billed_usd",
                )
        else:
            if (
                self.provider_billed_usd is not None
                or self.estimated_usd is not None
            ):
                raise ValueError(
                    f"{basis.value} cannot carry a USD amount",
                )
        if (
            basis is not CostBasis.CATALOG_PRICED
            and self.catalog_version is not None
        ):
            raise ValueError(
                "catalog_version is valid only for catalog_priced",
            )

    @classmethod
    def provider_billed(
        cls,
        amount: float,
        *,
        route: RouteIdentity | None = None,
    ) -> "CostObservation":
        return cls(
            basis=CostBasis.PROVIDER_BILLED,
            provider_billed_usd=amount,
            route=route,
        )

    @classmethod
    def catalog_priced(
        cls,
        amount: float,
        *,
        route: RouteIdentity | None = None,
        catalog_version: str = MODEL_COST_CATALOG_VERSION,
    ) -> "CostObservation":
        return cls(
            basis=CostBasis.CATALOG_PRICED,
            estimated_usd=amount,
            catalog_version=catalog_version,
            route=route,
        )

    @classmethod
    def configured_rate(
        cls,
        amount: float,
        *,
        route: RouteIdentity | None = None,
    ) -> "CostObservation":
        return cls(
            basis=CostBasis.CONFIGURED_RATE,
            estimated_usd=amount,
            route=route,
        )

    @classmethod
    def cli_reported(
        cls,
        amount: float,
        *,
        route: RouteIdentity | None = None,
    ) -> "CostObservation":
        return cls(
            basis=CostBasis.CLI_REPORTED,
            estimated_usd=amount,
            route=route,
        )

    @classmethod
    def subscription(
        cls,
        *,
        route: RouteIdentity | None = None,
    ) -> "CostObservation":
        return cls(basis=CostBasis.SUBSCRIPTION, route=route)

    @classmethod
    def unknown(
        cls,
        *,
        route: RouteIdentity | None = None,
    ) -> "CostObservation":
        return cls(basis=CostBasis.UNKNOWN, route=route)

    @property
    def legacy_cost_usd(self) -> float:
        """Numeric compatibility value used by existing callers."""
        if self.provider_billed_usd is not None:
            return self.provider_billed_usd
        if self.estimated_usd is not None:
            return self.estimated_usd
        return 0.0

    @property
    def has_numeric_usd(self) -> bool:
        return (
            self.provider_billed_usd is not None
            or self.estimated_usd is not None
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "basis": self.basis.value,
            "provider_billed_usd": self.provider_billed_usd,
            "estimated_usd": self.estimated_usd,
            "catalog_version": self.catalog_version,
            "route": self.route.as_dict() if self.route else None,
        }


@dataclass(frozen=True)
class AccountingSummary:
    """Immutable aggregate of attempt observations."""

    provider_billed_usd: float = 0.0
    catalog_priced_usd: float = 0.0
    configured_rate_usd: float = 0.0
    cli_reported_usd: float = 0.0
    provider_billed_calls: int = 0
    catalog_priced_calls: int = 0
    configured_rate_calls: int = 0
    cli_reported_calls: int = 0
    subscription_calls: int = 0
    unknown_calls: int = 0
    unknown_failed_attempts: int = 0
    retained_reservation_estimate_usd: float = 0.0
    exposure_unresolved: bool = False
    usd_total_complete: bool = True
    authoritative_remaining_usd: float | None = None

    def add(self, observation: CostObservation) -> "AccountingSummary":
        if not isinstance(observation, CostObservation):
            raise TypeError("observation must be CostObservation")
        changes: dict[str, Any] = {}
        if observation.basis is CostBasis.PROVIDER_BILLED:
            changes = {
                "provider_billed_usd": (
                    self.provider_billed_usd
                    + float(observation.provider_billed_usd or 0.0)
                ),
                "provider_billed_calls": self.provider_billed_calls + 1,
            }
        elif observation.basis is CostBasis.CATALOG_PRICED:
            changes = {
                "catalog_priced_usd": (
                    self.catalog_priced_usd
                    + float(observation.estimated_usd or 0.0)
                ),
                "catalog_priced_calls": self.catalog_priced_calls + 1,
            }
        elif observation.basis is CostBasis.CONFIGURED_RATE:
            changes = {
                "configured_rate_usd": (
                    self.configured_rate_usd
                    + float(observation.estimated_usd or 0.0)
                ),
                "configured_rate_calls": self.configured_rate_calls + 1,
            }
        elif observation.basis is CostBasis.CLI_REPORTED:
            changes = {
                "cli_reported_usd": (
                    self.cli_reported_usd
                    + float(observation.estimated_usd or 0.0)
                ),
                "cli_reported_calls": self.cli_reported_calls + 1,
            }
        elif observation.basis is CostBasis.SUBSCRIPTION:
            changes = {
                "subscription_calls": self.subscription_calls + 1,
                "usd_total_complete": False,
                "authoritative_remaining_usd": None,
            }
        else:
            changes = {
                "unknown_calls": self.unknown_calls + 1,
                "usd_total_complete": False,
                "authoritative_remaining_usd": None,
            }
        return replace(self, **changes)

    def add_unknown_failure(
        self,
        *,
        retained_reservation_estimate_usd: float = 0.0,
    ) -> "AccountingSummary":
        retained = _cost_amount(
            retained_reservation_estimate_usd,
            "retained_reservation_estimate_usd",
        )
        return replace(
            self,
            unknown_failed_attempts=self.unknown_failed_attempts + 1,
            retained_reservation_estimate_usd=(
                self.retained_reservation_estimate_usd + retained
            ),
            exposure_unresolved=True,
            usd_total_complete=False,
            authoritative_remaining_usd=None,
        )

    def with_authoritative_remaining(
        self, amount: float | None,
    ) -> "AccountingSummary":
        if amount is None:
            return replace(self, authoritative_remaining_usd=None)
        return replace(
            self,
            authoritative_remaining_usd=_cost_amount(
                amount, "authoritative_remaining_usd",
            ),
        )

    def merge(self, other: "AccountingSummary") -> "AccountingSummary":
        if not isinstance(other, AccountingSummary):
            raise TypeError("other must be AccountingSummary")
        remaining: float | None
        if (
            self.authoritative_remaining_usd is None
            or other.authoritative_remaining_usd is None
        ):
            remaining = None
        else:
            remaining = min(
                self.authoritative_remaining_usd,
                other.authoritative_remaining_usd,
            )
        return AccountingSummary(
            provider_billed_usd=(
                self.provider_billed_usd + other.provider_billed_usd
            ),
            catalog_priced_usd=(
                self.catalog_priced_usd + other.catalog_priced_usd
            ),
            configured_rate_usd=(
                self.configured_rate_usd + other.configured_rate_usd
            ),
            cli_reported_usd=(
                self.cli_reported_usd + other.cli_reported_usd
            ),
            provider_billed_calls=(
                self.provider_billed_calls + other.provider_billed_calls
            ),
            catalog_priced_calls=(
                self.catalog_priced_calls + other.catalog_priced_calls
            ),
            configured_rate_calls=(
                self.configured_rate_calls + other.configured_rate_calls
            ),
            cli_reported_calls=(
                self.cli_reported_calls + other.cli_reported_calls
            ),
            subscription_calls=(
                self.subscription_calls + other.subscription_calls
            ),
            unknown_calls=self.unknown_calls + other.unknown_calls,
            unknown_failed_attempts=(
                self.unknown_failed_attempts
                + other.unknown_failed_attempts
            ),
            retained_reservation_estimate_usd=(
                self.retained_reservation_estimate_usd
                + other.retained_reservation_estimate_usd
            ),
            exposure_unresolved=(
                self.exposure_unresolved or other.exposure_unresolved
            ),
            usd_total_complete=(
                self.usd_total_complete and other.usd_total_complete
            ),
            authoritative_remaining_usd=remaining,
        )

    @property
    def estimated_usd(self) -> float:
        return (
            self.catalog_priced_usd
            + self.configured_rate_usd
            + self.cli_reported_usd
        )

    @property
    def legacy_total_cost(self) -> float:
        return self.provider_billed_usd + self.estimated_usd

    @property
    def calls(self) -> int:
        return (
            self.provider_billed_calls
            + self.catalog_priced_calls
            + self.configured_rate_calls
            + self.cli_reported_calls
            + self.subscription_calls
            + self.unknown_calls
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider_billed_usd": self.provider_billed_usd,
            "catalog_priced_usd": self.catalog_priced_usd,
            "configured_rate_usd": self.configured_rate_usd,
            "cli_reported_usd": self.cli_reported_usd,
            "estimated_usd": self.estimated_usd,
            "provider_billed_calls": self.provider_billed_calls,
            "catalog_priced_calls": self.catalog_priced_calls,
            "configured_rate_calls": self.configured_rate_calls,
            "cli_reported_calls": self.cli_reported_calls,
            "subscription_calls": self.subscription_calls,
            "unknown_calls": self.unknown_calls,
            "unknown_failed_attempts": self.unknown_failed_attempts,
            "retained_reservation_estimate_usd": (
                self.retained_reservation_estimate_usd
            ),
            "exposure_unresolved": self.exposure_unresolved,
            "usd_total_complete": self.usd_total_complete,
            "authoritative_remaining_usd": (
                self.authoritative_remaining_usd
            ),
        }


AttemptOutcome = Literal["no_spend", "observed", "unknown_failed"]


@dataclass(frozen=True)
class AttemptSettlement:
    """Final immutable result of one accounting attempt."""

    outcome: AttemptOutcome
    route: RouteIdentity
    reservation_usd: float
    observation: CostObservation | None = None


class AttemptLedger:
    """Single-attempt exactly-once settlement guard."""

    __slots__ = ("route", "reservation_usd", "_settlement")

    def __init__(
        self,
        *,
        route: RouteIdentity,
        reservation_usd: float,
    ) -> None:
        if not isinstance(route, RouteIdentity):
            raise TypeError("route must be RouteIdentity")
        self.route = route
        self.reservation_usd = _cost_amount(
            reservation_usd, "reservation_usd",
        )
        self._settlement: AttemptSettlement | None = None

    @property
    def settled(self) -> bool:
        return self._settlement is not None

    @property
    def settlement(self) -> AttemptSettlement | None:
        return self._settlement

    def _settle(
        self,
        outcome: AttemptOutcome,
        observation: CostObservation | None,
    ) -> AttemptSettlement:
        if self._settlement is not None:
            raise AttemptSettlementError(
                f"accounting attempt for {self.route.provider}/"
                f"{self.route.model} settled more than once",
            )
        if observation is not None and observation.route not in (
            None,
            self.route,
        ):
            raise AttemptSettlementError(
                "cost observation route does not match attempt route",
            )
        if observation is not None and observation.route is None:
            observation = replace(observation, route=self.route)
        settlement = AttemptSettlement(
            outcome=outcome,
            route=self.route,
            reservation_usd=self.reservation_usd,
            observation=observation,
        )
        self._settlement = settlement
        return settlement

    def settle_no_spend(self) -> AttemptSettlement:
        return self._settle("no_spend", None)

    def settle_observation(
        self, observation: CostObservation,
    ) -> AttemptSettlement:
        if not isinstance(observation, CostObservation):
            raise TypeError("observation must be CostObservation")
        return self._settle("observed", observation)

    def settle_unknown_failed(self) -> AttemptSettlement:
        return self._settle(
            "unknown_failed",
            CostObservation.unknown(route=self.route),
        )

    def require_settled(self) -> AttemptSettlement:
        if self._settlement is None:
            raise AttemptSettlementError(
                f"accounting attempt for {self.route.provider}/"
                f"{self.route.model} exited without settlement",
            )
        return self._settlement


_EXCEPTION_OBSERVATION_ATTR = "_raptor_cost_observation"


def attach_cost_observation(
    exc: BaseException,
    observation: CostObservation,
) -> BaseException:
    """Attach accounting evidence without changing the exception type."""
    if not isinstance(exc, BaseException):
        raise TypeError("exc must be a BaseException")
    if not isinstance(observation, CostObservation):
        raise TypeError("observation must be CostObservation")
    try:
        setattr(exc, _EXCEPTION_OBSERVATION_ATTR, observation)
    except Exception:
        return exc
    return exc


def cost_observation_from_exception(
    exc: BaseException,
) -> CostObservation | None:
    """Find attached accounting evidence in an exception causal chain."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen and len(seen) < 8:
        seen.add(id(current))
        observation = getattr(
            current, _EXCEPTION_OBSERVATION_ATTR, None,
        )
        if isinstance(observation, CostObservation):
            return observation
        if current.__cause__ is not None:
            current = current.__cause__
        elif not current.__suppress_context__:
            current = current.__context__
        else:
            current = None
    return None


def normalize_budget_contract(
    value: UsdBudgetContract | str,
) -> UsdBudgetContract:
    try:
        return UsdBudgetContract(value)
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(item.value for item in UsdBudgetContract)
        raise ValueError(
            f"usd_budget_contract must be one of: {allowed}",
        ) from exc


def normalize_trusted_routes(
    values: Iterable[TrustedUsdRoute],
) -> tuple[TrustedUsdRoute, ...]:
    routes: list[TrustedUsdRoute] = []
    for value in values:
        if not isinstance(value, TrustedUsdRoute):
            raise TypeError(
                "trusted_usd_routes entries must be TrustedUsdRoute",
            )
        routes.append(value)
    return tuple(routes)


def route_identity_from_config(config: Any) -> RouteIdentity:
    """Build the canonical non-secret route from a ModelConfig-like object."""
    return RouteIdentity(
        getattr(config, "provider", ""),
        getattr(config, "model_name", ""),
    )


def cost_basis_for_model_config(config: Any) -> CostBasis:
    """Expected non-invoice basis for a direct provider configuration."""
    route = route_identity_from_config(config)
    if route.provider == "ollama":
        return CostBasis.UNKNOWN
    from core.llm.model_data import resolve_model_costs
    if resolve_model_costs(route.model):
        return CostBasis.CATALOG_PRICED
    raw_rate = getattr(config, "cost_per_1k_tokens", 0.0)
    try:
        rate = _cost_amount(raw_rate, "cost_per_1k_tokens")
    except (TypeError, ValueError):
        return CostBasis.UNKNOWN
    if rate > 0.0:
        return CostBasis.CONFIGURED_RATE
    return CostBasis.UNKNOWN


def direct_api_accounting_capability(
    config: Any,
) -> AccountingCapability:
    """Capability for existing direct SDK routes; never provider-billed."""
    basis = cost_basis_for_model_config(config)
    mode = (
        AccountingMode.AUTHORITATIVE
        if basis in (
            CostBasis.CATALOG_PRICED,
            CostBasis.CONFIGURED_RATE,
        )
        else AccountingMode.UNKNOWN
    )
    return AccountingCapability(
        mode=mode,
        hard_limit_supported=False,
        model_key_aggregation=model_key_aggregation_for_config(config),
    )


def model_key_aggregation_for_config(
    config: Any,
) -> ModelKeyAggregation:
    """Return the compatibility policy for a model-name-only key.

    Only provider spellings whose scorecard behavior predates route-aware
    accounting retain the v2 model-name key. New or unclassified transports
    fail closed until the deferred route-qualified scorecard migration.
    """
    route = route_identity_from_config(config)
    if route.provider in _LEGACY_MODEL_KEY_PROVIDERS:
        return ModelKeyAggregation.LEGACY_MODEL_NAME
    return ModelKeyAggregation.REFUSE


def estimated_cost_observation(
    config: Any,
    amount: float,
) -> CostObservation:
    """Create the configured route's catalog/configured estimate."""
    route = route_identity_from_config(config)
    basis = cost_basis_for_model_config(config)
    if basis is CostBasis.CATALOG_PRICED:
        return CostObservation.catalog_priced(amount, route=route)
    if basis is CostBasis.CONFIGURED_RATE:
        return CostObservation.configured_rate(amount, route=route)
    return CostObservation.unknown(route=route)


def cli_cost_observation(
    *,
    cost_usd: float,
    cost_reported: bool,
    route: RouteIdentity,
) -> CostObservation:
    """Claude CLI estimate when the envelope carried the field."""
    if not cost_reported:
        return CostObservation.unknown(route=route)
    try:
        return CostObservation.cli_reported(cost_usd, route=route)
    except (TypeError, ValueError):
        return CostObservation.unknown(route=route)


def is_observation_authorized(
    observation: CostObservation,
    trusted_routes: Iterable[TrustedUsdRoute],
) -> bool:
    """Whether an observation satisfies authoritative-required policy."""
    if observation.basis is CostBasis.PROVIDER_BILLED:
        return True
    if observation.basis not in (
        CostBasis.CATALOG_PRICED,
        CostBasis.CONFIGURED_RATE,
    ):
        return False
    if observation.route is None:
        return False
    return any(
        trusted.route == observation.route
        and trusted.basis is observation.basis
        for trusted in trusted_routes
    )


def is_basis_authorized(
    *,
    basis: CostBasis,
    route: RouteIdentity,
    trusted_routes: Iterable[TrustedUsdRoute],
) -> bool:
    """Pre-dispatch counterpart of :func:`is_observation_authorized`."""
    basis = CostBasis(basis)
    if basis is CostBasis.PROVIDER_BILLED:
        return True
    if basis not in (
        CostBasis.CATALOG_PRICED,
        CostBasis.CONFIGURED_RATE,
    ):
        return False
    return any(
        trusted.route == route and trusted.basis is basis
        for trusted in trusted_routes
    )


def format_accounting_summary(summary: AccountingSummary) -> str:
    """Render an honest compact cost summary for core surfaces."""
    if not isinstance(summary, AccountingSummary):
        raise TypeError("summary must be AccountingSummary")
    parts: list[str] = []
    if summary.provider_billed_calls:
        parts.append(f"Known USD ${summary.provider_billed_usd:.2f}")
    estimated_calls = (
        summary.catalog_priced_calls
        + summary.configured_rate_calls
        + summary.cli_reported_calls
    )
    if estimated_calls or not parts:
        labels: list[str] = []
        if summary.catalog_priced_calls:
            labels.append(f"catalog v{MODEL_COST_CATALOG_VERSION}")
        if summary.configured_rate_calls:
            labels.append("configured rate")
        if summary.cli_reported_calls:
            labels.append("CLI reported")
        label = f" ({' / '.join(labels)})" if labels else ""
        parts.append(
            f"Estimated USD ${summary.estimated_usd:.2f}{label}",
        )
    incomplete: list[str] = []
    if summary.unknown_calls:
        incomplete.append(f"{summary.unknown_calls} unknown")
    if summary.subscription_calls:
        incomplete.append(f"{summary.subscription_calls} subscription")
    if summary.unknown_failed_attempts:
        incomplete.append(
            f"{summary.unknown_failed_attempts} unknown failed",
        )
    if incomplete:
        parts[-1] += " — incomplete (" + ", ".join(incomplete) + " calls)"
    if summary.exposure_unresolved:
        parts.append(
            "unresolved exposure: actual unknown "
            "(retained reservation estimate "
            f"${summary.retained_reservation_estimate_usd:.4f})"
        )
    return "; ".join(parts)


__all__ = [
    "AccountingCapability",
    "AccountingMode",
    "AccountingSummary",
    "AttemptLedger",
    "AttemptSettlement",
    "AttemptSettlementError",
    "CostBasis",
    "CostObservation",
    "LLMAccountingUnavailableError",
    "LLMHardLimitUnsupportedError",
    "LLMPolicyError",
    "MODEL_COST_CATALOG_VERSION",
    "ModelKeyAggregation",
    "PinnedRouteSnapshot",
    "PinnedRouteViolation",
    "RouteIdentity",
    "ScorecardAggregationRefused",
    "TrustedUsdRoute",
    "UsdBudgetContract",
    "attach_cost_observation",
    "cli_cost_observation",
    "cost_basis_for_model_config",
    "cost_observation_from_exception",
    "direct_api_accounting_capability",
    "estimated_cost_observation",
    "format_accounting_summary",
    "is_basis_authorized",
    "is_observation_authorized",
    "model_key_aggregation_for_config",
    "normalize_budget_contract",
    "normalize_trusted_routes",
    "route_identity_from_config",
]
