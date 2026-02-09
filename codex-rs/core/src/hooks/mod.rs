pub(crate) mod config;
mod executor;
mod registry;
mod types;
mod user_notification;

pub(crate) use registry::Hooks;
pub(crate) use types::EffectAction;
pub(crate) use types::HookEvent;
pub(crate) use types::HookEventAfterAgent;
pub(crate) use types::HookEventPostToolUse;
pub(crate) use types::HookEventPreToolUse;
pub(crate) use types::HookPayload;

// Re-export new event structs as they are wired into dispatch sites.
// Unused re-exports are added incrementally in Tasks #46-#54.
pub(crate) use types::HookEventSessionStart;
pub(crate) use types::HookEventSessionEnd;
pub(crate) use types::HookEventPostToolUseFailure;
