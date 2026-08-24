//! Provider request-body schema helpers (plan §10.2 `schema/`). One module per provider —
//! `anthropic.rs` is the only one M3 needs; `bedrock.rs` is later work (M8+).

pub(crate) mod anthropic;
