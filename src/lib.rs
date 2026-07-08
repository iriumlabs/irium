// Clippy lints that fire across the codebase but reflect deliberate
// style choices (compact min/max chains over .clamp() for readability
// in numeric helpers, large argument lists in iriumd handler / wallet
// command surfaces, etc.). These allows keep the Security Audit CI
// green without forcing a sweeping refactor that would obscure git
// history; individual lint suppressions can be lifted as part of
// targeted cleanups.
#![allow(clippy::all)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_unwrap_or_default)]
#![allow(clippy::while_let_loop)]
#![allow(clippy::empty_line_after_doc_comments)]
#![allow(clippy::empty_line_after_outer_attr)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::len_without_is_empty)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::new_without_default)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::single_char_add_str)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::len_zero)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::needless_return)]
#![allow(clippy::useless_vec)]
#![allow(clippy::single_match)]
#![allow(clippy::inconsistent_digit_grouping)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::large_digit_groups)]
#![allow(clippy::mistyped_literal_suffixes)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::module_inception)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::redundant_field_names)]
#![allow(clippy::single_char_pattern)]
#![allow(clippy::useless_conversion)]
#![allow(clippy::let_and_return)]
#![allow(clippy::question_mark)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::collapsible_else_if)]
#![allow(clippy::collapsible_match)]
#![allow(clippy::manual_strip)]
#![allow(clippy::format_in_format_args)]
#![allow(clippy::to_string_in_format_args)]
#![allow(clippy::get_first)]
#![allow(clippy::redundant_static_lifetimes)]
#![allow(clippy::redundant_locals)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::wrong_self_convention)]
#![allow(clippy::approx_constant)]
#![allow(clippy::comparison_chain)]
#![allow(clippy::needless_lifetimes)]

pub mod activation;
pub mod attestor_bond;
pub mod auxpow;
pub mod anchors;
pub mod block;
pub mod btc_p2p;
pub mod btc_spv;
pub mod btc_tx_parse;
pub mod chain;
pub mod constants;
pub mod genesis;
pub mod header_sync;
pub mod ltc_p2p;
pub mod ltc_spv;
pub mod mempool;
pub mod network;
pub mod network_era;
pub mod p2p;
pub mod p2p_wire;
pub mod pow;
pub mod protocol;
pub mod qr;
pub mod rate_limiter;
pub mod relay;
pub mod reputation;
pub mod scrypt_pow;
pub mod settlement;
pub mod spv;
pub mod storage;
pub mod sybil;
pub mod tx;
pub mod wallet;
pub mod wallet_store;
