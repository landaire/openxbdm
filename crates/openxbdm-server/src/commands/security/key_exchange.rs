//! `keyxchg`: Diffie-Hellman exchange of the session key.
// The exchange releases its transfer block through the unsafe
// `TransferBlocks::release`.
#![allow(unsafe_code)]

use openxbdm_core::auth;
use openxbdm_core::auth::DH_LENGTH;
use openxbdm_core::auth::DhValue;
use openxbdm_core::auth::SessionKey;

use super::Continuation;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::transfer_blocks::TransferBlock;

/// `keyxchg` transfer: the client value is received, then the server value
/// is sent in the same block (stock allocates it from pool memory).
#[derive(Debug)]
pub struct KeyExchange {
    value: TransferBlock,
    phase: KeyExchangePhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyExchangePhase {
    Receiving,
    Sending,
    Sent,
}

/// `keyxchg`: receives the client's 0x60-byte public value, replies with
/// the server's, and sets the session key from the shared secret.
pub(super) fn key_exchange(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(socket) = invocation.session.as_ref().map(|session| session.socket()) else {
        return Err(CommandError::Fail);
    };

    let Some(value) =
        invocation
            .state
            .transfer_blocks
            .acquire(invocation.backend, socket, DH_LENGTH as u32)
    else {
        return Err(CommandError::OutOfMemory);
    };

    if let Some(session) = invocation.session.as_deref_mut() {
        session.continuation =
            crate::continuation::Continuation::Security(Continuation::KeyExchange(KeyExchange {
                value,
                phase: KeyExchangePhase::Receiving,
            }));
        session.receive_remaining = Some(DH_LENGTH as u32);
    }

    Ok(Reply::SendBinary)
}

pub(super) fn resume_key_exchange(
    exchange: &mut KeyExchange,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    match exchange.phase {
        KeyExchangePhase::Receiving => {
            let remaining = cx.session.receive_remaining.unwrap_or(0) as usize;

            if cx.received.is_empty() {
                cx.session.receive_remaining = Some(0);
                return Err(CommandError::Unexpected);
            }

            let offset = DH_LENGTH - remaining;
            let count = cx.received.len().min(remaining);
            let value =
                &mut cx.state.transfer_blocks.bytes(cx.backend, exchange.value)[..DH_LENGTH];
            value[offset..offset + count].copy_from_slice(&cx.received[..count]);

            let remaining = remaining - count;
            cx.session.receive_remaining = Some(remaining as u32);
            if remaining != 0 {
                return Ok(Reply::Ok);
            }

            let mut client = DhValue([0; DH_LENGTH]);
            client.0.copy_from_slice(value);

            let mut exponent = DhValue([0; DH_LENGTH]);
            cx.backend.random_bytes(&mut exponent.0);
            let shared = auth::dh_mod_exp(Some(&client), &exponent);
            let server = auth::dh_mod_exp(None, &exponent);

            cx.state.transfer_blocks.bytes(cx.backend, exchange.value)[..DH_LENGTH]
                .copy_from_slice(&server.0);
            exchange.phase = KeyExchangePhase::Sending;
            cx.session.session_key = Some(SessionKey::derive(&shared));

            Ok(Reply::Binary)
        }
        KeyExchangePhase::Sending => {
            cx.binary[..DH_LENGTH].copy_from_slice(
                &cx.state.transfer_blocks.bytes(cx.backend, exchange.value)[..DH_LENGTH],
            );
            cx.binary_len = DH_LENGTH;
            exchange.phase = KeyExchangePhase::Sent;
            Ok(Reply::Ok)
        }
        KeyExchangePhase::Sent => {
            // SAFETY: the transfer ends with this result, so the server drops
            // the continuation, the only other holder.
            unsafe { cx.state.transfer_blocks.release(cx.backend, exchange.value) };
            Err(CommandError::EndOfData)
        }
    }
}
