//! Notification texts posted for the server thread.

use core::num::NonZeroU32;

use openxbdm_server::Server;
use openxbdm_server::notify::POSTED_TEXT_CAPACITY;
use openxbdm_server::notify::PostedTexts;
use xbox360::sync::SpinLock;
use xbox360::thread::current_object;
use xbox360_sys::xboxkrnl;

use super::super::Console;
use super::super::dispatcher;
use super::tell_log;
use crate::kernel::pool_tag;
use crate::net::XamNetwork;

static POSTED: SpinLock<Posted> = SpinLock::new(Posted {
    queue: PostedTexts::new(),
    kept_first: None,
    kept_last: None,
});

/// Texts waiting for the server thread. Kept texts are pool blocks of
/// posters that could not wait; while any exists, new texts are kept too,
/// so every queued text is older than every kept one.
struct Posted {
    queue: PostedTexts,
    kept_first: Option<NonZeroU32>,
    kept_last: Option<NonZeroU32>,
}

/// Header of a kept text's pool block; the text follows it.
#[repr(C)]
struct KeptText {
    next: Option<NonZeroU32>,
    length: u32,
}

/// The header of the kept text at `address`.
///
/// # Safety
///
/// `address` must be a block [`keep`] allocated and not yet freed.
unsafe fn header<'a>(address: NonZeroU32) -> &'a mut KeptText {
    // SAFETY: the caller's contract.
    unsafe { &mut *core::ptr::with_exposed_provenance_mut::<KeptText>(address.get() as usize) }
}

/// A text whose poster waits for the server thread to send it.
struct WaitingText {
    address: u32,
    length: u32,
}

/// Send a notification text to every notification channel. The server
/// thread sends it on its next pass. A text that does not fit the queue is
/// sent by the server thread while the poster waits. A poster that cannot
/// wait (the server thread itself, the log worker, which the server may be
/// waiting for, and any thread while the server waits for a command thread
/// or refuses requests otherwise) keeps the text in a pool block until a
/// later pass; only a failed allocation, or a server that stopped, loses it.
pub(super) fn post_notification(text: &[u8]) {
    {
        let mut posted = POSTED.lock();
        if posted.kept_first.is_none() && posted.queue.push(text) {
            return;
        }
    }

    let log_worker =
        tell_log::worker().is_some_and(|worker| worker.get() == current_object().id().raw());
    if log_worker || dispatcher::on_server_thread() || dispatcher::posts_blocked() {
        keep(text);
        return;
    }

    let mut request = WaitingText {
        address: text.as_ptr() as usize as u32,
        length: text.len() as u32,
    };
    if dispatcher::call_on_server_with(&mut request, send_waiting_text).is_none()
        && !dispatcher::stopped()
    {
        keep(text);
    }
}

/// Copy `text` into a pool block at the end of the kept texts. Once the
/// server stopped nobody sends them, so the text is dropped.
fn keep(text: &[u8]) {
    const HEADER_SIZE: usize = core::mem::size_of::<KeptText>();

    if dispatcher::stopped() {
        return;
    }

    let Ok(size) = u32::try_from(HEADER_SIZE + text.len()) else {
        return;
    };
    // SAFETY: the allocation takes only a size and tag.
    let Some(address) =
        NonZeroU32::new(unsafe { xboxkrnl::ExAllocatePoolWithTag(size, pool_tag::MONITOR) })
    else {
        return;
    };

    // SAFETY: the block holds the header and `text.len()` bytes after it.
    unsafe {
        let block = core::ptr::with_exposed_provenance_mut::<u8>(address.get() as usize);
        block.cast::<KeptText>().write(KeptText {
            next: None,
            length: text.len() as u32,
        });
        core::ptr::copy_nonoverlapping(text.as_ptr(), block.add(HEADER_SIZE), text.len());
    }

    let mut posted = POSTED.lock();
    // Checked again under the lock, which `discard_kept` takes after the
    // server stopped.
    if dispatcher::stopped() {
        drop(posted);
        // SAFETY: the block was allocated above and never listed.
        unsafe { xboxkrnl::ExFreePool(address.get()) };
        return;
    }

    match posted.kept_last.replace(address) {
        // SAFETY: the last kept block stays allocated while it is listed.
        Some(last) => unsafe { header(last) }.next = Some(address),
        None => posted.kept_first = Some(address),
    }
}

/// Free the kept texts once the server stopped, before the image unloads.
pub(super) fn discard_kept() {
    let mut current = {
        let mut posted = POSTED.lock();
        posted.kept_last = None;
        posted.kept_first.take()
    };

    while let Some(block) = current {
        // SAFETY: the chain was unlinked above and belongs to this call.
        current = unsafe { header(block) }.next;
        // SAFETY: as above; the block is not used again.
        unsafe { xboxkrnl::ExFreePool(block.get()) };
    }
}

/// Take the oldest posted text and pass it to `send`; `false` when none
/// waits.
pub(super) fn send_next(send: &mut dyn FnMut(&[u8])) -> bool {
    let mut text = [0u8; POSTED_TEXT_CAPACITY];

    let kept = {
        let mut posted = POSTED.lock();
        if let Some(length) = posted.queue.pop(&mut text) {
            drop(posted);
            send(&text[..length]);
            return true;
        }

        let Some(first) = posted.kept_first else {
            return false;
        };
        // SAFETY: listed blocks stay allocated until taken here.
        posted.kept_first = unsafe { header(first) }.next;
        if posted.kept_first.is_none() {
            posted.kept_last = None;
        }

        first
    };

    // SAFETY: the block was unlinked above and belongs to this call; its
    // text follows the header.
    unsafe {
        let length = header(kept).length as usize;
        let block = core::ptr::with_exposed_provenance::<u8>(kept.get() as usize);
        send(core::slice::from_raw_parts(
            block.add(core::mem::size_of::<KeptText>()),
            length,
        ));
        xboxkrnl::ExFreePool(kept.get());
    }

    true
}

/// Server-thread part of [`post_notification`]; waiting texts go first.
fn send_waiting_text(
    server: &mut Server,
    console: &mut Console,
    network: &mut XamNetwork,
    request: &mut WaitingText,
) -> u32 {
    server.drain_posted_notifications(console, network);

    // SAFETY: the poster waits in `call_on_server_with` while its text is
    // alive.
    let text = unsafe {
        core::slice::from_raw_parts(
            request.address as usize as *const u8,
            request.length as usize,
        )
    };
    server.state.notifications.send_text(text, network);

    0
}
