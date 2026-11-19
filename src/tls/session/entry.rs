//! Per-key ticket slots for the built-in TLS session store.
//!
//! [`SessionEntry`] holds up to two tickets per key. The parent store handles locking and
//! drops retired tickets after releasing its lock.

use btls::ssl::SslSessionRef;

use super::Ticket;

/// Ordered ticket slots stored under a single session key in the built-in LRU store.
///
/// Holds up to two tickets (primary and fallback) and returns displaced or expired tickets
/// so the store can drop them outside its lock.
pub(in crate::tls) struct SessionEntry {
    tickets: TicketSlots<Ticket>,
}

/// Primary and optional fallback ticket slots.
///
/// Slot `0` is preferred. Slot `1` only holds a demoted single-use ticket and is never
/// occupied while slot `0` is empty. Single-use tickets are consumed on lookup
/// ([RFC 8446 Appendix C.4](https://datatracker.ietf.org/doc/html/rfc8446#appendix-C.4)),
/// while reusable tickets stay in slot `0` and are cloned.
struct TicketSlots<T> {
    slots: [Option<T>; 2],
}

// ===== impl SessionEntry =====

impl SessionEntry {
    /// Creates an entry with `ticket` in the primary slot.
    pub(in crate::tls) fn new(ticket: Ticket) -> Self {
        Self {
            tickets: TicketSlots::with_primary(ticket),
        }
    }

    /// Inserts a new ticket and returns any displaced ticket to drop outside the store lock.
    pub(in crate::tls) fn push(&mut self, ticket: Ticket) -> Option<Ticket> {
        self.tickets
            .push(ticket, |ticket| ticket.session().should_be_single_use())
    }

    /// Returns the preferred ticket, removing it if single-use or cloning it if reusable.
    pub(in crate::tls) fn pop(&mut self) -> Option<Ticket> {
        self.tickets
            .pop(|ticket| ticket.session().should_be_single_use())
    }

    /// Removes expired tickets and returns them to drop outside the store lock.
    ///
    /// A missing `now` or an expired primary clears both slots; otherwise only the fallback
    /// is checked, and expiration never promotes the fallback.
    pub(in crate::tls) fn expire(&mut self, now: Option<u64>) -> [Option<Ticket>; 2] {
        self.tickets
            .expire(|ticket| is_expired(ticket.session(), now))
    }

    /// Returns `true` when no tickets remain in this entry.
    pub(in crate::tls) fn is_empty(&self) -> bool {
        self.tickets.is_empty()
    }
}

// ===== impl TicketSlots =====

impl<T> TicketSlots<T> {
    fn with_primary(ticket: T) -> Self {
        Self {
            slots: [Some(ticket), None],
        }
    }

    /// Inserts `ticket` into slot `0`, returning any evicted ticket.
    ///
    /// If the current primary is single-use, it moves to slot `1` (evicting the previous
    /// fallback); otherwise the primary is replaced directly and slot `1` stays untouched.
    fn push<F>(&mut self, ticket: T, should_be_single_use: F) -> Option<T>
    where
        F: FnOnce(&T) -> bool,
    {
        if self.slots[0].as_ref().is_some_and(should_be_single_use) {
            let primary = self.slots[0].replace(ticket);
            std::mem::replace(&mut self.slots[1], primary)
        } else {
            self.slots[0].replace(ticket)
        }
    }

    /// Pops a single-use primary (promoting slot `1`), or clones a reusable primary in place.
    fn pop<F>(&mut self, should_be_single_use: F) -> Option<T>
    where
        T: Clone,
        F: FnOnce(&T) -> bool,
    {
        if self.slots[0].as_ref().is_some_and(should_be_single_use) {
            let ticket = self.slots[0].take();
            self.slots[0] = self.slots[1].take();
            ticket
        } else {
            self.slots[0].clone()
        }
    }

    /// Clears both slots if the primary is missing or expired; otherwise expires only slot `1`.
    fn expire<F>(&mut self, mut is_expired: F) -> [Option<T>; 2]
    where
        F: FnMut(&T) -> bool,
    {
        if self.slots[0].as_ref().is_none_or(&mut is_expired) {
            return [self.slots[0].take(), self.slots[1].take()];
        }

        [None, self.slots[1].take_if(|ticket| is_expired(ticket))]
    }

    fn is_empty(&self) -> bool {
        // Slot 1 is never populated while slot 0 is empty.
        self.slots[0].is_none()
    }
}

/// Returns `true` if `session` is expired at `now` (Unix seconds); `None` always expires.
#[inline(always)]
pub(in crate::tls) fn is_expired(session: &SslSessionRef, now: Option<u64>) -> bool {
    is_expired_at(now, session.time(), session.timeout())
}

/// Checks session expiry against `[established - 1, established + timeout)` using saturating math.
///
/// Allows 1 second of clock rollback and enforces the TLS 1.3 lifetime boundary
/// ([RFC 8446 Section 4.6.1](https://datatracker.ietf.org/doc/html/rfc8446#section-4.6.1)).
/// Missing `now` is treated as expired.
fn is_expired_at(now: Option<u64>, established: u64, timeout: u32) -> bool {
    let Some(now) = now else {
        return true;
    };
    now < established.saturating_sub(1) || now >= established.saturating_add(u64::from(timeout))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestTicket {
        id: usize,
        single_use: bool,
    }

    fn ticket(id: usize, single_use: bool) -> TestTicket {
        TestTicket { id, single_use }
    }

    #[test]
    fn ticket_slots_match_single_use_and_reusable_policy() {
        let mut tickets = TicketSlots::with_primary(ticket(1, true));
        assert_eq!(tickets.push(ticket(2, true), |item| item.single_use), None);
        assert_eq!(
            tickets.push(ticket(3, true), |item| item.single_use),
            Some(ticket(1, true))
        );
        assert_eq!(tickets.pop(|item| item.single_use), Some(ticket(3, true)));
        assert_eq!(tickets.pop(|item| item.single_use), Some(ticket(2, true)));
        assert_eq!(tickets.pop(|item| item.single_use), None);

        tickets = TicketSlots::with_primary(ticket(4, true));
        assert_eq!(tickets.push(ticket(5, false), |item| item.single_use), None);
        assert_eq!(tickets.pop(|item| item.single_use), Some(ticket(5, false)));
        assert_eq!(
            tickets.push(ticket(6, true), |item| item.single_use),
            Some(ticket(5, false))
        );
        assert_eq!(tickets.pop(|item| item.single_use), Some(ticket(6, true)));
        assert_eq!(tickets.pop(|item| item.single_use), Some(ticket(4, true)));
        assert_eq!(tickets.pop(|item| item.single_use), None);
    }

    #[test]
    fn expiration_uses_timeout_boundary_and_clock_tolerance() {
        assert!(!is_expired_at(Some(99), 100, 10));
        assert!(is_expired_at(Some(98), 100, 10));
        assert!(!is_expired_at(Some(109), 100, 10));
        assert!(is_expired_at(Some(110), 100, 10));
        assert!(is_expired_at(None, 100, 10));
        assert!(is_expired_at(Some(u64::MAX), u64::MAX, 1));

        let mut lookup = TicketSlots::with_primary(ticket(1, true));
        lookup.push(ticket(2, true), |item| item.single_use);
        assert_eq!(lookup.pop(|item| item.single_use), Some(ticket(2, true)));
        assert_eq!(lookup.expire(|item| item.id == 2), [None, None]);
        assert_eq!(lookup.pop(|item| item.single_use), Some(ticket(1, true)));

        let mut primary_expired = TicketSlots::with_primary(ticket(1, true));
        primary_expired.push(ticket(2, true), |item| item.single_use);
        assert_eq!(
            primary_expired.expire(|item| item.id == 2),
            [Some(ticket(2, true)), Some(ticket(1, true))]
        );
        assert!(primary_expired.is_empty());

        let mut fallback_expired = TicketSlots::with_primary(ticket(3, true));
        fallback_expired.push(ticket(4, true), |item| item.single_use);
        assert_eq!(
            fallback_expired.expire(|item| item.id == 3),
            [None, Some(ticket(3, true))]
        );
        assert_eq!(
            fallback_expired.pop(|item| item.single_use),
            Some(ticket(4, true))
        );

        let mut missing_primary = TicketSlots {
            slots: [None, Some(ticket(5, true))],
        };
        assert_eq!(
            missing_primary.expire(|_| false),
            [None, Some(ticket(5, true))]
        );
        assert!(missing_primary.is_empty());
    }
}
