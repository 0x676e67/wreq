//! Ticket state for one TLS session-cache key.
//!
//! [`SessionEntry`] owns the two ticket slots for one full session key. The
//! parent cache serializes state changes and drops retired values outside its lock.

use btls::ssl::{SslSession, SslSessionRef};

/// Tickets retained for one compatible connection identity.
///
/// The parent LRU key supplies the endpoint and complete TLS configuration.
/// This entry owns only the ordered ticket state.
pub(in crate::tls) struct SessionEntry {
    /// Preferred and fallback tickets issued for the parent key.
    tickets: TicketSlots<SslSession>,
}

/// Two ordered TLS session tickets belonging to one cache entry.
///
/// The first slot is preferred. The second only holds a former primary already
/// classified as single-use, and cannot exist without the first. Reusable
/// tickets stay in the first slot and are cloned on lookup.
///
/// TLS 1.3 servers may treat a ticket as single-use. Consuming such tickets on
/// lookup follows the replay guidance in
/// [RFC 8446 Appendix C.4](https://datatracker.ietf.org/doc/html/rfc8446#appendix-C.4).
struct TicketSlots<T> {
    /// Preferred ticket at index `0` and fallback at index `1`.
    slots: [Option<T>; 2],
}

// ===== impl SessionEntry =====

impl SessionEntry {
    /// Creates an entry with `ticket` as the preferred session.
    pub(in crate::tls) fn new(ticket: SslSession) -> Self {
        Self {
            tickets: TicketSlots::with_primary(ticket),
        }
    }

    /// Inserts a newly issued ticket and returns any displaced ticket.
    /// The parent cache drops the returned value after releasing its lock.
    pub(in crate::tls) fn push(&mut self, ticket: SslSession) -> Option<SslSession> {
        self.tickets
            .push(ticket, |session| session.should_be_single_use())
    }

    /// Retrieves the preferred ticket according to its single-use policy.
    /// Single-use tickets are consumed while reusable tickets are up-referenced.
    pub(in crate::tls) fn pop(&mut self) -> Option<SslSession> {
        self.tickets.pop(|session| session.should_be_single_use())
    }

    /// Removes expired tickets and returns them for destruction outside the
    /// parent cache lock.
    ///
    /// A missing time or expired primary clears both slots. Otherwise only the
    /// fallback is checked; expiration never promotes it.
    pub(in crate::tls) fn expire(&mut self, now: Option<u64>) -> [Option<SslSession>; 2] {
        self.tickets.expire(|ticket| is_expired(ticket, now))
    }

    /// Returns whether the entry no longer owns a ticket.
    pub(in crate::tls) fn is_empty(&self) -> bool {
        self.tickets.is_empty()
    }
}

// ===== impl TicketSlots =====

impl<T> TicketSlots<T> {
    /// Creates slots with `ticket` as the preferred value and no fallback.
    fn with_primary(ticket: T) -> Self {
        Self {
            slots: [Some(ticket), None],
        }
    }

    /// Inserts the newest ticket and returns a ticket that is no longer kept.
    ///
    /// A single-use primary moves to fallback and displaces the older fallback.
    /// A reusable primary is displaced directly, leaving the fallback intact.
    /// The callback examines only the current primary.
    fn push<F>(&mut self, ticket: T, should_be_single_use: F) -> Option<T>
    where
        F: FnOnce(&T) -> bool,
    {
        let retired = if self.slots[0].as_ref().is_some_and(should_be_single_use) {
            let retired = self.slots[1].take();
            self.slots[1] = self.slots[0].take();
            retired
        } else {
            self.slots[0].take()
        };
        self.slots[0] = Some(ticket);
        retired
    }

    /// Retrieves the preferred ticket and applies its consumption rule.
    ///
    /// A single-use primary is removed and the fallback is promoted. A reusable
    /// primary is cloned without changing either slot.
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

    /// Applies the cache's expiration policy and returns removed tickets.
    ///
    /// A missing or expired primary clears both slots without checking the
    /// fallback. Otherwise only an expired fallback is removed. Returned
    /// positions mirror the slots; expiration never promotes a ticket.
    fn expire<F>(&mut self, mut is_expired: F) -> [Option<T>; 2]
    where
        F: FnMut(&T) -> bool,
    {
        let Some(ticket) = self.slots[0].as_ref() else {
            return [None, self.slots[1].take()];
        };
        if is_expired(ticket) {
            return [self.slots[0].take(), self.slots[1].take()];
        }

        let second = if self.slots[1].as_ref().is_some_and(is_expired) {
            self.slots[1].take()
        } else {
            None
        };
        [None, second]
    }

    /// Returns whether neither slot contains a ticket.
    ///
    /// Checking the primary is enough because fallback cannot exist alone.
    fn is_empty(&self) -> bool {
        self.slots[0].is_none()
    }
}

/// Returns whether a cached session is unusable at `now`.
/// A missing time expires it; BoringSSL expresses these values as Unix seconds.
#[inline(always)]
pub(in crate::tls) fn is_expired(session: &SslSessionRef, now: Option<u64>) -> bool {
    is_expired_at(now, session.time(), session.timeout())
}

/// Applies the session lifetime boundary and clock-rollback tolerance to raw
/// timestamp values.
///
/// Both bounds use saturating arithmetic; the lower bound allows one second of
/// clock rollback, while the upper bound follows the TLS 1.3 lifetime in
/// [RFC 8446 Section 4.6.1](https://datatracker.ietf.org/doc/html/rfc8446#section-4.6.1).
/// A missing `now` expires the session.
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
