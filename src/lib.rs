#![forbid(unsafe_code)]

//! The party authorize technology — a technology of `xmip-core-authorize`.
//!
//! One policy at the transport layer: an allow-list of Parties (ADR-0050
//! section 5). A Party is the actor Xmip recognizes, and resolving a
//! credential to one answers authentication; whether that Party may do this
//! is the separate question asked afterwards (ADR-0019 clause 4). This is
//! that question, answered from a list.
//!
//! The list is kept three ways and the three add up: Parties allowed
//! everywhere, Parties allowed at one Location by the artifact name the
//! attempt carries, and Parties allowed on one Contract. Where none of the
//! three has anything to say about an attempt — no list for everywhere, none
//! for this artifact, none for this Contract — the policy has no opinion.
//! Where any of them does, the Party judged is the accountable one, the
//! transport identity's; an identity that resolved to no Party is refused,
//! because a list of Parties cannot admit nobody, and a Party on no
//! applicable list is refused by identifier.

use authorize::{Attempt, Authorizer, Decision};
use context::IdentityFacts;
use std::collections::BTreeMap;
use xcore::{Layer, PartyId};

/// The manifest leaf, and the name a denial carries.
pub const NAME: &str = "party";

/// The allow-list, kept for everywhere, per Location and per Contract.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PartyPolicy {
    everywhere: Vec<PartyId>,
    at: BTreeMap<String, Vec<PartyId>>,
    on: BTreeMap<String, Vec<PartyId>>,
}

impl PartyPolicy {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow a Party on every artifact and Contract.
    #[must_use]
    pub fn allow(mut self, party: PartyId) -> Self {
        self.everywhere.push(party);
        self
    }

    /// Allow a Party at one Location, by the artifact name attempts carry.
    #[must_use]
    pub fn allow_at(mut self, artifact: impl Into<String>, party: PartyId) -> Self {
        self.at.entry(artifact.into()).or_default().push(party);
        self
    }

    /// Allow a Party on one Contract.
    #[must_use]
    pub fn allow_on(mut self, contract: impl Into<String>, party: PartyId) -> Self {
        self.on.entry(contract.into()).or_default().push(party);
        self
    }

    /// The lists that apply to an attempt, added up; `None` where no list
    /// speaks about it at all.
    fn applicable(&self, attempt: &Attempt) -> Option<Vec<PartyId>> {
        let at = self.at.get(&attempt.artifact);
        let on = attempt
            .contract
            .as_ref()
            .and_then(|contract| self.on.get(contract));

        if self.everywhere.is_empty() && at.is_none() && on.is_none() {
            return None;
        }

        Some(
            self.everywhere
                .iter()
                .chain(at.into_iter().flatten())
                .chain(on.into_iter().flatten())
                .copied()
                .collect(),
        )
    }
}

impl Authorizer for PartyPolicy {
    fn name(&self) -> &str {
        NAME
    }

    fn layer(&self) -> Layer {
        Layer::Transport
    }

    fn decide(&self, identity: &IdentityFacts, attempt: &Attempt) -> Option<Decision> {
        let allowed = self.applicable(attempt)?;
        let accountable = identity.accountable();
        let contract = attempt
            .contract
            .as_ref()
            .map(|contract| format!(" carrying {contract}"))
            .unwrap_or_default();

        let Some(party) = accountable.party_id else {
            return Some(Decision::denied(
                NAME,
                format!(
                    "{}={} resolved to no Party, and '{}' admits Parties only",
                    accountable.mechanism.name(),
                    accountable.value,
                    attempt.artifact
                ),
            ));
        };

        if allowed.contains(&party) {
            return Some(Decision::Allowed);
        }

        Some(Decision::denied(
            NAME,
            format!(
                "Party {party} is not allowed to {} on '{}'{contract}",
                attempt.action, attempt.artifact
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authorize::Action;
    use context::{Alignment, AuthenticatedIdentity, Verified};
    use xcore::{Established, mechanism};

    fn tls(party: Option<PartyId>) -> IdentityFacts {
        let identity = AuthenticatedIdentity::new(
            mechanism::mutual_tls(),
            "CN=partner-x.example",
            Established::Passed,
            Verified::Proven,
        );
        let identity = match party {
            Some(party) => identity.resolving_to(party),
            None => identity,
        };

        IdentityFacts::evaluate(Alignment::None, identity, None)
    }

    fn policy() -> PartyPolicy {
        PartyPolicy::new()
            .allow_at("partner-x", PartyId::new(1))
            .allow_on("Invoices", PartyId::new(2))
    }

    #[test]
    fn a_party_on_the_list_for_this_location_is_allowed() {
        let decision = policy().decide(
            &tls(Some(PartyId::new(1))),
            &Attempt::new(Action::Receive, "partner-x"),
        );

        assert_eq!(decision, Some(Decision::Allowed));
        assert_eq!(policy().name(), "party");
        assert_eq!(policy().layer(), Layer::Transport);
    }

    #[test]
    fn a_party_on_no_applicable_list_is_refused_by_identifier() {
        let decision = policy()
            .decide(
                &tls(Some(PartyId::new(2))),
                &Attempt::new(Action::Receive, "partner-x").on_contract("Orders"),
            )
            .expect("an opinion");

        assert_eq!(
            decision.to_string(),
            "denied by party: Party 00000000-0000-0000-0000-000000000002 is not allowed \
             to receive on 'partner-x' carrying Orders"
        );
    }

    #[test]
    fn an_attempt_no_list_speaks_about_is_no_opinion() {
        let decision = policy().decide(
            &tls(Some(PartyId::new(1))),
            &Attempt::new(Action::Send, "Billing"),
        );

        assert_eq!(decision, None);
    }

    #[test]
    fn an_identity_that_resolved_to_no_party_is_refused_where_a_list_applies() {
        // A list of Parties cannot admit nobody. The same identity at an
        // artifact no list covers is still nothing to this policy.
        let decision = policy()
            .decide(&tls(None), &Attempt::new(Action::Receive, "partner-x"))
            .expect("an opinion");

        assert_eq!(
            decision.to_string(),
            "denied by party: mutual-tls=CN=partner-x.example resolved to no Party, \
             and 'partner-x' admits Parties only"
        );
        assert_eq!(
            policy().decide(&tls(None), &Attempt::new(Action::Send, "Billing")),
            None
        );
    }

    #[test]
    fn the_lists_add_up_so_a_contract_list_admits_on_any_location() {
        // Party 2 is allowed on Invoices, wherever they arrive; everywhere
        // adds Party 3 to every attempt.
        let policy = policy().allow(PartyId::new(3));
        let invoices = Attempt::new(Action::Receive, "partner-x").on_contract("Invoices");

        assert_eq!(
            policy.decide(&tls(Some(PartyId::new(2))), &invoices),
            Some(Decision::Allowed)
        );
        assert_eq!(
            policy.decide(
                &tls(Some(PartyId::new(3))),
                &Attempt::new(Action::Send, "Billing")
            ),
            Some(Decision::Allowed)
        );
    }
}
