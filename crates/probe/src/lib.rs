//! Structured network probe results and conservative signal classification.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Passed,
    Failed,
    TimedOut,
    NotRun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation<T> {
    Known(T),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSignal {
    Public,
    PrivateOrLoopback,
    Unspecified,
    Empty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResponseState {
    Answer,
    NoData,
    NxDomain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsFamilyResult {
    pub status: CheckStatus,
    pub response: Observation<DnsResponseState>,
    pub addresses: Vec<std::net::IpAddr>,
    pub address_signal: Observation<AddressSignal>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsBaseline {
    pub system_a: DnsFamilyResult,
    pub system_aaaa: DnsFamilyResult,
    pub doh_a: DnsFamilyResult,
    pub doh_aaaa: DnsFamilyResult,
    pub doh_provider: Observation<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineReport {
    pub target: String,
    pub control: EndpointResult,
    pub target_result: EndpointResult,
    pub dns: DnsBaseline,
    pub signal: Observation<ProbeSignal>,
}

impl DnsFamilyResult {
    pub fn from_result(status: CheckStatus, addresses: Vec<std::net::IpAddr>) -> Self {
        let response = if status != CheckStatus::Passed || addresses.is_empty() {
            Observation::Unknown
        } else {
            Observation::Known(DnsResponseState::Answer)
        };
        Self::from_dns_response(status, response, addresses)
    }

    pub fn from_dns_response(
        status: CheckStatus,
        response: Observation<DnsResponseState>,
        addresses: Vec<std::net::IpAddr>,
    ) -> Self {
        let address_signal = if status != CheckStatus::Passed {
            Observation::Unknown
        } else if response == Observation::Known(DnsResponseState::NoData) {
            Observation::Known(AddressSignal::Empty)
        } else if addresses.is_empty() {
            Observation::Unknown
        } else if addresses.iter().any(|ip| ip.is_unspecified()) {
            Observation::Known(AddressSignal::Unspecified)
        } else if addresses.iter().any(|ip| match ip {
            std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
            std::net::IpAddr::V6(ip) => {
                ip.is_unique_local() || ip.is_loopback() || ip.is_unicast_link_local()
            }
        }) {
            Observation::Known(AddressSignal::PrivateOrLoopback)
        } else {
            Observation::Known(AddressSignal::Public)
        };
        Self {
            status,
            response,
            addresses,
            address_signal,
        }
    }
}

pub fn dns_baseline_signal(dns: &DnsBaseline) -> Observation<ProbeSignal> {
    let pairs = [
        (&dns.system_a, &dns.doh_a),
        (&dns.system_aaaa, &dns.doh_aaaa),
    ];
    let mut has_comparable_family = false;
    let mut has_unknown_family = false;
    let mut has_special_answer = false;
    for (system, doh) in pairs {
        if system.status != CheckStatus::Passed || doh.status != CheckStatus::Passed {
            has_unknown_family = true;
            continue;
        }
        has_comparable_family = true;
        match (system.response, doh.response) {
            (
                Observation::Known(DnsResponseState::Answer),
                Observation::Known(DnsResponseState::Answer),
            ) => {
                if normalized(&system.addresses) != normalized(&doh.addresses) {
                    return Observation::Known(ProbeSignal::PossibleDnsDivergence);
                }
                has_special_answer |=
                    is_special(system.address_signal) || is_special(doh.address_signal);
            }
            (Observation::Known(system_state), Observation::Known(doh_state))
                if system_state == doh_state => {}
            (Observation::Known(_), Observation::Known(_)) => {
                return Observation::Known(ProbeSignal::PossibleDnsDivergence);
            }
            _ => {
                has_unknown_family = true;
            }
        }
    }
    if has_special_answer {
        Observation::Known(ProbeSignal::PossibleDnsSinkholeAnswer)
    } else if has_unknown_family || !has_comparable_family {
        Observation::Unknown
    } else {
        Observation::Known(ProbeSignal::NoObservedFailure)
    }
}

fn normalized(addresses: &[std::net::IpAddr]) -> Vec<std::net::IpAddr> {
    let mut result = addresses.to_vec();
    result.sort_unstable();
    result.dedup();
    result
}

fn is_special(signal: Observation<AddressSignal>) -> bool {
    matches!(
        signal,
        Observation::Known(AddressSignal::Unspecified | AddressSignal::PrivateOrLoopback)
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointResult {
    pub endpoint: String,
    pub dns: CheckStatus,
    pub tcp: CheckStatus,
    pub tls: CheckStatus,
    pub content: CheckStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeSignal {
    NoObservedFailure,
    PossibleDnsDivergence,
    PossibleDnsSinkholeAnswer,
    PossibleTcpInterference,
    PossibleTlsInterference,
    PossibleContentThrottlingOrFailure,
    GeneralConnectivityProblem,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsObservation {
    pub system_status: CheckStatus,
    pub system_addresses: Vec<String>,
    pub doh_status: CheckStatus,
    pub doh_addresses: Vec<String>,
}

/// Produces diagnostic signals only. These observations are not proof of DPI or
/// of any particular network cause.
pub fn classify(control: &EndpointResult, target: &EndpointResult) -> ProbeSignal {
    let control_reachable = control.tcp == CheckStatus::Passed;
    if !control_reachable && target.tcp != CheckStatus::NotRun {
        return ProbeSignal::GeneralConnectivityProblem;
    }
    if target.dns == CheckStatus::Failed
        || target.dns == CheckStatus::TimedOut
        || target.dns == CheckStatus::Passed && target.tcp == CheckStatus::NotRun
    {
        return ProbeSignal::PossibleDnsDivergence;
    }
    if target.tcp != CheckStatus::Passed {
        return if control_reachable {
            ProbeSignal::PossibleTcpInterference
        } else {
            ProbeSignal::Inconclusive
        };
    }
    if target.tls != CheckStatus::Passed {
        return ProbeSignal::PossibleTlsInterference;
    }
    if target.content != CheckStatus::Passed {
        return ProbeSignal::PossibleContentThrottlingOrFailure;
    }
    if control.content != CheckStatus::Passed {
        return ProbeSignal::Inconclusive;
    }
    ProbeSignal::NoObservedFailure
}

pub fn compare_dns(observation: &DnsObservation) -> ProbeSignal {
    if observation.system_status == CheckStatus::Passed
        && observation.doh_status == CheckStatus::Passed
        && observation.system_addresses != observation.doh_addresses
    {
        ProbeSignal::PossibleDnsDivergence
    } else if observation.system_status == CheckStatus::Passed
        && observation.doh_status == CheckStatus::Passed
    {
        ProbeSignal::NoObservedFailure
    } else {
        ProbeSignal::Inconclusive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(tcp: CheckStatus, tls: CheckStatus, content: CheckStatus) -> EndpointResult {
        EndpointResult {
            endpoint: "probe.example".into(),
            dns: CheckStatus::Passed,
            tcp,
            tls,
            content,
        }
    }

    #[test]
    fn separates_general_network_failure_from_target_failure() {
        let control = result(
            CheckStatus::Failed,
            CheckStatus::NotRun,
            CheckStatus::NotRun,
        );
        let target = result(
            CheckStatus::Failed,
            CheckStatus::NotRun,
            CheckStatus::NotRun,
        );
        assert_eq!(
            classify(&control, &target),
            ProbeSignal::GeneralConnectivityProblem
        );
    }

    #[test]
    fn reports_possible_target_tls_failure_only_as_a_signal() {
        let control = result(
            CheckStatus::Passed,
            CheckStatus::Passed,
            CheckStatus::Passed,
        );
        let target = result(
            CheckStatus::Passed,
            CheckStatus::Failed,
            CheckStatus::NotRun,
        );
        assert_eq!(
            classify(&control, &target),
            ProbeSignal::PossibleTlsInterference
        );
    }

    #[test]
    fn dns_answer_difference_is_not_reported_when_checks_failed() {
        let observation = DnsObservation {
            system_status: CheckStatus::TimedOut,
            system_addresses: vec![],
            doh_status: CheckStatus::Passed,
            doh_addresses: vec!["192.0.2.1".into()],
        };
        assert_eq!(compare_dns(&observation), ProbeSignal::Inconclusive);
    }

    #[test]
    fn empty_and_special_dns_answers_are_signals_not_confirmed_spoofing() {
        let empty = DnsFamilyResult::from_dns_response(
            CheckStatus::Passed,
            Observation::Known(DnsResponseState::NoData),
            vec![],
        );
        assert_eq!(
            empty.address_signal,
            Observation::Known(AddressSignal::Empty)
        );
        let local =
            DnsFamilyResult::from_result(CheckStatus::Passed, vec!["127.0.0.1".parse().unwrap()]);
        assert_eq!(
            local.address_signal,
            Observation::Known(AddressSignal::PrivateOrLoopback)
        );
        let zero =
            DnsFamilyResult::from_result(CheckStatus::Passed, vec!["0.0.0.0".parse().unwrap()]);
        assert_eq!(
            zero.address_signal,
            Observation::Known(AddressSignal::Unspecified)
        );
    }

    #[test]
    fn dns_baseline_keeps_missing_families_unknown_and_compares_a_and_aaaa_separately() {
        let public_a = DnsFamilyResult::from_result(
            CheckStatus::Passed,
            vec!["203.0.113.10".parse().unwrap()],
        );
        let not_run = DnsFamilyResult::from_result(CheckStatus::NotRun, vec![]);
        let dns = DnsBaseline {
            system_a: public_a.clone(),
            system_aaaa: not_run.clone(),
            doh_a: public_a,
            doh_aaaa: not_run,
            doh_provider: Observation::Unknown,
        };
        assert_eq!(dns_baseline_signal(&dns), Observation::Unknown);
    }

    #[test]
    fn matching_nodata_is_a_known_non_divergent_result() {
        let public_a = DnsFamilyResult::from_result(
            CheckStatus::Passed,
            vec!["203.0.113.10".parse().unwrap()],
        );
        let empty_aaaa = DnsFamilyResult::from_dns_response(
            CheckStatus::Passed,
            Observation::Known(DnsResponseState::NoData),
            vec![],
        );
        let dns = DnsBaseline {
            system_a: public_a.clone(),
            system_aaaa: empty_aaaa.clone(),
            doh_a: public_a,
            doh_aaaa: empty_aaaa,
            doh_provider: Observation::Known("test".into()),
        };
        assert_eq!(
            dns_baseline_signal(&dns),
            Observation::Known(ProbeSignal::NoObservedFailure)
        );
    }

    #[test]
    fn untyped_empty_result_stays_unknown() {
        let result = DnsFamilyResult::from_result(CheckStatus::Passed, vec![]);
        assert_eq!(result.response, Observation::Unknown);
        assert_eq!(result.address_signal, Observation::Unknown);
    }

    #[test]
    fn matching_special_addresses_are_sinkhole_signals_not_dns_divergence() {
        let private =
            DnsFamilyResult::from_result(CheckStatus::Passed, vec!["10.0.0.8".parse().unwrap()]);
        let no_aaaa = DnsFamilyResult::from_result(CheckStatus::NotRun, vec![]);
        let dns = DnsBaseline {
            system_a: private.clone(),
            system_aaaa: no_aaaa.clone(),
            doh_a: private,
            doh_aaaa: no_aaaa,
            doh_provider: Observation::Known("mock".into()),
        };
        assert_eq!(
            dns_baseline_signal(&dns),
            Observation::Known(ProbeSignal::PossibleDnsSinkholeAnswer)
        );
    }

    #[test]
    fn reordered_dns_sets_are_equal_when_both_families_were_queried() {
        let system = DnsFamilyResult::from_result(
            CheckStatus::Passed,
            vec![
                "203.0.113.2".parse().unwrap(),
                "203.0.113.1".parse().unwrap(),
            ],
        );
        let doh = DnsFamilyResult::from_result(
            CheckStatus::Passed,
            vec![
                "203.0.113.1".parse().unwrap(),
                "203.0.113.2".parse().unwrap(),
            ],
        );
        let system_aaaa =
            DnsFamilyResult::from_result(CheckStatus::Passed, vec!["2001:db8::1".parse().unwrap()]);
        let doh_aaaa =
            DnsFamilyResult::from_result(CheckStatus::Passed, vec!["2001:db8::1".parse().unwrap()]);
        let dns = DnsBaseline {
            system_a: system,
            system_aaaa,
            doh_a: doh,
            doh_aaaa,
            doh_provider: Observation::Known("mock".into()),
        };
        assert_eq!(
            dns_baseline_signal(&dns),
            Observation::Known(ProbeSignal::NoObservedFailure)
        );
    }

    #[test]
    fn differing_nxdomain_and_nodata_statuses_are_dns_divergence() {
        let system_a = DnsFamilyResult::from_dns_response(
            CheckStatus::Passed,
            Observation::Known(DnsResponseState::NxDomain),
            vec![],
        );
        let doh_a = DnsFamilyResult::from_dns_response(
            CheckStatus::Passed,
            Observation::Known(DnsResponseState::NoData),
            vec![],
        );
        let no_aaaa = DnsFamilyResult::from_dns_response(
            CheckStatus::Passed,
            Observation::Known(DnsResponseState::NoData),
            vec![],
        );
        let dns = DnsBaseline {
            system_a,
            system_aaaa: no_aaaa.clone(),
            doh_a,
            doh_aaaa: no_aaaa,
            doh_provider: Observation::Known("mock".into()),
        };
        assert_eq!(
            dns_baseline_signal(&dns),
            Observation::Known(ProbeSignal::PossibleDnsDivergence)
        );
    }
}
