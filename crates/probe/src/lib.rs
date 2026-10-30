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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsFamilyResult {
    pub status: CheckStatus,
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
        let address_signal = if status != CheckStatus::Passed {
            Observation::Unknown
        } else if addresses.is_empty() {
            Observation::Known(AddressSignal::Empty)
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
            addresses,
            address_signal,
        }
    }
}

pub fn dns_baseline_signal(dns: &DnsBaseline) -> Observation<ProbeSignal> {
    let families = [&dns.system_a, &dns.system_aaaa, &dns.doh_a, &dns.doh_aaaa];
    if families
        .iter()
        .any(|family| family.status == CheckStatus::NotRun)
    {
        return Observation::Unknown;
    }
    if families
        .iter()
        .any(|family| family.address_signal == Observation::Known(AddressSignal::Empty))
    {
        return Observation::Unknown;
    }
    if families.iter().any(|family| {
        matches!(
            family.address_signal,
            Observation::Known(
                AddressSignal::Unspecified
                    | AddressSignal::Empty
                    | AddressSignal::PrivateOrLoopback
            )
        )
    }) {
        return Observation::Known(ProbeSignal::PossibleDnsDivergence);
    }
    let a_comparable =
        dns.system_a.status == CheckStatus::Passed && dns.doh_a.status == CheckStatus::Passed;
    let aaaa_comparable =
        dns.system_aaaa.status == CheckStatus::Passed && dns.doh_aaaa.status == CheckStatus::Passed;
    if (a_comparable && dns.system_a.addresses != dns.doh_a.addresses)
        || (aaaa_comparable && dns.system_aaaa.addresses != dns.doh_aaaa.addresses)
    {
        Observation::Known(ProbeSignal::PossibleDnsDivergence)
    } else if a_comparable || aaaa_comparable {
        Observation::Known(ProbeSignal::NoObservedFailure)
    } else {
        Observation::Unknown
    }
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
        let empty = DnsFamilyResult::from_result(CheckStatus::Passed, vec![]);
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
    fn empty_family_answer_is_unknown_not_a_dns_interference_signal() {
        let public_a = DnsFamilyResult::from_result(
            CheckStatus::Passed,
            vec!["203.0.113.10".parse().unwrap()],
        );
        let empty_aaaa = DnsFamilyResult::from_result(CheckStatus::Passed, vec![]);
        let dns = DnsBaseline {
            system_a: public_a.clone(),
            system_aaaa: empty_aaaa.clone(),
            doh_a: public_a,
            doh_aaaa: empty_aaaa,
            doh_provider: Observation::Known("test".into()),
        };
        assert_eq!(dns_baseline_signal(&dns), Observation::Unknown);
    }
}
