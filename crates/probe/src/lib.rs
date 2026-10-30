//! Network probe result types. Active probes will be added in the next increment.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Passed,
    Failed,
    TimedOut,
    NotRun,
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
}
