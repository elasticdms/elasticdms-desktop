//! What is set on the mock before it runs.
//!
//! Everything has a default, and the default is the **strict** reading of the contract: a nonce
//! required, `Elasticdms-Version` required, the page size as in 03 §6.0.8. A test harness that is
//! lenient by default lets through exactly the mistakes that are expensive in production; whoever
//! wants to switch a rule off for one experiment switches it off explicitly.

/// The mock's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Configuration {
    /// Port of the resource API; `0` means "any free one" (tests).
    pub api_port: u16,
    /// Port of the authorization server; `0` as above.
    pub auth_port: u16,
    /// Base address of the web interface. Without one the mock serves `/geraet` and `/erfassung` on
    /// the auth listener, and that one is then the web interface as well.
    pub app_base: Option<String>,
    /// The tenant that every token and every key statement names (03 §6.0.1).
    pub tenant: String,
    /// The tenant's display name.
    pub tenant_name: String,
    /// The version of the server key set (`keySetVersion`).
    pub key_state: u64,
    /// Default for `limit` when the request names none (03 §6.0.8: 200).
    pub page_size: u32,
    /// `displayLimit` of the document listings when the container has no limit of its own (§7.1.2).
    pub display_limit: u64,
    /// Whether a freshly enrolled device is `active` straight away. Default: yes — otherwise every
    /// experiment would need an approval first. Set to `false`, every token request answers
    /// `403 device-pending-approval` (§7.0.5), and exactly that path becomes testable.
    pub auto_approval: bool,
    /// Whether a device flow counts as confirmed straight away. Default: yes. Set to `false`, it
    /// waits for the `/device` page or for [`crate::Control::confirm`].
    pub auto_confirmation: bool,
    /// Whether every answer hands out a **new** nonce. Default: no — the nonce of an origin then
    /// stays put until somebody rotates it, and a test stays readable.
    pub nonce_per_response: bool,
    /// Whether `Elasticdms-Version` is mandatory on `/v1/*` (§7.0.1). Default: yes.
    pub requires_version: bool,
    /// Whether the tenant has unlocked the folder client. On `false` every resource call answers
    /// `403 desktop-client-not-permitted` (§7.5.1).
    pub folder_client_unlocked: bool,
    /// Whether the mock starts with the German sample tenant (see [`crate::seed`]).
    pub with_seed: bool,
    /// Lifetime of an access token in seconds (§7.0.8, proposal for a workstation: 15 min).
    pub access_token_second: u64,
    /// Absolute lifetime of a refresh token in seconds (§7.0.8: 12 h).
    pub refresh_second: u64,
    /// Lifetime of a device code in the device flow (RFC 8628, §7.0.7: 300 s).
    pub device_code_second: u64,
    /// Longest permitted wait time of the long poll in seconds (§7.3.1: 25).
    pub wait_time_max: u32,
}

impl Default for Configuration {
    fn default() -> Self {
        Self::defaults()
    }
}

impl Configuration {
    /// The default: two random ports, the strict reading, the German sample tenant.
    pub fn defaults() -> Self {
        Self {
            api_port: 0,
            auth_port: 0,
            app_base: None,
            tenant: "t_acme".to_owned(),
            tenant_name: "ACME GmbH".to_owned(),
            key_state: 7,
            page_size: edms_wire::namespace::LIMIT_DEFAULT,
            display_limit: edms_wire::namespace::DISPLAY_LIMIT_PROPOSAL,
            auto_approval: true,
            auto_confirmation: true,
            nonce_per_response: false,
            requires_version: true,
            folder_client_unlocked: true,
            with_seed: true,
            access_token_second: 900,
            refresh_second: 43_200,
            device_code_second: 300,
            wait_time_max: edms_wire::delivery::WAIT_TIME_SECOND,
        }
    }

    /// Fixed ports instead of random ones — the `edms-mock` program uses them.
    #[must_use]
    pub fn with_ports(mut self, api: u16, auth: u16) -> Self {
        self.api_port = api;
        self.auth_port = auth;
        self
    }

    /// After enrolment the device waits for an administrator's approval.
    #[must_use]
    pub fn awaiting_approval(mut self) -> Self {
        self.auto_approval = false;
        self
    }

    /// The device flow waits for a human.
    #[must_use]
    pub fn awaiting_confirmation(mut self) -> Self {
        self.auto_confirmation = false;
        self
    }

    /// Small pages, so that a test sees several pages without creating 200 documents.
    #[must_use]
    pub fn with_page_size(mut self, size: u32) -> Self {
        self.page_size = size;
        self
    }

    /// Without the German sample tenant — an empty server.
    #[must_use]
    pub fn without_seed(mut self) -> Self {
        self.with_seed = false;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_reads_the_contract_strictly() {
        let k = Configuration::defaults();
        assert!(
            k.requires_version,
            "without the version header the client only fails in production"
        );
        assert_eq!(k.page_size, 200, "03 §6.0.8");
        assert_eq!(k.wait_time_max, 25, "§7.3.1");
        assert!(k.auto_approval && k.auto_confirmation, "the short path is the default");
    }

    #[test]
    fn the_switches_change_exactly_one_value() {
        let k = Configuration::defaults().awaiting_approval().with_page_size(2);
        assert!(!k.auto_approval);
        assert!(k.auto_confirmation);
        assert_eq!(k.page_size, 2);
    }
}
