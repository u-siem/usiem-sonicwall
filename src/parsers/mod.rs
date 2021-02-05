use chrono::prelude::{DateTime, Datelike, NaiveDate, NaiveDateTime, TimeZone, Utc};
use std::borrow::Cow;
use std::collections::BTreeMap;
use usiem::events::field::{SiemField, SiemIp};
use usiem::events::firewall::{FirewallEvent, FirewallOutcome};
use usiem::events::protocol::NetworkProtocol;
use usiem::events::{SiemEvent, SiemLog};
use usiem::utilities::ip_utils::{ipv4_from_str, ipv6_from_str, port_to_u16};

pub fn parse_log(log: SiemLog) -> Result<SiemLog, SiemLog> {
    let log_line = log.message();
    let start_log_pos = match log_line.find(" id=") {
        Some(val) => val,
        None => return Err(log),
    };
    let syslog_header = &log_line[0..start_log_pos];
    let log_content = &log_line[start_log_pos..];

    let mut syslog_hdr_content = Vec::new();
    let syslog_start = match syslog_header.find(">") {
        Some(val) => val,
        None => return Err(log),
    };
    syslog_hdr_content.push(&syslog_header[1..syslog_start]);
    let mut last_pos = 0;
    for (pos, c) in syslog_header[syslog_start + 1..].char_indices() {
        if c == ' ' {
            syslog_hdr_content.push(&syslog_header[last_pos..pos]);
            last_pos = pos + 1;
        }
    }

    let field_map = extract_fields(log_line);

    let event_created = match field_map.get("time") {
        Some(val) => {
            //FORMAT: 2021-02-05 01:02:03 UTC
            match Utc.datetime_from_str(val, "%Y-%m-%d %H:%M:%S UTC") {
                Ok(timestamp) => timestamp.timestamp_millis(),
                Err(_err) => return Err(log),
            }
        }
        None => return Err(log),
    };
    let service = match field_map.get("id") {
        Some(val) => val.to_string(),
        None => return Err(log),
    };
    let observer_name = match field_map.get("sn") {
        Some(val) => val.to_string(),
        None => return Err(log),
    };
    let observer_ip = match syslog_hdr_content.get(4) {
        Some(val) => match ipv4_from_str(val) {
            Ok(val) => SiemIp::V4(val),
            Err(_) => match ipv6_from_str(val) {
                Ok(val) => SiemIp::V6(val),
                Err(_) => log.origin().clone(),
            },
        },
        None => return Err(log),
    };
    let mut log = SiemLog::new(log_content.to_owned(), log.event_received(), observer_ip);
    log.set_event_created(event_created);
    log.set_vendor(Cow::Borrowed("SonicWall"));
    log.set_product(Cow::Borrowed("SonicWall"));
    log.set_service(Cow::Owned(service));
    log.set_category(Cow::Borrowed("Firewall"));
    log.add_field("observer.name", SiemField::Text(Cow::Owned(observer_name)));

    sonicwall_event_selector(field_map, log)
}

fn sonicwall_event_selector<'a>(
    field_map: BTreeMap<Cow<'a, str>, Cow<'a, str>>,
    mut log: SiemLog,
) -> Result<SiemLog, SiemLog> {
    //fw=Firewall WAN IP
    //pri=Message priority
    //c=Message category (legacy only)
    //m=Message ID
    //msg
    //sess=Pre-defined string indicating session type
    /*
        None - the starting session type when user authentication is still pending or just started
        Web - identified as a Web browser session
        Portal - SSL-VPN portal login
        l2tpc - L2TP client session
        vpnc - VPN client session
        sslvpnc - SSL-VPN client session
        Auto - Auto-logged in session, for example Single Sign On (SSO)
        Other - none of the known types
        CLI - indicates a CLI session
    */
    //n=Message count
    //usr=Displays the user name
    //src=Indicates the source IP address, and optionally, port, network interface, and resolved name
    //dst=Destination IP address, and optionally, port, network interface, and resolved name
    //srcMac=Source MAC Address
    //dstMac=Destination MAC Address
    //proto=Diplays the protocol information(rendered as “proto=[protocol]” or just “[proto]/[service]”)
    //rcvd=Indicates the number of bytes received within connection
    //rule=Used to identify a policy or a rule associated with an even
    match field_map.get("usr") {
        Some(val) => log.add_field("user.name", SiemField::User(val.to_string())),
        None => {}
    };
    match field_map.get("src") {
        Some(val) => {
            let (src_ip, src_port, src_intrf) = get_ip_field(val);
            add_field_or_not(&mut log, src_ip,"source.ip");
            add_field_or_not(&mut log, src_port,"source.port");
            add_field_or_not(&mut log, src_intrf,"source.interface");
        }
        None => {}
    };
    match field_map.get("dst") {
        Some(val) => {
            let (src_ip, src_port, src_intrf) = get_ip_field(val);
            add_field_or_not(&mut log, src_ip,"destination.ip");
            add_field_or_not(&mut log, src_port,"destination.port");
            add_field_or_not(&mut log, src_intrf,"destination.interface");
        }
        None => {}
    };
    add_value_or_not(&mut log, field_map.get("srcMac"), "source.mac" );
    add_value_or_not(&mut log, field_map.get("dstMac"), "destination.mac" );
    match field_map.get("proto") {
        Some(val) => {
            for s in val.split("/") {
                log.add_field("network.transport", SiemField::Text(Cow::Owned(s.to_string())));
                break;
            }
        },
        None => {}
    };
    match field_map.get("rcvd") {
        Some(val) => {
            let received_bytes = val.parse::<u64>();
            match received_bytes {
                Ok(val) => {log.add_field("destination.bytes", SiemField::U64(val));},
                Err(_) =>{}
            }
        },
        None => {}
    };
    match field_map.get("sess") {
        Some(sess) => {
            match sess {
                Cow::Borrowed("slvpnc") => {
                    //Auth type
                    log.add_field("event.dataset", SiemField::from_str("slvpnc"));
                    return Ok(log)
                },
                _ => {}
            }
            
        },
        None => {}
    }
    Ok(log)
}

fn add_value_or_not<'a>(log : &'a mut SiemLog, field_value : Option<&Cow<'a, str>>, name : &'static str) {
    match field_value {
        Some(val) => {
            log.add_field(name, SiemField::Text(Cow::Owned(val.to_string())));
        },
        None => {}
    };
}
fn add_field_or_not<'a>(log : &'a mut SiemLog, field_value : Option<SiemField>, name : &'static str) {
    match field_value {
        Some(val) => {
            log.add_field(name, SiemField::Text(Cow::Owned(val.to_string())));
        },
        None => {}
    };
}

fn get_ip_field<'a>(value: &'a str) -> (Option<SiemField>, Option<SiemField>, Option<SiemField>) {
    let mut pos = 0;
    let mut src_ip = None;
    let mut src_port = None;
    let mut src_intrf = None;
    for s in value.split(":") {
        match pos {
            0 => {
                let ip = match ipv4_from_str(s) {
                    Ok(ip) => SiemIp::V4(ip),
                    Err(_) => match ipv6_from_str(s) {
                        Ok(ip) => SiemIp::V6(ip),
                        Err(_) => {
                            break;
                        }
                    },
                };
                src_ip = Some(SiemField::IP(ip));
            }
            1 => {
                let port = match port_to_u16(s) {
                    Ok(val) => val,
                    Err(_) => {
                        break;
                    }
                };
                src_port = Some(SiemField::U32(port as u32));
            },
            2 => {
                src_intrf = Some(SiemField::Text(Cow::Owned(s.to_string())));
            },
            _ => {
                break;
            }
        }
        pos += 1;
    }
    (src_ip, src_port, src_intrf)
}

pub fn extract_fields<'a>(message: &'a str) -> BTreeMap<Cow<'a, str>, Cow<'a, str>> {
    let mut field_map = BTreeMap::new();
    let mut start_field = 0;
    let mut end_field = 0;
    let mut start_val = 0;
    let mut found = false;
    let mut is_string = false;
    let mut last_char = ' ';
    let mut cleaned = true;
    for (i, c) in message.char_indices() {
        if !found && c.is_whitespace() {
            if !cleaned {
                start_field = 0;
                end_field = 0;
                start_val = 0;
                found = false;
                is_string = false;
                cleaned = true;
            }
        } else {
            if found {
                if end_field <= start_field {
                    if c == '=' {
                        end_field = i;
                    } else if !c.is_alphanumeric() {
                        start_field = 0;
                        end_field = 0;
                        start_val = 0;
                        found = false;
                        is_string = false;
                        cleaned = true;
                    }
                } else {
                    if start_val == 0 {
                        // Set starting pos for value
                        if c == '"' {
                            //String value
                            start_val = i + 1;
                            is_string = true;
                        } else if c.is_alphanumeric() {
                            start_val = i;
                            is_string = false;
                        } else {
                            start_field = 0;
                            end_field = 0;
                            start_val = 0;
                            found = false;
                            is_string = false;
                            cleaned = true;
                        }
                    } else {
                        //Search end pos for value
                        if is_string {
                            if c == '"' && last_char != '"' {
                                field_map.insert(
                                    Cow::Borrowed(&message[start_field..end_field]),
                                    Cow::Borrowed(&message[start_val..i]),
                                );
                                start_field = 0;
                                end_field = 0;
                                start_val = 0;
                                found = false;
                                is_string = false;
                                cleaned = true;
                            }
                        } else {
                            if c.is_whitespace() {
                                field_map.insert(
                                    Cow::Borrowed(&message[start_field..end_field]),
                                    Cow::Borrowed(&message[start_val..i]),
                                );
                                start_field = 0;
                                end_field = 0;
                                start_val = 0;
                                found = false;
                                is_string = false;
                                cleaned = true;
                            }
                        }
                    }
                }
            } else {
                if c.is_alphanumeric() {
                    start_field = i;
                    found = true;
                } else {
                    start_field = 0;
                    end_field = 0;
                    start_val = 0;
                    found = false;
                    is_string = false;
                    cleaned = true;
                }
            }
        }
        last_char = c;
    }
    field_map
}

#[cfg(test)]
mod filterlog_tests {
    use super::{extract_fields,parse_log};
    use std::borrow::Cow;
    use usiem::events::field::SiemIp;
    use usiem::events::{SiemLog};
    use usiem::events::field::SiemField;

    #[test]
    fn test_extract_fields() {
        let log = "May 11 03:28:24 10.1.99.1   id=firewall sn=HOSTNAMEFW1 time=\"2021-02-05 01:02:03 UTC\" fw=111.222.111.222 pri=6 c=1024 m=1153 msg=\"SSL VPN Traffic\" sess=\"sslvpnc\" n=1234567890 usr=\"test@usiem.com\" src=10.1.2.3:3080:X6-V80 dst=10.2.3.4:50005:X1 srcMac=9d:88:a1:7c:af:1a dstMac=5c:61:a0:81:cc:f1 proto=tcp/50005 rcvd=392 rule=\"123 (SSLVPN->NET_RRHH1)\"";
        let map = extract_fields(log);
        assert_eq!(map.get("id"), Some(&Cow::Borrowed("firewall")));
        assert_eq!(map.get("sn"), Some(&Cow::Borrowed("HOSTNAMEFW1")));
        assert_eq!(
            map.get("time"),
            Some(&Cow::Borrowed("2021-02-05 01:02:03 UTC"))
        );
        assert_eq!(map.get("fw"), Some(&Cow::Borrowed("111.222.111.222")));
        assert_eq!(map.get("pri"), Some(&Cow::Borrowed("6")));
        assert_eq!(map.get("c"), Some(&Cow::Borrowed("1024")));
        assert_eq!(map.get("m"), Some(&Cow::Borrowed("1153")));
        assert_eq!(map.get("msg"), Some(&Cow::Borrowed("SSL VPN Traffic")));
        assert_eq!(map.get("sess"), Some(&Cow::Borrowed("sslvpnc")));
        assert_eq!(map.get("n"), Some(&Cow::Borrowed("1234567890")));
        assert_eq!(map.get("usr"), Some(&Cow::Borrowed("test@usiem.com")));
        assert_eq!(map.get("src"), Some(&Cow::Borrowed("10.1.2.3:3080:X6-V80")));
        assert_eq!(map.get("dst"), Some(&Cow::Borrowed("10.2.3.4:50005:X1")));
        assert_eq!(map.get("srcMac"), Some(&Cow::Borrowed("9d:88:a1:7c:af:1a")));
        assert_eq!(map.get("dstMac"), Some(&Cow::Borrowed("5c:61:a0:81:cc:f1")));
        assert_eq!(map.get("proto"), Some(&Cow::Borrowed("tcp/50005")));
        assert_eq!(map.get("rcvd"), Some(&Cow::Borrowed("392")));
        assert_eq!(
            map.get("rule"),
            Some(&Cow::Borrowed("123 (SSLVPN->NET_RRHH1)"))
        );
        assert_eq!(map.len(), 18);
    }
    #[test]
    fn test_extract_fields_with_errors() {
        let log = "Feb 5 01:02:03 10.1.99.1 10.1.99.1 aaa= 123%= id=firewall sn=HOSTNAMEFW1 time=\"2021-02-05 01:02:03 UTC\" 123%= 123%=fw=111.222.111.222 pri=6 c=1024 m=1153 msg=\"SSL VPN Traffic\" sess=\"sslvpnc\" n=1234567890 usr=\"test@usiem.com\" src=10.1.2.3:3080:X6-V80 dst=10.2.3.4:50005:X1 srcMac=9d:88:a1:7c:af:1a dstMac=5c:61:a0:81:cc:f1 proto=tcp/50005 rcvd=392 rule=\"123 (SSLVPN->NET_RRHH1)\"";
        let map = extract_fields(log);
        assert_eq!(map.get("id"), Some(&Cow::Borrowed("firewall")));
        assert_eq!(map.get("sn"), Some(&Cow::Borrowed("HOSTNAMEFW1")));
        assert_eq!(
            map.get("time"),
            Some(&Cow::Borrowed("2021-02-05 01:02:03 UTC"))
        );
        assert_eq!(map.get("fw"), Some(&Cow::Borrowed("111.222.111.222")));
        assert_eq!(map.get("pri"), Some(&Cow::Borrowed("6")));
        assert_eq!(map.get("c"), Some(&Cow::Borrowed("1024")));
        assert_eq!(map.get("m"), Some(&Cow::Borrowed("1153")));
        assert_eq!(map.get("msg"), Some(&Cow::Borrowed("SSL VPN Traffic")));
        assert_eq!(map.get("sess"), Some(&Cow::Borrowed("sslvpnc")));
        assert_eq!(map.get("n"), Some(&Cow::Borrowed("1234567890")));
        assert_eq!(map.get("usr"), Some(&Cow::Borrowed("test@usiem.com")));
        assert_eq!(map.get("src"), Some(&Cow::Borrowed("10.1.2.3:3080:X6-V80")));
        assert_eq!(map.get("dst"), Some(&Cow::Borrowed("10.2.3.4:50005:X1")));
        assert_eq!(map.get("srcMac"), Some(&Cow::Borrowed("9d:88:a1:7c:af:1a")));
        assert_eq!(map.get("dstMac"), Some(&Cow::Borrowed("5c:61:a0:81:cc:f1")));
        assert_eq!(map.get("proto"), Some(&Cow::Borrowed("tcp/50005")));
        assert_eq!(map.get("rcvd"), Some(&Cow::Borrowed("392")));
        assert_eq!(
            map.get("rule"),
            Some(&Cow::Borrowed("123 (SSLVPN->NET_RRHH1)"))
        );
        assert_eq!(map.len(), 18);
    }
    #[test]
    fn test_parser() {
        let log = "<12>Feb 5 01:02:03 10.1.99.1 10.1.99.1 aaa= 123%= id=firewall sn=HOSTNAMEFW1 time=\"2021-02-05 01:02:03 UTC\" 123%= 123%=fw=111.222.111.222 pri=6 c=1024 m=1153 msg=\"SSL VPN Traffic\" sess=\"sslvpnc\" n=1234567890 usr=\"test@usiem.com\" src=10.1.2.3:3080:X6-V80 dst=10.2.3.4:50005:X1 srcMac=9d:88:a1:7c:af:1a dstMac=5c:61:a0:81:cc:f1 proto=tcp/50005 rcvd=392 rule=\"123 (SSLVPN->NET_RRHH1)\"";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let siem_log = parse_log(log);
        match siem_log {
            Ok(log) => {
                assert_eq!(log.service(), "firewall");
                
                assert_eq!(log.field("observer.name"), Some(&SiemField::from_str("HOSTNAMEFW1")));
                assert_eq!(log.field("source.mac"), Some(&SiemField::from_str("9d:88:a1:7c:af:1a")));
                assert_eq!(log.field("destination.mac"), Some(&SiemField::from_str("5c:61:a0:81:cc:f1")));
                //assert_eq!(log.field("observer_name"), Some(&SiemField::Text(Cow::Borrowed("HOSTNAMEFW1"))));
            },
            Err(_) => assert_eq!(1,0)
        }
        /*
        assert_eq!(map.get("id"), Some(&Cow::Borrowed("firewall")));
        assert_eq!(map.get("sn"), Some(&Cow::Borrowed("HOSTNAMEFW1")));
        assert_eq!(
            map.get("time"),
            Some(&Cow::Borrowed("2021-02-05 01:02:03 UTC"))
        );
        assert_eq!(map.get("fw"), Some(&Cow::Borrowed("111.222.111.222")));
        assert_eq!(map.get("pri"), Some(&Cow::Borrowed("6")));
        assert_eq!(map.get("c"), Some(&Cow::Borrowed("1024")));
        assert_eq!(map.get("m"), Some(&Cow::Borrowed("1153")));
        assert_eq!(map.get("msg"), Some(&Cow::Borrowed("SSL VPN Traffic")));
        assert_eq!(map.get("sess"), Some(&Cow::Borrowed("sslvpnc")));
        assert_eq!(map.get("n"), Some(&Cow::Borrowed("1234567890")));
        assert_eq!(map.get("usr"), Some(&Cow::Borrowed("test@usiem.com")));
        assert_eq!(map.get("src"), Some(&Cow::Borrowed("10.1.2.3:3080:X6-V80")));
        assert_eq!(map.get("dst"), Some(&Cow::Borrowed("10.2.3.4:50005:X1")));
        assert_eq!(map.get("srcMac"), Some(&Cow::Borrowed("9d:88:a1:7c:af:1a")));
        assert_eq!(map.get("dstMac"), Some(&Cow::Borrowed("5c:61:a0:81:cc:f1")));
        assert_eq!(map.get("proto"), Some(&Cow::Borrowed("tcp/50005")));
        assert_eq!(map.get("rcvd"), Some(&Cow::Borrowed("392")));
        assert_eq!(
            map.get("rule"),
            Some(&Cow::Borrowed("123 (SSLVPN->NET_RRHH1)"))
        );
        assert_eq!(map.len(), 18);
        */
    }
}
