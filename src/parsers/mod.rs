use chrono::prelude::{TimeZone, Utc};
use std::borrow::Cow;
use std::collections::BTreeMap;
use usiem::events::field::{SiemField, SiemIp};
use usiem::events::field_dictionary;
use usiem::events::SiemLog;

pub mod common;
mod firewall;
pub mod proxy_category;
use firewall::{is_firewall_event, sonicwall_firewall};
mod def_event;
use def_event::sonicwall_default;
mod webproxy;
use webproxy::sonicwall_webproxy;

//TODO: Improve CORE features: ParseError=[MismatchedDevice, ParserError, LogFormatError]
// MismatchedDevice -> Indicate that the log is not generated by this kind of device
// ParserError -> Maybe the format of the logs has changed (Product Updated?) Typical in Symantec products
// LogFormatError -> The parser tells that there are errors in this logs
pub fn parse_log(log: SiemLog) -> Result<SiemLog, SiemLog> {
    let log_line = log.message();
    let start_log_pos = match log_line.find(" id=") {
        Some(val) => val + 1,
        None => return Err(log),
    };
    let syslog_header = &log_line[0..start_log_pos];
    let log_content = &log_line[start_log_pos..];

    let mut syslog_hdr_content = Vec::new();
    let syslog_start = match syslog_header.find(">") {
        Some(val) => val,
        None => return Err(log),
    };
    syslog_hdr_content.push(&syslog_header[1..syslog_start]); //Add <XXX>
    let mut last_pos = 0;
    let init_pos = syslog_start + 1;
    for (pos, c) in syslog_header[init_pos..].char_indices() {
        if c == ' ' {
            syslog_hdr_content.push(&syslog_header[(init_pos + last_pos)..(init_pos + pos)]);
            last_pos = pos + 1;
        }
    }
    let origin = log.origin().clone();
    let mut observer_name: Option<SiemField> = None;
    let mut observer_ip: Option<SiemIp> = None;
    match syslog_hdr_content.get(4) {
        Some(val1) => match SiemIp::from_ip_str(*val1) {
            Ok(val_ip) => {
                observer_ip = Some(val_ip);
            }
            Err(_) => observer_name = Some(SiemField::from_str((*val1).to_string())),
        },
        _ => {}
    };
    match syslog_hdr_content.get(5) {
        Some(val1) => match SiemIp::from_ip_str(*val1) {
            Ok(val_ip) => {
                observer_ip = Some(val_ip);
            }
            Err(_) => observer_name = Some(SiemField::from_str((*val1).to_string())),
        },
        _ => {}
    };
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
    let observer_id = match field_map.get("sn") {
        Some(val) => val.to_string(),
        None => return Err(log),
    };

    let mut log = match observer_ip {
        Some(observer_ip) => {
            SiemLog::new(log_content.to_owned(), log.event_received(), observer_ip)
        }
        None => SiemLog::new(log_content.to_owned(), log.event_received(), origin),
    };
    log.set_event_created(event_created);
    log.set_vendor(Cow::Borrowed("SonicWall"));
    log.set_product(Cow::Borrowed("SonicWall"));
    log.set_service(Cow::Owned(service));
    log.set_category(Cow::Borrowed("Firewall"));
    log.add_field("observer.id", SiemField::Text(Cow::Owned(observer_id)));
    match observer_name {
        Some(val) => {
            log.add_field("observer.name", val);
        }
        None => {}
    };

    sonicwall_event_selector(field_map, log)
}

fn sonicwall_event_selector<'a>(
    field_map: BTreeMap<&'a str, &'a str>,
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

    let event_code = field_map
        .get("c")
        .map(|c| c.parse::<u32>().unwrap_or(0))
        .unwrap_or(0);
    let event_subcode = field_map
        .get("m")
        .map(|m| m.parse::<u32>().unwrap_or(0))
        .unwrap_or(0);
    log.add_field(field_dictionary::EVENT_CODE, SiemField::U32(event_code));
    log.add_field("event.subcode", SiemField::U32(event_subcode));

    match event_code {
        1024 => {
            //Traffic info
            match event_subcode {
                97 => {
                    //URL Traffic
                    return sonicwall_webproxy(field_map, log);
                }
                537 => {
                    //Normal Traffic
                    return sonicwall_firewall(field_map, log);
                }
                1153 => {
                    //VPN Traffic
                    return sonicwall_firewall(field_map, log);
                }
                _ => {
                    //TODO
                    return sonicwall_default(field_map, log);
                }
            }
        }
        ec if is_firewall_event(ec) => {
            return sonicwall_firewall(field_map, log);
        }
        _ => {
            //TODO
            return sonicwall_default(field_map, log);
        }
    }
}

pub fn extract_fields<'a>(message: &'a str) -> BTreeMap<&'a str, &'a str> {
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
                        } else if !c.is_whitespace() {
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
                                    &message[start_field..end_field],
                                    &message[start_val..i],
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
                                    &message[start_field..end_field],
                                    &message[start_val..i],
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
    use super::{extract_fields, parse_log};
    use usiem::events::field::SiemField;
    use usiem::events::field::SiemIp;
    use usiem::events::{SiemEvent, SiemLog};
    use usiem::utilities::ip_utils::ipv4_from_str;

    #[test]
    fn test_extract_fields() {
        let log = "May 11 03:28:24 10.1.99.1   id=firewall sn=SERIALNUMBER111 time=\"2021-02-05 01:02:03 UTC\" fw=111.222.111.222 pri=6 c=1024 m=1153 msg=\"SSL VPN Traffic\" sess=\"sslvpnc\" n=1234567890 usr=\"test@usiem.com\" src=10.1.2.3:3080:X6-V80 dst=10.2.3.4:50005:X1 srcMac=98:90:96:de:f1:78 dstMac=ec:f4:bb:fb:f7:f6 proto=tcp/50005 rcvd=392 rule=\"123 (SSLVPN->NET_RRHH1)\"";
        let map = extract_fields(log);
        assert_eq!(map.get("id"), Some(&"firewall"));
        assert_eq!(map.get("sn"), Some(&"SERIALNUMBER111"));
        assert_eq!(map.get("time"), Some(&"2021-02-05 01:02:03 UTC"));
        assert_eq!(map.get("fw"), Some(&"111.222.111.222"));
        assert_eq!(map.get("pri"), Some(&"6"));
        assert_eq!(map.get("c"), Some(&"1024"));
        assert_eq!(map.get("m"), Some(&"1153"));
        assert_eq!(map.get("msg"), Some(&"SSL VPN Traffic"));
        assert_eq!(map.get("sess"), Some(&"sslvpnc"));
        assert_eq!(map.get("n"), Some(&"1234567890"));
        assert_eq!(map.get("usr"), Some(&"test@usiem.com"));
        assert_eq!(map.get("src"), Some(&"10.1.2.3:3080:X6-V80"));
        assert_eq!(map.get("dst"), Some(&"10.2.3.4:50005:X1"));
        assert_eq!(map.get("srcMac"), Some(&"98:90:96:de:f1:78"));
        assert_eq!(map.get("dstMac"), Some(&"ec:f4:bb:fb:f7:f6"));
        assert_eq!(map.get("proto"), Some(&"tcp/50005"));
        assert_eq!(map.get("rcvd"), Some(&"392"));
        assert_eq!(map.get("rule"), Some(&"123 (SSLVPN->NET_RRHH1)"));
        assert_eq!(map.len(), 18);
    }
    #[test]
    fn test_extract_fields_with_errors() {
        let log = "Feb 5 01:02:03 10.1.99.1 10.1.99.1 aaa= 123%= id=firewall sn=SERIALNUMBER111 time=\"2021-02-05 01:02:03 UTC\" 123%= 123%=fw=111.222.111.222 pri=6 c=1024 m=1153 msg=\"SSL VPN Traffic\" sess=\"sslvpnc\" n=1234567890 usr=\"test@usiem.com\" src=10.1.2.3:3080:X6-V80 dst=10.2.3.4:50005:X1 srcMac=98:90:96:de:f1:78 dstMac=ec:f4:bb:fb:f7:f6 proto=tcp/50005 rcvd=392 rule=\"123 (SSLVPN->NET_RRHH1)\"";
        let map = extract_fields(log);
        assert_eq!(map.get("id"), Some(&"firewall"));
        assert_eq!(map.get("sn"), Some(&"SERIALNUMBER111"));
        assert_eq!(map.get("time"), Some(&"2021-02-05 01:02:03 UTC"));
        assert_eq!(map.get("fw"), Some(&"111.222.111.222"));
        assert_eq!(map.get("pri"), Some(&"6"));
        assert_eq!(map.get("c"), Some(&"1024"));
        assert_eq!(map.get("m"), Some(&"1153"));
        assert_eq!(map.get("msg"), Some(&"SSL VPN Traffic"));
        assert_eq!(map.get("sess"), Some(&"sslvpnc"));
        assert_eq!(map.get("n"), Some(&"1234567890"));
        assert_eq!(map.get("usr"), Some(&"test@usiem.com"));
        assert_eq!(map.get("src"), Some(&"10.1.2.3:3080:X6-V80"));
        assert_eq!(map.get("dst"), Some(&"10.2.3.4:50005:X1"));
        assert_eq!(map.get("srcMac"), Some(&"98:90:96:de:f1:78"));
        assert_eq!(map.get("dstMac"), Some(&"ec:f4:bb:fb:f7:f6"));
        assert_eq!(map.get("proto"), Some(&"tcp/50005"));
        assert_eq!(map.get("rcvd"), Some(&"392"));
        assert_eq!(map.get("rule"), Some(&"123 (SSLVPN->NET_RRHH1)"));
        assert_eq!(map.len(), 18);
    }
    #[test]
    fn test_parser() {
        let log = "<12>Feb 5 01:02:03 10.1.99.1 10.1.99.1 aaa= 123%= id=firewall sn=SERIALNUMBER111 time=\"2021-02-05 01:02:03 UTC\" 123%= 123%=fw=111.222.111.222 pri=6 c=1024 m=1153 msg=\"SSL VPN Traffic\" sess=\"sslvpnc\" n=1234567890 usr=\"test@usiem.com\" src=10.1.2.3:3080:X6-V80 dst=10.2.3.4:50005:X1 srcMac=98:90:96:de:f1:78 dstMac=ec:f4:bb:fb:f7:f6 proto=tcp/50005 rcvd=392 rule=\"123 (SSLVPN->NET_RRHH1)\"";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let siem_log = parse_log(log);
        match siem_log {
            Ok(log) => {
                assert_eq!(log.service(), "firewall");

                assert_eq!(
                    log.field("observer.id"),
                    Some(&SiemField::from_str("SERIALNUMBER111"))
                );
                assert_eq!(log.field("observer.name"), None);
                assert_eq!(
                    log.origin(),
                    &SiemIp::V4(ipv4_from_str("10.1.99.1").unwrap())
                );
                assert_eq!(
                    log.field("source.mac"),
                    Some(&SiemField::from_str("98:90:96:de:f1:78"))
                );
                assert_eq!(
                    log.field("destination.mac"),
                    Some(&SiemField::from_str("ec:f4:bb:fb:f7:f6"))
                );
                assert_eq!(
                    log.field("source.ip"),
                    Some(&SiemField::IP(SiemIp::V4(
                        ipv4_from_str("10.1.2.3").unwrap()
                    )))
                );
                assert_eq!(
                    log.field("destination.ip"),
                    Some(&SiemField::IP(SiemIp::V4(
                        ipv4_from_str("10.2.3.4").unwrap()
                    )))
                );
            }
            Err(_) => assert_eq!(1, 0),
        }
    }
    #[test]
    fn test_parser_2() {
        let log = "<12>Feb 5 01:02:03 FWSonicWall 10.1.99.1 aaa= 123%= id=firewall sn=SERIALNUMBER111 time=\"2021-02-05 01:02:03 UTC\" 123%= 123%=fw=111.222.111.222 pri=6 c=1024 m=1153 msg=\"SSL VPN Traffic\" sess=\"sslvpnc\" n=1234567890 usr=\"test@usiem.com\" src=10.1.2.3:3080:X6-V80 dst=10.2.3.4:50005:X1 srcMac=98:90:96:de:f1:78 dstMac=ec:f4:bb:fb:f7:f6 proto=tcp/50005 rcvd=392 rule=\"123 (SSLVPN->NET_RRHH1)\"";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let siem_log = parse_log(log);
        match siem_log {
            Ok(log) => {
                assert_eq!(log.service(), "firewall");

                assert_eq!(
                    log.field("observer.id"),
                    Some(&SiemField::from_str("SERIALNUMBER111"))
                );
                assert_eq!(
                    log.field("observer.name"),
                    Some(&SiemField::from_str("FWSonicWall"))
                );
                assert_eq!(
                    log.origin(),
                    &SiemIp::V4(ipv4_from_str("10.1.99.1").unwrap())
                );
                assert_eq!(
                    log.field("source.mac"),
                    Some(&SiemField::from_str("98:90:96:de:f1:78"))
                );
                assert_eq!(
                    log.field("destination.mac"),
                    Some(&SiemField::from_str("ec:f4:bb:fb:f7:f6"))
                );
                assert_eq!(
                    log.field("source.ip"),
                    Some(&SiemField::IP(SiemIp::V4(
                        ipv4_from_str("10.1.2.3").unwrap()
                    )))
                );
                assert_eq!(
                    log.field("destination.ip"),
                    Some(&SiemField::IP(SiemIp::V4(
                        ipv4_from_str("10.2.3.4").unwrap()
                    )))
                );
            }
            Err(_) => assert_eq!(1, 0),
        }
    }

    #[test]
    fn test_parser_web_connection() {
        let log = "<134>Feb 5 01:02:03 FWSonicWall 10.1.99.1 id=firewall sn=18B1690729A8 time=\"2016-06-16 17:21:40 UTC\" fw=10.205.123.15 pri=6 c=1024 m=97 app=48 n=9 src=192.168.168.10:52589:X0 dst=69.192.240.232:443:X1:a69-192-240-232.deploy.akamaitechnologies.com srcMac=98:90:96:de:f1:78 dstMac=ec:f4:bb:fb:f7:f6 proto=tcp/https op=1 sent=798 rcvd=12352 result=403 dstname=www.suntrust.com arg=/favicon.ico code=20 Category=\"Online Banking\"";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let siem_log = parse_log(log);
        match siem_log {
            Ok(log) => {
                assert_eq!(log.service(), "firewall");

                assert_eq!(
                    log.field("observer.id"),
                    Some(&SiemField::from_str("18B1690729A8"))
                );
                assert_eq!(
                    log.field("observer.name"),
                    Some(&SiemField::from_str("FWSonicWall"))
                );
                assert_eq!(
                    log.origin(),
                    &SiemIp::V4(ipv4_from_str("10.1.99.1").unwrap())
                );
                assert_eq!(
                    log.field("source.mac"),
                    Some(&SiemField::from_str("98:90:96:de:f1:78"))
                );
                assert_eq!(
                    log.field("destination.mac"),
                    Some(&SiemField::from_str("ec:f4:bb:fb:f7:f6"))
                );
                assert_eq!(
                    log.field("source.ip"),
                    Some(&SiemField::IP(
                        SiemIp::from_ip_str("192.168.168.10").unwrap()
                    ))
                );
                assert_eq!(
                    log.field("destination.ip"),
                    Some(&SiemField::IP(SiemIp::V4(
                        ipv4_from_str("69.192.240.232").unwrap()
                    )))
                );
                assert_eq!(
                    log.field("url.domain"),
                    Some(&SiemField::from_str("www.suntrust.com"))
                );
                assert_eq!(
                    log.field("url.path"),
                    Some(&SiemField::from_str("/favicon.ico"))
                );
                match log.event() {
                    SiemEvent::WebProxy(_wp) => {}
                    _ => {
                        assert_eq!("WebProxy", "Not WebProxy")
                    }
                }
            }
            Err(_) => assert_eq!(1, 0),
        }
    }

    #[test]
    fn test_parser_default() {
        let log = "<134>Feb 5 01:02:03 FWSonicWall 10.1.99.1 id=firewall sn=18B1690729A8 time=\"2016-06-16 17:21:40 UTC\" fw=10.205.123.15 pri=6 c=123456 m=231312 app=48 n=9 src=192.168.168.10:52589:X0 dst=69.192.240.232:443:X1:a69-192-240-232.deploy.akamaitechnologies.com srcMac=98:90:96:de:f1:78 dstMac=ec:f4:bb:fb:f7:f6 proto=tcp/https op=1 sent=798 rcvd=12352 result=403 dstname=www.suntrust.com arg=/favicon.ico code=20 Category=\"Online Banking\" msg=\"TEST\"";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let siem_log = parse_log(log);
        match siem_log {
            Ok(log) => {
                assert_eq!(log.service(), "firewall");

                assert_eq!(
                    log.field("observer.id"),
                    Some(&SiemField::from_str("18B1690729A8"))
                );
                assert_eq!(
                    log.field("observer.name"),
                    Some(&SiemField::from_str("FWSonicWall"))
                );
                assert_eq!(
                    log.origin(),
                    &SiemIp::V4(ipv4_from_str("10.1.99.1").unwrap())
                );
                assert_eq!(
                    log.field("source.mac"),
                    Some(&SiemField::from_str("98:90:96:de:f1:78"))
                );
                assert_eq!(
                    log.field("destination.mac"),
                    Some(&SiemField::from_str("ec:f4:bb:fb:f7:f6"))
                );
                assert_eq!(
                    log.field("source.ip"),
                    Some(&SiemField::IP(
                        SiemIp::from_ip_str("192.168.168.10").unwrap()
                    ))
                );
                assert_eq!(
                    log.field("destination.ip"),
                    Some(&SiemField::IP(SiemIp::V4(
                        ipv4_from_str("69.192.240.232").unwrap()
                    )))
                );
                assert_eq!(
                    log.field("event.original"),
                    Some(&SiemField::from_str("TEST"))
                );
                assert_eq!(log.field("url.full"), None);

                match log.event() {
                    SiemEvent::Unknown => {}
                    _ => {
                        assert_eq!("WebProxy", "Not WebProxy")
                    }
                }
            }
            Err(_) => assert_eq!(1, 0),
        }
    }
}
