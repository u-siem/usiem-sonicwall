use std::borrow::Cow;
use std::collections::BTreeMap;
use usiem::events::field::SiemField;
use usiem::events::field_dictionary;
use usiem::events::firewall::FirewallOutcome;
use usiem::events::protocol::NetworkProtocol;
use usiem::events::{SiemEvent, SiemLog};

use super::common::{add_value_or_not, firewall_event, get_ip_values, parse_protocol};

pub fn is_firewall_event(ec: u32) -> bool {
    [
        36, 38, 41, 173, 174, 175, 522, 524, 526, 533, 534, 1024, 652, 1235, 1253, 1254, 1257,
        1447, 262144,
    ]
    .contains(&ec)
        || [64, 128, 256, 1024, 2048, 4096, 8192, 262144].contains(&ec)//Legacy
}

pub fn sonicwall_firewall<'a>(
    field_map: BTreeMap<&'a str, &'a str>,
    mut log: SiemLog,
) -> Result<SiemLog, SiemLog> {
    let user_name = field_map.get("usr").map(|v| v.to_string());
    add_value_or_not(&mut log, field_map.get("srcMac"), "source.mac");
    add_value_or_not(&mut log, field_map.get("dstMac"), "destination.mac");

    let (source_ip, source_port, source_interface) = match field_map.get("src") {
        Some(val) => {
            //add_field_or_not(&mut log, src_ip, "source.ip");
            //add_field_or_not(&mut log, src_port, "source.port");
            //add_field_or_not(&mut log, src_intrf, "source.interface");
            get_ip_values(val)
        }
        None => (None, None, None),
    };
    let source_interface = match source_interface {
        Some(val) => val,
        None => Cow::Borrowed(""),
    };
    let (destination_ip, destination_port, destination_interface) = match field_map.get("dst") {
        Some(val) => get_ip_values(val),
        None => (None, None, None),
    };
    let destination_interface = match destination_interface {
        Some(val) => val,
        None => Cow::Borrowed(""),
    };

    let (network_transport, network_protocol) = field_map
        .get("proto")
        .map(|proto| parse_protocol(proto))
        .unwrap_or((NetworkProtocol::UNKNOWN, None));

    let in_bytes = field_map
        .get("rcvd")
        .map(|v| v.parse::<u32>().unwrap_or(0))
        .unwrap_or(0);
    let out_bytes = field_map
        .get("sent")
        .map(|v| v.parse::<u32>().unwrap_or(0))
        .unwrap_or(0);

    match &network_protocol {
        Some(network_protocol) => {
            log.add_field(
                field_dictionary::NETWORK_PROTOCOL,
                SiemField::from_str(network_protocol.to_string()),
            );
        }
        None => {}
    };
    let event_code = field_map
        .get("c")
        .map(|c| c.parse::<u32>().unwrap_or(0))
        .unwrap_or(0);
    let event_subcode = field_map
        .get("m")
        .map(|c| c.parse::<u32>().unwrap_or(0))
        .unwrap_or(0);

    let mut event_outcome = match event_code {
        ec if [526, 1235].contains(&ec) => FirewallOutcome::ALLOW,
        ec if [
            36, 38, 41, 173, 174, 175, 522, 524, 533, 534, 652, 1253, 1254, 1257, 1447,
        ]
        .contains(&ec) =>
        {
            FirewallOutcome::BLOCK
        }
        262144 => FirewallOutcome::OPEN,
        _ => FirewallOutcome::ALLOW,
    };
    if event_code == 1024 {
        if event_subcode == 1153 || event_subcode == 1463 {
            event_outcome = FirewallOutcome::STATS;
        }
    }
    let event = firewall_event(
        source_ip.clone(),
        source_port,
        source_interface.clone(),
        destination_ip.clone(),
        destination_port,
        destination_interface.clone(),
        network_transport.clone(),
        event_outcome,
        in_bytes,
        out_bytes,
    );
    match event {
        Some(event) => {
            log.set_event(SiemEvent::Firewall(event));
        }
        None => {}
    };
    match user_name {
        Some(val) => {
            log.add_field(field_dictionary::USER_NAME, SiemField::User(val));
        }
        None => {}
    };
    Ok(log)
}
