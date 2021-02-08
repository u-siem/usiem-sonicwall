use usiem::events::{SiemLog};
use usiem::events::field::SiemField;
use std::collections::BTreeMap;
use super::common::{get_ip_values};
use std::borrow::Cow;
use usiem::events::field_dictionary;

pub fn sonicwall_default<'a>(
    field_map: BTreeMap<&'a str, &'a str>,
    mut log: SiemLog,
) -> Result<SiemLog, SiemLog> {

    let (source_ip, source_port, source_interface) = match field_map.get("src") {
        Some(val) => {
            get_ip_values(val)
        }
        None => (None, None, None),
    };
    match source_ip {
        Some(ip) => {log.add_field(field_dictionary::SOURCE_IP, SiemField::IP(ip));},
        None =>  {}
    };
    match source_port {
        Some(port) => {log.add_field(field_dictionary::SOURCE_PORT, SiemField::U32(port as u32));},
        None =>  {}
    };
    match source_interface {
        Some(source_interface) => {log.add_field(field_dictionary::IN_INTERFACE, SiemField::Text(Cow::Owned(source_interface.to_string())));},
        None =>  {}
    };
    let (destination_ip, destination_port, destination_interface) = match field_map.get("dst") {
        Some(val) => get_ip_values(val),
        None => (None, None, None),
    };

    match destination_ip {
        Some(ip) => {log.add_field(field_dictionary::DESTINATION_IP, SiemField::IP(ip));},
        None =>  {}
    };
    match destination_port {
        Some(port) => {log.add_field(field_dictionary::DESTINATION_PORT, SiemField::U32(port as u32));},
        None =>  {}
    };
    match destination_interface {
        Some(destination_interface) => {log.add_field(field_dictionary::OUT_INTERFACE, SiemField::Text(Cow::Owned(destination_interface.to_string())));},
        None =>  {}
    };
    let in_bytes = field_map
        .get("rcvd")
        .map(|v| v.parse::<u32>().unwrap_or(0));
    let out_bytes = field_map
        .get("sent")
        .map(|v| v.parse::<u32>().unwrap_or(0));
    match in_bytes {
        Some(in_bytes) => {log.add_field(field_dictionary::DESTINATION_BYTES, SiemField::U64(in_bytes as u64))},
        None => {}
    };
    match out_bytes {
        Some(out_bytes) => {log.add_field(field_dictionary::SOURCE_BYTES, SiemField::U64(out_bytes as u64))},
        None => {}
    };

    //TODO: More fields to index

    for (key,value) in field_map.iter() {
        if ["msg","sess","srcMac","dstMac"].contains(key) {
            //TEXT type
            let key = mapped_keys(key);
            match key {
                Some(key) => log.add_field(key, SiemField::from_str(value.to_string())),
                None => {}
            }

        }else if ["usr"].contains(key) {
            let key = mapped_keys(key);
            match key {
                Some(key) => log.add_field(key, SiemField::User(value.to_string())),
                None => {}
            }
        }
    }
    return Ok(log)
}


fn mapped_keys(key : &str) -> Option<&'static str> {
    match key {
        "msg" => Some("event.original"),
        "sess" => Some("event.dataset"),
        "usr" => Some("user.name"),
        "srcMac" => Some("source.mac"),
        "dstMac" => Some("destination.mac"),
        _ => None
    }
}