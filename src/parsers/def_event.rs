use usiem::events::{SiemLog};
use usiem::events::field::SiemField;
use std::collections::BTreeMap;
use super::common::{get_ip_values,common_extractor};
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

    //TODO: More fields to index

    let log = common_extractor(field_map, log);
    return Ok(log)
}