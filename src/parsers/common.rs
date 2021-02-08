use usiem::events::protocol::NetworkProtocol;
use std::borrow::Cow;
use usiem::events::firewall::{FirewallEvent, FirewallOutcome};
use usiem::events::field::{SiemField, SiemIp};
use usiem::events::{SiemLog};
use usiem::utilities::ip_utils::{port_to_u16};
use usiem::events::common::{WebProtocol, HttpMethod};
use usiem::events::webproxy::{WebProxyEvent,WebProxyOutcome,WebProxyRuleCategory};

pub fn parse_protocol(proto : &str) -> (NetworkProtocol, Option<Cow<'static, str>>) {
    let mut splt = proto.split("/");
    let net_trans = splt.next().map(|trs| parse_network_transport(trs)).unwrap_or(NetworkProtocol::UNKNOWN);
    let net_proto = splt.next().map(|prt| {
        if prt.chars().next().map(|c| !c.is_numeric()).unwrap_or(false){
            Some(Cow::Owned(prt.to_string()))
        }else{
            None
        }
    }).unwrap_or(None);
    (net_trans, net_proto)
}

pub fn parse_network_transport(protocol : &str) -> NetworkProtocol {
    match protocol {
        "tcp" => NetworkProtocol::TCP,
        "udp" => NetworkProtocol::UDP,
        _ => NetworkProtocol::OTHER(Cow::Owned(protocol.to_uppercase())),
    }
}
pub fn parse_network_protocol(protocol : &str) -> WebProtocol {
    match protocol {
        "http" => WebProtocol::HTTP,
        "https" => WebProtocol::HTTPS,
        _ => WebProtocol::UNKNOWN(protocol.to_uppercase()),
    }
}

pub fn firewall_event(source_ip : Option<SiemIp>,source_port : Option<u16>,source_if : Cow<'static,str>, destination_ip : Option<SiemIp>, destination_port : Option<u16>,destination_if : Cow<'static,str>, network_protocol : NetworkProtocol, outcome : FirewallOutcome, in_bytes : u32, out_bytes : u32) -> Option<FirewallEvent> {
    match (source_ip,source_port,destination_ip,destination_port) {
        (Some(source_ip),Some(source_port),Some(destination_ip),Some(destination_port)) => {
            Some(FirewallEvent {
                destination_ip,
                destination_port,
                source_ip,
                source_port,
                in_bytes : in_bytes,
                out_bytes : out_bytes,
                in_interface : source_if,
                out_interface : destination_if,
                outcome : outcome,
                network_protocol
            })
        },
        _ => None
    }
}

pub fn webproxy_event(source_ip : Option<SiemIp>,url : Cow<'static,str>, destination_ip : Option<SiemIp>, destination_port : Option<u16>,domain : Cow<'static,str>, protocol : WebProtocol, outcome : WebProxyOutcome, in_bytes : u32, out_bytes : u32,user_name : Cow<'static,str>,mime_type : Cow<'static,str>, rule_name : Option<Cow<'static,str>>, rule_category : Option<WebProxyRuleCategory>,http_code : u32, http_method : HttpMethod) -> Option<WebProxyEvent> {
    match (source_ip,destination_ip,destination_port) {
        (Some(source_ip),Some(destination_ip),Some(destination_port)) => {
            Some(WebProxyEvent {
                source_ip,
                destination_ip,
                destination_port,
                in_bytes,
                out_bytes,
                http_code,
                http_method,
                url,
                domain,
                protocol,
                user_name,
                mime_type,
                outcome,
                rule_name,
                rule_category
            })
        },
        _ => None
    }
}


pub fn add_value_or_not<'a>(
    log: &'a mut SiemLog,
    field_value: Option<&&'a str>,
    name: &'static str,
) {
    match field_value {
        Some(val) => {
            log.add_field(name, SiemField::Text(Cow::Owned((*val).to_string())));
        }
        None => {}
    };
}


pub fn get_ip_values<'a>(value: &'a str) -> (Option<SiemIp>, Option<u16>, Option<Cow<'static, str>>) {
    let mut pos = 0;
    let mut src_ip = None;
    let mut src_port = None;
    let mut src_intrf = None;
    for s in value.split(":") {
        match pos {
            0 => {
                src_ip = match SiemIp::from_ip_str(s.to_string()) {
                    Ok(ip) => Some(ip),
                    Err(_) => None,
                };
            }
            1 => {
                let port = match port_to_u16(s) {
                    Ok(val) => val,
                    Err(_) => {
                        break;
                    }
                };
                src_port = Some(port);
            }
            2 => {
                src_intrf = Some(Cow::Owned(s.to_string()));
            }
            _ => {
                break;
            }
        }
        pos += 1;
    }
    (src_ip, src_port, src_intrf)
}

pub fn http_operation(operation : &str) -> HttpMethod {
    match operation {
        "0" => HttpMethod::OPTIONS, //NO OPERATION
        "1" => HttpMethod::GET,
        "2" => HttpMethod::POST,
        "3" => HttpMethod::UNKNOWN("HEAD".to_owned()),
        _ => HttpMethod::OPTIONS
    }
}
