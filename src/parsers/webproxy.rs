use std::borrow::Cow;
use std::collections::BTreeMap;
use usiem::events::field::SiemField;
use usiem::events::field_dictionary;
use usiem::events::protocol::NetworkProtocol;
use usiem::events::{SiemEvent, SiemLog};
use usiem::events::common::{WebProtocol, HttpMethod};
use usiem::events::webproxy::{WebProxyOutcome,WebProxyRuleCategory};

use super::common::{add_value_or_not,http_operation, webproxy_event, get_ip_values, parse_protocol,parse_network_protocol};
use super::proxy_category;

pub fn sonicwall_webproxy<'a>(
    field_map: BTreeMap<&'a str, &'a str>,
    mut log: SiemLog,
) -> Result<SiemLog, SiemLog> {

    let user_name = field_map.get("usr").map(|v| v.to_string());

    add_value_or_not(&mut log, field_map.get("srcMac"), "source.mac");
    add_value_or_not(&mut log, field_map.get("dstMac"), "destination.mac");

    let (source_ip, _sp, _si) = match field_map.get("src") {
        Some(val) => {
            get_ip_values(val)
        }
        None => (None, None, None),
    };

    let (destination_ip, destination_port, _di) = match field_map.get("dst") {
        Some(val) => get_ip_values(val),
        None => (None, None, None),
    };

    let (_nt, network_protocol) = field_map
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

    let url_domain = match field_map.get("dstname") {
        Some(val) => Cow::Owned(val.to_string()),
        None => Cow::Borrowed(""),
    };
    let (url_path, url_query) = match field_map.get("arg") {
        Some(val) => {
            println!("{}", val);
            if val.starts_with("/") {
                let pos = val.find("?");
                match pos {
                    Some(pos) => {
                        log.add_field(
                            field_dictionary::URL_PATH,
                            SiemField::from_str(Cow::Owned((&val[..pos]).to_string())),
                        );
                        log.add_field(
                            field_dictionary::URL_QUERY,
                            SiemField::from_str(Cow::Owned((&val[pos..]).to_string())),
                        );
                        (
                            Cow::Owned((&val[..pos]).to_string()),
                            Cow::Owned((&val[pos..]).to_string()),
                        )
                    }
                    None => {
                        log.add_field(
                            field_dictionary::URL_PATH,
                            SiemField::from_str(Cow::Owned((&val[..]).to_string())),
                        );
                        (Cow::Owned((&val[..]).to_string()), Cow::Borrowed(""))
                    }
                }
            } else {
                (Cow::Borrowed(""), Cow::Borrowed(""))
            }
        }
        None => (Cow::Borrowed(""), Cow::Borrowed("")),
    };
    let status_code = match field_map.get("result") {
        Some(val) => match val.parse::<u32>() {
            Ok(val) => val,
            Err(_) => 0,
        },
        None => 0,
    };
    let url_full = Cow::Owned(format!("{}{}{}", url_domain, url_path, url_query));
    let http_method = field_map
        .get("op")
        .map(|op| http_operation(op))
        .unwrap_or(HttpMethod::CONNECT);
    let rule_name = field_map
        .get("Category")
        .map(|c| Cow::Owned(c.to_string()))
        .unwrap_or(Cow::Borrowed(""));
    let url_category = field_map
        .get("code")
        .map(|c| c.parse::<u32>().unwrap_or(0u32))
        .map(|c| proxy_category::web_code_category(c))
        .unwrap_or(WebProxyRuleCategory::Uncategorized);
    //TODO: WebProxy
    let web_protocol = network_protocol
        .map(|pro| parse_network_protocol(&pro))
        .unwrap_or(WebProtocol::HTTP);
    let user_name = user_name
        .map(|usr| Cow::Owned(usr.to_string()))
        .unwrap_or(Cow::Borrowed(""));

    let event = webproxy_event(
        source_ip.clone(),
        url_full,
        destination_ip.clone(),
        destination_port,
        url_domain,
        web_protocol,
        WebProxyOutcome::ALLOW,
        in_bytes,
        out_bytes,
        user_name,
        Cow::Borrowed(""),
        Some(rule_name),
        Some(url_category),
        status_code,
        http_method,
    );
    match event {
        Some(event) => {
            log.set_event(SiemEvent::WebProxy(event));
        }
        None => {}
    };
    Ok(log)
}
