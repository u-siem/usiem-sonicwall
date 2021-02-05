use std::borrow::Cow;
use std::collections::BTreeMap;

pub fn extract_fields<'a>(message: &'a str) -> BTreeMap<Cow<'a, str>, Cow<'a, str>> {
    let mut field_map = BTreeMap::default();
    let mut start_field = 0;
    let mut end_field = 0;
    let mut start_val = 0;
    let mut found = false;
    let mut is_string = false;
    let mut last_char = ' ';
    for (i, c) in message.char_indices() {
        if !found && c.is_whitespace() {
            start_field = 0;
            end_field = 0;
            start_val = 0;
            found = false;
            is_string = false;
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
                        } else {
                            start_field = 0;
                            end_field = 0;
                            start_val = 0;
                            found = false;
                            is_string = false;
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
                }
            }
        }
        last_char = c;
    }
    field_map
}

#[cfg(test)]
mod filterlog_tests {
    use super::{extract_fields};
    use std::borrow::Cow;
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
        let log = "May 11 03:28:24 10.1.99.1 aaa= 123%= id=firewall sn=HOSTNAMEFW1 time=\"2021-02-05 01:02:03 UTC\" 123%= 123%=fw=111.222.111.222 pri=6 c=1024 m=1153 msg=\"SSL VPN Traffic\" sess=\"sslvpnc\" n=1234567890 usr=\"test@usiem.com\" src=10.1.2.3:3080:X6-V80 dst=10.2.3.4:50005:X1 srcMac=9d:88:a1:7c:af:1a dstMac=5c:61:a0:81:cc:f1 proto=tcp/50005 rcvd=392 rule=\"123 (SSLVPN->NET_RRHH1)\"";
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
}
