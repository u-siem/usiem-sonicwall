use usiem_sonicwall::parsers;
fn main() {
    let now = std::time::Instant::now();
    for _i in 0..10_000_000{
        let log = "Feb 5 01:02:03 10.1.99.1 aaa= 123%= id=firewall sn=HOSTNAMEFW1 time=\"2021-02-05 01:02:03 UTC\" 123%= 123%=fw=111.222.111.222 pri=6 c=1024 m=1153 msg=\"SSL VPN Traffic\" sess=\"sslvpnc\" n=1234567890 usr=\"test@usiem.com\" src=10.1.2.3:3080:X6-V80 dst=10.2.3.4:50005:X1 srcMac=9d:88:a1:7c:af:1a dstMac=5c:61:a0:81:cc:f1 proto=tcp/50005 rcvd=392 rule=\"123 (SSLVPN->NET_RRHH1)\"";
        let _map = parsers::extract_fields(log);
    }

    println!("{:?} EPS",10_000_000_000 /now.elapsed().as_millis());
    
}