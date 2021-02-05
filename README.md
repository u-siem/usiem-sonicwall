# usiem-sonicwall
uSIEM parser for SonicWall Firewall

Security related Message ID (https://www.sonicwall.com/techdocs/pdf/sonicos-6-5-1-log-events-reference-guide.pdf)
```
22  Security ServicesAttacksAttack   ALERT  501  Ping of Death BlockedPing of death dropped
23  Security ServicesAttacksAttack   ALERT  502  IP Spoof DetectedIP spoof dropped
24  Users   Authentication AccessUser Activity INFO   ---   User Disconnect DetectedUser logged out - user disconnect detected 
25  Firewall SettingsFlood ProtectionAttack   WARNING 503  Possible SYN FloodPossible SYN flood attack detected
27  Security ServicesAttacksAttack   ALERT  505  Land Attack  Land attack dropped
29  Users   Authentication AccessUser Activity INFO   ---   Successful Admin LoginAdministrator login allowed
30  Users   Authentication AccessAttack   ALERT  560  Wrong Admin PasswordAdministrator login denied due to bad credentials
31  Users   Authentication AccessUser Activity INFO   ---   Successful User LoginUser login from an internal zone allowed
32  Users   Authentication AccessUser Activity INFO   ---   Wrong User Password User login denied due to bad credentials
33  Users   Authentication AccessUser Activity INFO   ---   Unknown User Login AttemptUser login denied due to bad credentials
34  Users   Authentication AccessUser Activity INFO   ---   Login Timeout Pending login timed out
35  Users   Authentication AccessAttack   ALERT  506  Admin Login DisabledAdministrator login denied from %s; logins disabled from this interface
36  Network  TCPTCPNOTICE  ---   TCP Packets DroppedTCP connection dropped
37  Network  UDPUDPNOTICE  ---   UDP Packets DroppedUDP packet dropped
38  Network  ICMPICMP    NOTICE  ---   ICMP Packets DroppedICMP packet dropped due to Policy
41  Network  Network Access Debug   NOTICE  ---   Unknown Protocol DroppedUnknown protocol dropped
67  VPN   VPN IPsec   Attack   ERROR  508  IPsec Authenticate FailureIPsec Authentication Failed
70  VPN   VPN IPsec   Attack   ERROR  510  Illegal IPsec PeerIPsec packet from or to an illegal host
81  Security ServicesAttacksAttack   ALERT  520  Smurf Attack  Smurf Amplification attack dropped
82  Security ServicesAttacksAttack   ALERT  521  Port Scan PossiblePossible port scan detected
83  Security ServicesAttacksAttack   ALERT  522  Port Scan ProbableProbable port scan detected
98  Network  Network Access Connection INFO   ---   Connection OpenedConnection Opened
138 Network  Interfaces   System Error WARNING 636  WAN IP ChangeWan IP Changed
139 VPN   VPN Client   User Activity INFO   ---   XAUTH SuccessXAUTH Succeeded with VPN %s
140 VPN   VPN Client   User Activity ERROR  ---   XAUTH Failure XAUTH Failed with VPN %s, Authentication failure
159 Security ServicesAnti-Virus   Maintenance WARNING 526  AV Expire messageReceived AV Alert: Your Network Anti-Virus subscription has expired. %s
165 Security ServicesE-mail Filtering Attack   ALERT  527  Allow E-mail AttachmentForbidden E-Mail attachment disabled
173 Network  TCPLAN TCP   NOTICE  ---   LAN TCP Deny TCP connection from LAN denied
174 Network  UDPLAN UDP | LAN TCPNOTICE  ---   LAN UDP Deny UDP packet from LAN dropped
175 Network  ICMPLAN ICMP | LAN TCPNOTICE  ---   LAN ICMP DenyICMP packet from LAN dropped
177 Security ServicesAttacksAttack   ALERT  528  TCP FIN Scan  Probable TCP FIN scan detected
178 Security ServicesAttacksAttack   ALERT  529  TCP Xmas Scan Probable TCP XMAS scan detected
179 Security ServicesAttacksAttack   ALERT  530  TCP Null Scan Probable TCP NULL scan detected
181 Network  TCPDebug   DEBUG  ---   TCP FIN Drop TCP FIN packet dropped
199 Users   Authentication AccessUser Activity INFO   ---   Admin Login From CLICLI administrator login allowed
200 Users   Authentication AccessUser Activity WARNING ---   Admin Password Error From CLICLI administrator login denied due to bad credentials
212 Network  L2TP Client   Maintenance INFO   ---   L2TP PPP Authenticate FailedL2TP PPP Authentication Failed
229 VPN   DHCP Relay   Attack   ERROR  533  DHCPR IP SpoofIP spoof detected on packet to Central Gateway, packet dropped
235 Users   Authentication AccessUser Activity INFO   ---   Admin VPN LoginVPN zone administrator login allowed
236 Users   Authentication AccessUser Activity INFO   ---   Admin WAN LoginWAN zone administrator login allowed
237 Users   Authentication AccessUser Activity INFO   ---   User VPN LoginVPN zone remote user login allowed
238 Users   Authentication AccessUser Activity INFO   ---   User WAN LoginWAN zone remote user login allowed
243 Users   Radius AuthenticationUser Activity INFO   ---   User Login FailedUser login denied - RADIUS authentication failure
244 Users   Radius AuthenticationUser Activity WARNING ---   User Login TimeoutUser login denied - RADIUS server Timeout
245 Users   Radius AuthenticationUser Activity WARNING ---   User Login ErrorUser login denied - RADIUS configuration error
246 Users   Authentication AccessUser Activity INFO   ---   User Login From Wrong LocationUser login denied - User has no privileges for login from that location
248 Security ServicesE-mail Filtering Attack   ERROR  534  E-mail AttachmentForbidden E-Mail attachment deleted
267 Security ServicesAttacksAttack   ALERT  547  TCP Xmas Tree AttackTCP Xmas Tree dropped
289 Network  PPP---INFO   ---   PPP Authenticate SuccessPPP: Authentication successful
290 Network  PPP---INFO   ---   PPP PAP Failed PPP: PAP Authentication failed - check username / password
291 Network  PPP---INFO   ---   PPP CHAP FailedPPP: CHAP authentication failed - check username / password
292 Network  PPP---INFO   ---   PPP MS-CHAP FailedPPP: MS-CHAP authentication failed - check username / password
311 VPN   L2TP Server  Maintenance INFO   ---   L2TP Radius Authentication FailureL2TP Server:  RADIUS/LDAP reports Authentication Failure
312 VPN   L2TP Server  Maintenance INFO   ---   L2TP Local Authentication FailureL2TP Server:  Local  Authentication Failure
318 VPN   L2TP Server  Maintenance INFO   ---   L2TP Local Authentication SuccessL2TP Server:  Local  Authentication Success.
319 VPN   L2TP Server  Maintenance INFO   ---   L2TP Radius Authentication SuccessL2TP Server:  RADIUS/LDAP Authentication Success
329 Users   Authentication AccessAttack   ERROR  561  User Login LockoutUser login failure rate exceeded - logins from user IP address denied
336 VPN   L2TP Server  Maintenance INFO   ---   L2TPS Tunnel DeleteL2TP Server : Deleting the Tunnel
344 VPN   L2TP Server  Maintenance INFO   ---   L2TPS Authentication Local FailureL2TP Server : User  Name authentication Failure locally
408 Security ServicesAnti-Virus   Maintenance INFO   ---   AV License ExceededAnti-Virus Licenses Exceeded
438 Users   Authentication AccessUser Activity INFO   ---   User Login Lockout ExpiredLocked-out user logins allowed - lockout period expired
439 Users   Authentication AccessUser Activity INFO   ---   User Login Lockout Clear Locked-out user logins allowed by %s
440 Firewall  Access Rules  User Activity INFO   ---   Rule Added  Access rule added
441 Firewall  Access Rules  User Activity INFO   ---   Rule Modified Access rule viewed or modified
442 Firewall  Access Rules  User Activity INFO   ---   Rule Deleted  Access rule deleted
446 Firewall SettingsFTPAttack   ERROR  551  FTP Passive AttackFTP: PASV response spoof attack dropped
452 VPN   VPN PKI    Maintenance ERROR  ---   PKI Bad PasswordPKI Failure: Incorrect admin password
465 VPN   VPN PKI    Maintenance ERROR  ---   PKI Certificate ExpirePKI Failure: Certificate expiration
473 VPN   DHCP Relay   Debug   INFO   ---   Remote: DHCP RequestDHCP REQUEST received from remote device
474 VPN   DHCP Relay   Debug   INFO   ---   Remote: DHCP DiscoverDHCP DISCOVER received from remote devic
476 VPN   DHCP Relay   Debug   INFO   ---   Server: DHCP OfferDHCP OFFER received from server
482 Security ServicesAnti-Virus   Maintenance WARNING 552  AV Expiration WarningReceived AV Alert: Your Network Anti-Virus subscription will expire in 7 days. %s
486 Users   Authentication AccessUser Activity INFO   ---   WLAN User Login DenyUser login denied - User has no privileges for guest service
491 Security ServicesE-mail Filtering Maintenance WARNING 564  E-mail Filtering Expiration WarningReceived E-Mail Filter Alert: Your E-Mail Filtering subscription will expire in 7 days.
492 Security ServicesE-mail Filtering Maintenance WARNING 565  E-mail Filtering Expiration MessageReceived E-Mail Filter Alert: Your E-Mail Filtering subscription has expired
506 Users   Authentication AccessMaintenance INFO   ---   VPN Disabled VPN disabled by administrator
507 Users   Authentication AccessMaintenance INFO   ---   VPN Enabled VPN enabled by administrator
508 Users   Authentication AccessMaintenance INFO   ---   WLAN DisabledWLAN disabled by administrator
509 Users   Authentication AccessMaintenance INFO   ---   WLAN Enabled WLAN enabled by administrator
566 Network  Interfaces   System Error ALERT  647  Multi-Interface Link DownInterface %s Link Is Down
575 System  Hardware   System EnvironmentERROR  101  Voltages Out of ToleranceVoltages Out of Tolerance
576 System  Hardware   System EnvironmentALERT  102  Fan Failure  Fan Failure
578 System  Hardware   System EnvironmentALERT  104  Thermal Red  Thermal Red
579 System  Hardware   System EnvironmentALERT  105  Thermal Red Timer ExceededThermal Red Timer Exceeded
580 Network  TCPAttack   ALERT  558  TCP SYN/FIN Packet DropTCP SYN/FIN packet dropped
583 Users   Authentication AccessAttack   ERROR  559  User Login DisableUser login disabled from %s
606 Security ServicesAttacksAttack   ALERT  568  Spank Attack Spank attack multicast packet dropped
608 Security ServicesIPSAttack   ALERT  569  IPS Detection AlertIPS Detection Alert: %s
609 Security ServicesIPSAttack   ALERT  570  IPS Prevention AlertIPS Prevention Alert: %s
610 Security ServicesCrypto Test   Maintenance ERROR  ---   Hardware AES Test FailedCrypto Hardware AES test failed
614 Security ServicesGeneralMaintenance WARNING 571  IDP Expiration MessageReceived IPS Alert: Your Intrusion Prevention (IDP) subscription has expired.
646 Firewall  Access Rules  System Error ALERT  5238  Source IP Connection LimitPacket dropped; connection limit for this source IP address has been reached
647 Firewall  Access Rules  System Error ALERT  5239  Destination IP Connection LimitPacket dropped; connection limit for this destination IP address has been reached
648 VPN   VPN IPsec   Attack   ERROR  572  Illegal DestinationPacket destination not in VPN Access list
734 Firewall  Access Rules  ---INFO   ---   Source Connection StatusSource IP address connection status: %s
735 Firewall  Access Rules  ---INFO   ---   Destination Connection StatusDestination IP address connection status: %s
745 Users   Radius AuthenticationUser Activity INFO   ---   LDAP Authentication FailureUser login denied - LDAP authentication failure
746 Users   Radius AuthenticationUser Activity WARNING ---   LDAP Server TimeoutUser login denied - LDAP server Timeout
747 Users   Radius AuthenticationUser Activity WARNING ---   LDAP Server ErrorUser login denied - LDAP server down or misconfigured
748 Users   Radius AuthenticationUser Activity WARNING ---   LDAP Communication ProblemUser login denied - LDAP communication problem
749 Users   Radius AuthenticationUser Activity WARNING ---   LDAP Server Invalid CredentialUser login denied - invalid credentials on LDAP server
750 Users   Radius AuthenticationUser Activity WARNING ---   LDAP Server Insufficient AccessUser login denied - insufficient access on LDAP server
751 Users   Radius AuthenticationUser Activity WARNING ---   LDAP Schema MismatchUser login denied - LDAP schema mismatch
753 Users   Radius AuthenticationUser Activity WARNING ---   LDAP Server Name Resolution FailedUser login denied - LDAP server name resolution failed
754 Users   Radius AuthenticationUser Activity WARNING ---   RADIUS Server Name Resolution FailedUser login denied - RADIUS server name resolution failed
755 Users   Radius AuthenticationUser Activity WARNING ---   LDAP Server Certificate InvalidUser login denied - LDAP server certificate not valid
756 Users   Radius AuthenticationUser Activity WARNING ---   LDAP TLS or Local ErrorUser login denied - TLS or local certificate problem
757 Users   Radius AuthenticationUser Activity WARNING ---   LDAP Directory MismatchUser login denied - LDAP directory mismatch
759 Users   Authentication AccessUser Activity INFO   ---   User Already Logged-InUser login denied - user already logged in
789 Security ServicesIDPAttack   ALERT  6435  IDP Detection AlertIDP Detection Alert: %s
790 Security ServicesIDPAttack   ALERT  6436  IDP Prevention AlertIDP Prevention Alert: %s
793 Firewall  Application FirewallUser Activity ALERT  13201 Application Firewall AlertApplication Firewall Alert: %s
794 Security ServicesAnti-Spyware  Attack   ALERT  6437  Anti-Spyware Prevention AlertAnti-Spyware Prevention Alert: %s
795 Security ServicesAnti-Spyware  Attack   ALERT  6438  Anti-Spyware Detection AlertAnti-Spyware Detection Alert: %s
796 Security ServicesAnti-Spyware  Maintenance WARNING 8631  Anti-Spyware Service ExpiredAnti-Spyware Service Expire
797 Security ServicesRBL Filter   ---NOTICE  ---   Outbound Connection DropOutbound connection to RBL-listed SMTP server dropped
798 Security ServicesRBL Filter   ---NOTICE  ---   Inbound Connection DropInbound connection from RBL-listed SMTP server dropped
799 Security ServicesRBL Filter   ---NOTICE  ---   SMTP Server on RBL BlacklistSMTP server found on RBL blacklist
809 Security ServicesGAVAttack   ALERT  8632  AV Gateway AlertGateway Anti-Virus Alert: %s
810 Security ServicesGAVMaintenance WARNING 8633  AV Gateway Service ExpireGateway Anti-Virus Service expired
815 Network  ARP---WARNING ---   Too Many Gratuitous ARPs DetectedToo many gratuitous ARPs detected
856 Firewall SettingsFlood ProtectionAttack   WARNING ---   SYN Flood Watch ModeSYN Flood Mode changed by user to: Watch and report possible SYN floods
857 Firewall SettingsFlood ProtectionAttack   WARNING ---   SYN Flood Trigger ModeSYN Flood Mode changed by user to: Watch and proxy WAN connections when under attack
858 Firewall SettingsFlood ProtectionAttack   WARNING ---   SYN Flood Proxy ModeSYN Flood Mode changed by user to: Always proxy WAN connections
859 Firewall SettingsFlood ProtectionAttack   ALERT  ---   SYN Flood Proxy Trigger ModePossible SYN flood detected on WAN IF %s - switching to connection-proxy mode
860 Firewall SettingsFlood ProtectionAttack   ALERT  ---   SYN Flood DetectedPossible SYN Flood on IF %s
861 Firewall SettingsFlood ProtectionAttack   ALERT  ---   SYN Flood Proxy Mode CancelSYN flood ceased or flooding machines blacklisted - connection proxy disabled
862 Firewall SettingsFlood ProtectionAttack   WARNING ---   SYN Flood Blacklist OnSYN Flood blacklisting enabled by user
863 Firewall SettingsFlood ProtectionAttack   WARNING ---   SYN Flood Blacklist OffSYN Flood blacklisting disabled by user
864 Firewall SettingsFlood ProtectionAttack   ALERT  ---   SYN-Flooding Machine BlacklistedSYN-Flooding machine %s blacklisted
865 Firewall SettingsFlood ProtectionAttack   ALERT  ---   Machine removed from SYN Flood BlacklistMachine %s removed from SYN flood blacklist
866 Firewall SettingsFlood ProtectionAttack   WARNING ---   Possible SYN Flood ContinuesPossible SYN Flood on IF %s continues
867 Firewall SettingsFlood ProtectionAttack   ALERT  ---   Possible SYN Flood CeasedPossible SYN Flood on IF %s has ceased
868 Firewall SettingsFlood ProtectionAttack   WARNING ---   SYN Flood Blacklist ContinuesSYN Flood Blacklist on IF %s continues
869 Firewall SettingsFlood ProtectionAttack   DEBUG  ---   TCP SYN ReceiveTCP SYN received
879 Wireless  RF Monitoring ---WARNING ---   WLAN Radio Frequency Threat DetectedWLAN radio frequency threat detected
881 System  Time---NOTICE  ---   System Clock Manually UpdatedSystem clock manually updated
883 Firewall SettingsChecksum EnforcementTCP|UDP  NOTICE  ---   IP Checksum ErrorIP Header checksum error; packet dropped
884 Firewall SettingsChecksum EnforcementTCPNOTICE  ---   TCP Checksum ErrorTCP checksum error; packet dropped
885 Firewall SettingsChecksum EnforcementUDPNOTICE  ---   UDP Checksum ErrorUDP checksum error; packet dropped
886 Firewall SettingsChecksum EnforcementUDPNOTICE  ---   ICMP Checksum ErrorICMP checksum error; packet dropped
897 Firewall SettingsFlood ProtectionAttack   INFO   ---   Invalid TCP SYN Flood CookieTCP packet received with invalid SYN Flood cookie; TCP packet dropped
898 Firewall SettingsFlood ProtectionAttack   ALERT  ---   RST-Flooding Machine BlacklistedRST-Flooding machine %s blacklisted
899 Firewall SettingsFlood ProtectionAttack   WARNING ---   RST Flood Blacklist ContinuesRST Flood Blacklist on IF %s continues
900 Firewall SettingsFlood ProtectionAttack   ALERT  ---   Machine Removed From RST Flood BlacklistMachine %s removed from RST flood blacklist
901 Firewall SettingsFlood ProtectionAttack   ALERT  ---   FIN-Flooding Machine BlacklistedFIN-Flooding machine %s blacklisted
902 Firewall SettingsFlood ProtectionAttack   WARNING ---   FIN Flood Blacklist ContinuesFIN Flood Blacklist on IF %s continues
903 Firewall SettingsFlood ProtectionAttack   ALERT  ---   Machine Removed From FIN Flood BlacklistMachine %s removed from FIN flood blacklist
904 Firewall SettingsFlood ProtectionAttack   ALERT  ---   Possible RST FloodPossible RST Flood on IF %s
905 Firewall SettingsFlood ProtectionAttack   ALERT  ---   Possible FIN FloodPossible FIN Flood on IF %s
906 Firewall SettingsFlood ProtectionAttack   ALERT  ---   Possible RST Flood CeasedPossible RST Flood on IF %s has ceased
907 Firewall SettingsFlood ProtectionAttack   ALERT  ---   Possible FIN Flood CeasedPossible FIN Flood on IF %s has ceased
908 Firewall SettingsFlood ProtectionAttack   WARNING ---   Possible RST Flood ContinuesPossible RST Flood on IF %s continues
909 Firewall SettingsFlood ProtectionAttack   WARNING ---   Possible FIN Flood ContinuesPossible FIN Flood on IF %s continues
986 Users   Authentication AccessUser Activity INFO   ---   Not Allowed by Policy RuleUser login denied - not allowed by Policy rule
987 Users   Authentication AccessUser Activity INFO   ---   Not Found LocallyUser login denied - not found locally
992 Users   SSO Agent AuthenticationUser Activity WARNING ---   User Name Too LongSSO agent returned user name too long
993 Users   SSO Agent AuthenticationUser Activity WARNING ---   Domain Name Too LongSSO agent returned domain name too lon
994 Users   Authentication AccessUser Activity INFO   ---   Configuration Mode Administration Session StartedConfiguration mode administration session started
996 Users   Authentication AccessUser Activity INFO   ---   Read-only Mode GUI Administration Session StartedRead-only mode GUI administration session started
999 Firewall SettingsSSL Control   Blocked Sites INFO   ---   Website Found in BlacklistSSL Control: Website found in blacklist
1010 Users   Radius AuthenticationSystem Error ALERT  ---   Using LDAP Without TLSUsing LDAP without TLS - highly insecure
1035 Users   Authentication AccessUser Activity INFO   ---   Password ExpireUser login denied - password expired
1048 Users   Authentication Access---INFO   ---   Password doesn't meet constraintsUser login denied - password doesn't meet constraints
1049 System  Settings    ---INFO   ---   System Setting ImportedSystem Setting Imported
1050 VPN   VPN IPsec   User Activity INFO   ---   VPN Policy AddedVPN policy %s is added
1051 VPN   VPN IPsec   User Activity INFO   ---   VPN Policy DeletedVPN policy %s is deleted
1052 VPN   VPN IPsec   User Activity INFO   ---   VPN Policy ModifiedVPN policy %s is modified
1080 Users   Authentication Access---INFO   ---   Successful SSL VPN User LoginSSL VPN zone remote user login allowed
1084 Anti-Spam General---INFO   13803 Service Enable Anti-Spam service is enabled by administrator.
1085 Anti-Spam General---INFO   13804 Service Disable Anti-Spam service is disabled by administrator.
1086 Anti-Spam General---WARNING 13805 Service Subscription ExpireYour Anti-Spam Service subscription has expired
1088 Anti-Spam General---WARNING 13807 Startup Failure Anti-Spam Startup Failure - %s
1093 Anti-Spam GRID---NOTICE  13811 SMTP Server Found on Reject ListSMTP server found on Reject List
1098 Network  DNS---ALERT  6465  DNS Rebind Attack DetectedPossible DNS rebind attack detected
1099 Network  DNS---ALERT  6466  DNS Rebind Attack BlockedDNS rebind attack blocked
1108 Anti-Spam E-mail---INFO   ---   E-mail Message BlockedMessage blocked by Real-Time E-mail Scanner
1110 Network  DHCP Server  ---INFO   ---   Assigned IP AddressAssigned IP address %s
1114 Firewall SettingsFTP---DEBUG  ---   FTP Client User LoginFtp client user logged in successfully
1115 Firewall SettingsFTP---DEBUG  ---   FTP Client User Login FailedFtp client user logged in failed
1149 High AvailabilityCluster---WARNING ---   VRRP Expiration MessageYour Active/Active Clustering subscription has expired
1153 SSL VPN  GeneralConnection TrafficINFO   ---   SSL VPN Traffic SSL VPN Traffic
1154 Firewall  Application Control---ALERT  15001 Application Control Detection AlertApplication Control Detection Alert: %s
1155 Firewall  Application Control---ALERT  15002 Application Control Prevention AlertApplication Control Prevention Alert: %s
1159 Security ServicesGeneral---WARNING ---   Visualization Control Expire MessageReceived Alert: Your Visualization Control subscription has expired
1176 WAN AccelerationLocal WXA Appliance---WARNING ---   WAN Acceleration Software License ExpiredYour WAN Acceleration Service subscription has expired.
1177 Network  DNSDebug   ALERT  ---   Malformed DNS PacketMalformed DNS packet detected
1178 Users   SSO Agent AuthenticationUser Activity ALERT  ---   High SSO Packet CountA high percentage of the system packet buffers are held waiting for SSO
1179 Users   SSO Agent AuthenticationUser Activity ALERT  ---   High SSO User ConnectionA user has a very high number of connections waiting for SSO
1180 Firewall SettingsFlood Protection---ALERT  ---   DOS Protection on WAN Begin DOS protection on WAN begins %s
1181 Firewall SettingsFlood Protection---WARNING ---   DOS Protection on WAN In-ProgressDOS protection on WAN %s
1182 Firewall SettingsFlood Protection---ALERT  ---   DOS Protection on WAN StoppedDOS protection on WAN %s
1195 Security ServicesBotnet Filter  Security ServicesWARNING ---   Botnet Filter Subscription ExpiredReceived Alert: Your Firewall Botnet Filter subscription has expired
1198 Security ServicesGeo-IP Filter  ---ALERT  ---   Geo IP Initiator BlockedInitiator from country blocked: %s
1199 Security ServicesGeo-IP Filter  ---ALERT  ---   Geo IP Responder BlockedResponder from country blocked: %s
1200 Security ServicesBotnet Filter  ---ALERT  ---   Botnet Initiator BlockedSuspected Botnet initiator blocked: %s
1201 Security ServicesBotnet Filter  ---ALERT  ---   Botnet Responder BlockedSuspected Botnet responder blocked: %s
1213 Firewall SettingsFlood ProtectionAttack   ALERT  ---   UDP Flood DetectedPossible UDP flood attack detected
1214 Firewall SettingsFlood ProtectionAttack   ALERT  ---   ICMP Flood DetectedPossible ICMP flood attack detected
1222 System  SNMP---WARNING ---   Invalid SNMPv3 UserInvalid SNMPv3 User
1304 Network  Network Access Debug   ALERT  ---   Packet Dropped Due to NDPP RulesPacket is dropped due to NDPP rules
1316 Network  ARP---ALERT  ---   ARP Attack DetectedPossible ARP attack from MAC address %s
1332 System  StatusMaintenance ALERT  ---   NDPP Mode ChangeNDPP mode is changed to %s
1333 Users   Authentication AccessUser Activity INFO   ---   Create a User %s
1334 Users   Authentication AccessUser Activity INFO   ---   Edit a User  %s
1335 Users   Authentication AccessUser Activity INFO   ---   Delete a User %s
1337 System  Settings    Firewall   INFO   ---   User Password Changed by Administrators%s
1338 System  Settings    Firewall   INFO   ---   User Change PasswordUser %s password is changed
1343 VPN   VPN IPsec   User Activity INFO   ---   VPN Policy Enabled/DisabledVPN Policy %s
1366 Firewall SettingsFlood ProtectionAttack   ALERT  ---   TCP-Flooding Machine BlacklistedTCP-Flooding machine %s blacklisted
1367 Firewall SettingsFlood ProtectionAttack   WARNING ---   TCP Flood Blacklist ContinuesTCP Flood Blacklist on IF %s continue
s1368 Firewall SettingsFlood ProtectionAttack   ALERT  ---   Machine Removed From TCP Flood BlacklistMachine %s removed from TCP flood blacklist
1369 Firewall SettingsFlood ProtectionAttack   ALERT  ---   Possible TCP FloodPossible TCP Flood on IF %s
1370 Firewall SettingsFlood ProtectionAttack   ALERT  ---   Possible TCP Flood CeasedPossible TCP Flood on IF %s has ceased
1371 Firewall SettingsFlood Protection---WARNING ---   Possible TCP Flood ContinuesPossible TCP Flood on IF %s continues
1373 Security ServicesAttacksAttack   ALERT  ---   IPv6 fragment size is less than minimum (<1280)IPv6 fragment dropped, invalid length (<1280 Bytes)
1374 Security ServicesAttacksAttack   ALERT  ---   IP Reassembly : Incomplete IGMP fragmentIGMP packet dropped, incomplete fragments
1375 Security ServicesAttacksAttack   ALERT  ---   UDP fragmented datagram is too big (>65535)UDP fragment dropped, exceeds maximum IP datagram size (>65535)
1376 Security ServicesAttacksAttack   ALERT  ---   Nestea/Teardrop AttackNestea/Teardrop attack dropped
1378 Anti-Spam General---ALERT  ---   SHLO replay attackPossible replay attack with this client IP - %s
1381 Security ServicesGeneral---WARNING 15003 Application Control Expiration MessageReceived App-Control Alert: Your Application Control subscription has expired.
1382 Log    Configuration AuditingUser Activity INFO   5609  Configuration Change SucceededConfiguration succeeded: %s
1383 Log    Configuration AuditingUser Activity INFO   5610  Configuration Change FailedConfiguration failed: %s
1387 Security ServicesAttacksAttack   ALERT  ---   TCP Null Flag AttackTCP Null Flag dropped
1388 VPN   VPN IPsec   Attack   DEBUG  ---   Vpn Decryption FailedIPSec VPN Decryption Failed
1426 Wireless  SonicPoint/SonicWave---INFO   13603 SonicPoint/SonicWave Unexpected Reboot %s unexpected reboot. Please check whether input power is adequate and ethernet connection is secured. (SonicWave/SonicPoint AC/NDR requires 802.3at PoE+)
1432 System  Settings    Firewall   INFO   ---   Configuration ChangeConfiguration changed: %
1442 System  Hardware   System EnvironmentALERT  ---   USB Over CurrentUSB Over Current
1443 Firewall SettingsAdvanced   Debug   WARNING ---   Control Plane Flood Protection Threshold ExceededControl Plane Flood Protection Threshold Exceeded: %s
1444 High AvailabilityStateMaintenance ERROR  ---   HA Reboot  Reboot occured (Reason :%s)
1450 Firewall SettingsFlood ProtectionAttack   ALERT  ---   UDPv6 Flood DetectedPossible UDPv6 flood attack detected
1451 Firewall SettingsFlood ProtectionAttack   ALERT  ---   ICMPv6 Flood DetectedPossible ICMPv6 flood attack detected
1452 Firewall SettingsFlood ProtectionAttack   ALERT  ---   Half Open TCP Connection Threshold ExceededToo many half-open TCP connection
1459 Security ServicesGAVMaintenance INFO   ---   Capture ATP File Transfer AttemptGateway Anti-Virus Status: %s
1460 Security ServicesGAVMaintenance INFO   ---   Capture ATP File Transfer ResultGateway Anti-Virus Status: %s
1461 Security ServicesContent Filter  ---NOTICE  703  CFS Alert   CFS Alert: %s1462 Security ServicesGAV---INFO   ---   AV Gateway InformGateway Anti-Virus Inform: %s
1474 Security ServicesGeo-IP Filter  ---ALERT  ---   Custom Geo IP Initiator BlockedInitiator from country blocked: %s, Source: Custom List
1475 Security ServicesGeo-IP Filter  ---ALERT  ---   Custom Geo IP Responder BlockedResponder from country blocked: %s, Source: Custom List
1476 Security ServicesBotnet Filter  ---ALERT  ---   Custom Botnet Initiator BlockedSuspected Botnet initiator blocked: %s, Source: Custom List
1477 Security ServicesBotnet Filter  ---ALERT  ---   Custom Botnet Responder BlockedSuspected Botnet responder blocked: %s, Source: Custom List
1495 System  StatusMaintenance INFO   ---   Firewall was Rebooted by Setting ImportFirewall was rebooted by setting import at %s
1496 System  StatusMaintenance INFO   ---   Firewall was Rebooted by FirmwareFirewall was rebooted by %
1507 Network  IPv6 MAC-IP Anti-SpoofAttack   ALERT  ---   IPv6 MAC-IP Anti-Spoof Check Enforced For HostsIPv6 MAC-IP Anti-spoof check enforced for hosts
1508 Network  IPv6 MAC-IP Anti-SpoofAttack   ALERT  ---   IPv6 MAC-IP Anti-Spoof Cache Not Found For RouterIPv6 MAC-IP Anti-spoof cache not found for this router
1509 Network  IPv6 MAC-IP Anti-SpoofAttack   ALERT  ---   IPv6 MAC-IP Anti-Spoof Cache Not RouterIPv6 MAC-IP Anti-spoof cache found, but it is not a router
1510 Network  IPv6 MAC-IP Anti-SpoofAttack   ALERT  ---   IPv6 MAC-IP Anti-Spoof Cache Blacklisted DeviceIPv6 MAC-IP Anti-spoof cache found, but it is blacklisted device
1515 System  Cloud Backup  Firewall   INFO   ---   Delete Cloud Backup Successful%s
1516 System  Cloud Backup  Firewall   INFO   ---   Delete Cloud Backup Failed%
1517 Users   Authentication AccessUser Activity INFO   ---   User Name Invalid Symbol User name invalid symbol: %s 
1518 Security ServicesBotnet Filter  ---ALERT  ---   Botnet Initiator BlockedSuspected Botnet initiator blocked: %s, Source: Dynamic List
1519 Security ServicesBotnet Filter  ---ALERT  ---   Botnet Responder BlockedSuspected Botnet responder blocked: %s, Source: Dynamic List
1526 Wireless  SonicPoint/SonicWave---INFO   ---   SonicWave License Invalid SonicWave %s
1532 Security ServicesDPI-SSH    Users    ALERT  ---   DPI-SSH PF UserDPI SSH Port Forward Alert: %s
1533 Security ServicesDPI-SSH    ---INFO   ---   DPI-SSH   DPI-SSH: %s
1534 Security ServicesDPI-SSH    ---ALERT  ---   DPI-SSH Connection CheckDPI-SSH Connection: %s
1564 Security ServicesDPI-SSL EnforcementMaintenance WARNING ---   SSLE Expire MessageReceived DPI-SSL Enforcement Alert: Your Network DPI-SSL Enforcement subscription has expired. %s
```