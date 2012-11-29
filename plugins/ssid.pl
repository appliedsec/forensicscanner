#-----------------------------------------------------------
# ssid
# Gets SSID and other info from WZCSVC key
#
#
# Change History:
#    20120925 - updated to RS format
#    20100301 - Updated References; removed dwCtlFlags being 
#               printed; minor adjustments to formatting
#    20091102 - added code to parse EAPOL values for SSIDs
#    20090807 - updated code in accordance with WZC_WLAN_CONFIG 
#               structure
#
# References
#    http://msdn.microsoft.com/en-us/library/aa448338.aspx
#
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package ssid;
use strict;

my %config = (hive          => "Software",
              hivemask      => 0x08,
              type          => "Reg",
              output        => "report",
              category      => "Wireless",
              class         => 0,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 1, #I've only verified this on XP
              version       => 20120925);

sub getConfig{return \%config}
sub getShortDescr {
	return "Get WZCSVC SSID Info (XP)";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();
my $error;

sub pluginmain {
	my $class = shift;
	my $parent = ::getConfig();
	
	::logMsg("ssid v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("ssid v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
		
	my $hive = $parent->{software};
# Get the NetworkCards values
	my %nc;
	if (%nc = getNetworkCards($hive)) {
		
	}
	else {
		::rptMsg("Problem w/ SSIDs, getting NetworkCards: ".$error);
		return;
	}
		
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	my $key_path = "Microsoft\\WZCSVC\\Parameters\\Interfaces";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("SSID");
		::rptMsg($key_path);
		::rptMsg("");
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $s (@subkeys) {
				my $name = $s->get_name();
				if (exists($nc{$name})) {
					::rptMsg("NIC: ".$nc{$name}{descr});
					::rptMsg("Key LastWrite: ".gmtime($s->get_timestamp())." UTC");
					::rptMsg("");
					my @vals = $s->get_list_of_values();
					if (scalar(@vals) > 0) {
						foreach my $v (@vals) {
							my $n = $v->get_name();
							if ($n =~ m/^Static#/) {
								my $data = $v->get_data();								
#								my $w = unpack("V",substr($data,0x04,0x04));
#								printf "dwCtlFlags = 0x%x\n",$w;
								
								my $l = unpack("V",substr($data, 0x10, 0x04));
								my $ssid = substr($data,0x14,$l);
								
								my $tm = uc(unpack("H*",substr($data,0x08,0x06)));
								my @t = split(//,$tm);
								my $mac = $t[0].$t[1]."-".$t[2].$t[3]."-".$t[4].$t[5]."-".$t[6].$t[7]."-".$t[8].$t[9]."-".$t[10].$t[11];
								
								my ($t1,$t2) = unpack("VV",substr($data,0x2B8,8));
								my $t        = ::getTime($t1,$t2);
								my $str = sprintf gmtime($t)." MAC: %-18s %-8s",$mac,$ssid;
								::rptMsg($str);
							}
						}
					}
					else {
						::rptMsg($name." has no values.");
					}
				}
			}
		}
		else {
			::rptMsg($key_path." has no subkeys.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
	
# Now, go to the EAPOL key, locate the appropriate subkeys and parse out
# any available SSIDs	
# EAPOL is Extensible Authentication Protocol over LAN
	my $key_path = "Microsoft\\EAPOL\\Parameters\\Interfaces";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("");
		::rptMsg($key_path);
		::rptMsg("");
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $s (@subkeys) {
				my $name = $s->get_name();
				if (exists $nc{$name}) {
					::rptMsg("NIC: ".$nc{$name}{descr});
				}
				else {
					::rptMsg("NIC: ".$name);
				}
				::rptMsg("LastWrite time: ".gmtime($s->get_timestamp())." UTC");
				
				my @vals = $s->get_list_of_values();
				my %eapol;
				if (scalar(@vals) > 0) {
					foreach my $v (@vals) {
						$eapol{$v->get_name()} = parseEAPOLData($v->get_data());
					}
					foreach my $i (sort {$a <=> $b} keys %eapol) {
						my $str = sprintf "%-3d  %s",$i,$eapol{$i};
						::rptMsg($str);
					}
				}
				::rptMsg("");
			}
		}
		else {
			::rtpMsg($key_path." has no subkeys.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}

sub getNetworkCards {
	my $hive = shift;
	my %nc;
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	my $key_path = "Microsoft\\Windows NT\\CurrentVersion\\NetworkCards";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $s (@subkeys) {
				my $service = $s->get_value("ServiceName")->get_data();
				$nc{$service}{descr} = $s->get_value("Description")->get_data();
				$nc{$service}{lastwrite} = $s->get_timestamp();
			}
		}
		else {
			$error = $key_path." has no subkeys.";
		}
	}
	else {
		$error = $key_path." not found.";
	}
	return %nc;
}

sub parseEAPOLData {
	my $data = shift;
	my $size = unpack("V",substr($data,0x10,4));
	return substr($data,0x14,$size);
}

1;