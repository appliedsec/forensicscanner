#-----------------------------------------------------------
# spp_clients
# Get the contents of a value that illustrates which volumes are monitored
# for VSCs
#
# History
#  20120925 - updated to RS format
#  20120914 - created
#
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package spp_clients;
use strict;

my %config = (hive          => "Software",
              hivemask      => 0x08,
              type          => "Reg",
              output        => "report",
              class         => 0,
              category      => "Config",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 50, #Vista, Win7, Win 8
              version       => 20120925);

sub getConfig{return \%config}
sub getShortDescr {
	return "Determines volumes monitored by VSS";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $parent = ::getConfig();
	
	::logMsg("spp_clients v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("spp_clients v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
		
	my $hive = $parent->{software};
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Microsoft\\Windows NT\\CurrentVersion\\SPP\\Clients';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("SPP_Clients");
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		::rptMsg("");
		
		my $mon;
		eval {
			$mon = $key->get_value("{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}")->get_data();
			::rptMsg("Monitored volumes: ".$mon);
		};
		
	}
	else {
		::rptMsg($key_path." not found.");
	}
}
1;