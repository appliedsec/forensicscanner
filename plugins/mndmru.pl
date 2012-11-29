#-----------------------------------------------------------
# mndmru.pl
# Plugin for Registry Ripper,
# Map Network Drive MRU parser
#
# Change history
#   20120925 - updated to RS format
#   20080324 - created
#
# References
# 
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package mndmru;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hivemask      => 0x10,
              type          => "Reg",
              output        => "report",
              class         => 1,
              category      => "User Network Access",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 31,
              version       => 20120925);

sub getConfig{return \%config}
sub getShortDescr {
	return "Get contents of user's Map Network Drive MRU";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $parent = ::getConfig();
	
	::logMsg("mndmru v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("mndmru v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");

	my $profile = $parent->{userprofile};
	::rptMsg("Profile: ".$profile);
#	my @u = split(/\\/,$profile);
#	my $n = scalar(@u) - 1;
#	my $user = $u[$n];
	$profile .= "\\" unless ($profile =~ m/\\$/);	
	my $ntuser = $profile."NTUSER\.DAT";
	
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Map Network Drive MRU';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("Map Network Drive MRU");
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		my @vals = $key->get_list_of_values();
		if (scalar(@vals) > 0) {
			my %mnd;
# Retrieve values and load into a hash for sorting			
			foreach my $v (@vals) {
				my $val = $v->get_name();
				my $data = $v->get_data();
				$mnd{$val} = $data;
			}
# Print sorted content to report file			
			if (exists $mnd{"MRUList"}) {
				::rptMsg("  MRUList = ".$mnd{"MRUList"});
				delete $mnd{"MRUList"};
			}
			foreach my $m (sort {$a <=> $b} keys %mnd) {
				::rptMsg("  ".$m."   ".$mnd{$m});
			}
		}
		else {
			::rptMsg($key_path." has no values.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}

1;