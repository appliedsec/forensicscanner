#-----------------------------------------------------------
# runmru.pl
# Plugin for Registry Ripper, NTUSER.DAT edition - gets the 
# RunMru values 
#
# Change history
#   20120925 - updated to RS format
#   20080324 - created
#
# References
#
# 
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package runmru;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hivemask      => 0x10,
              type          => "Reg",
              output        => "report",
              class         => 1,
              category      => "User Activity",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 31,
              version       => 20120925);

sub getConfig{return \%config}
sub getShortDescr {
	return "Gets contents of user's RunMRU key";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $parent = ::getConfig();
	 
	::logMsg("runmru v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("runmru v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
		
	my $profile = $parent->{userprofile};
	::rptMsg("Profile: ".$profile);
#	my @u = split(/\\/,$profile);
#	my $n = scalar(@u) - 1;
#	my $user = $u[$n];
	
	$profile .= "\\" unless ($profile =~ m/\\$/);	
	my $hive = $profile."NTUSER\.DAT";
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		my @vals = $key->get_list_of_values();
		my %runvals;
		my $mru;
		if (scalar(@vals) > 0) {
			foreach my $v (@vals) {
				$runvals{$v->get_name()} = $v->get_data() unless ($v->get_name() =~ m/^MRUList/i);
				$mru = $v->get_data() if ($v->get_name() =~ m/^MRUList/i);
			}
			::rptMsg("MRUList = ".$mru);
			foreach my $r (sort keys %runvals) {
				::rptMsg($r."   ".$runvals{$r});
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