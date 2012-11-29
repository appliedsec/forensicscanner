#-----------------------------------------------------------
# acmru.pl
# Plugin for Registry Ripper, NTUSER.DAT edition - gets the 
# ACMru values 
#
# Change history
#   20120823 - updated to Forensic Scanner format
#   20080324 - created
#
# References
#
# 
# copyright 2012
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package acmru;
use strict;

my %config = (hive          => "NTUSER\.DAT",
							hivemask      => 0x10,
              hasShortDescr => 1,
              hasDescr      => 0,
              category      => "User Activity",
              type          => "Reg",
              output        => "report",
              class         => 1,
              hasRefs       => 0,
              osmask        => 3,  #XP/2003
              version       => 20120823);

sub getConfig{return \%config}
sub getShortDescr {
	return "Gets contents of user's ACMru key";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $parent = ::getConfig();
  my $profile = $parent->{userprofile};
	
	::logMsg("acmru v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("acmru v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");

	::rptMsg("Profile: ".$profile);
	$profile .= "\\" unless ($profile =~ m/\\$/);
	
	my $ntuser = $profile."NTUSER\.DAT";
	
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Software\\Microsoft\\Search Assistant\\ACMru';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $s (@subkeys) { 
				::rptMsg($s->get_name()." [".gmtime($s->get_timestamp())." (UTC)]");
				my @vals = $s->get_list_of_values();
				my %ac_vals;
				foreach my $v (@vals) {
					$ac_vals{$v->get_name()} = $v->get_data();
				}
				foreach my $a (sort {$a <=> $b} keys %ac_vals) {
					::rptMsg("\t".$a." -> ".$ac_vals{$a});
				}
				::rptMsg("");
			}
		}
		else {
			::rptMsg($key_path." has no subkeys.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}

1;