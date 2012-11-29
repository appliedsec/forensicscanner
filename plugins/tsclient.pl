#-----------------------------------------------------------
# tsclient.pl
# Plugin for Registry Ripper
#
# Change history
#    20120827 - updated
#    20080324 - created
#
# References
#   http://support.microsoft.com/kb/312169
# 
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package tsclient;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hivemask      => 0x10,
              class         => 1,
              type          => "Reg",
              category      => "User Activity",
              output        => "report",
              hasShortDescr => 0,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 31,
              version       => 20120925);

sub getConfig{return \%config}
sub getShortDescr {
	return "Displays contents of user's TermServClient Default and Servers keys";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $parent = ::getConfig();
	 
	::logMsg("typedpaths v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("typedpaths v.".$VERSION);
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

	my $key_path = 'Software\\Microsoft\\Terminal Server Client\\Default';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("TSClient");
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		my @vals = $key->get_list_of_values();
		if (scalar(@vals) > 0) {
			my %mrus;
			foreach my $v (@vals) {
				my $val = $v->get_name();
				my $data = $v->get_data();
				my $tag = (split(/MRU/,$val))[1];
				$mrus{$tag} = $val.":".$data;
			}
			foreach my $u (sort {$a <=> $b} keys %mrus) {
				my ($val,$data) = split(/:/,$mrus{$u},2);
				::rptMsg("  ".$val." -> ".$data);
			}
		}
		else {
			::rptMsg($key_path." has no values.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
	::rptMsg("");
	
	my $key_path = 'Software\\Microsoft\\Terminal Server Client\\Servers';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		::rptMsg("");
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $s (@subkeys) {
				my $name = $s->get_name();
				my $lw   = $s->get_timestamp();
				::rptMsg($name."  LastWrite: ".gmtime($lw));
				my $hint;
				eval {
					$hint = $s->get_value("UsernameHint")->get_data();
					::rptMsg("  UsernameHint: ".$hint);
				};
			}
			::rptMsg("");
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