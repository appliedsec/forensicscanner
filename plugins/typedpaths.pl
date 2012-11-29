#-----------------------------------------------------------
# typedpaths.pl
# For Windows 7, Desktop Address Bar History
#
# Change history
#   20120925 - updated to RS format
#	  20100330 - created
#
# References
#   
# 
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package typedpaths;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hivemask      => 0x10,
              class         => 1,
              category      => "User Activity",
              type          => "Reg",
              output        => "report",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 0x10, #Win7
              version       => 20120925);

sub getConfig{return \%config}
sub getShortDescr {
	return "Gets contents of user's typedpaths key";	
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

	my $key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		::rptMsg("");
		my @vals = $key->get_list_of_values();
		if (scalar(@vals) > 0) {
			my %paths;
			foreach my $v (@vals) { 
				my $name = $v->get_name();
				$name =~ s/^url//;
				my $data = $v->get_data();
				$paths{$name} = $data;
			}
			foreach my $p (sort {$a <=> $b} keys %paths) {
				::rptMsg(sprintf "%-8s %-30s","url".$p,$paths{$p});
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