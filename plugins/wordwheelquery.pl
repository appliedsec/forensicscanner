#-----------------------------------------------------------
# wordwheelquery.pl
# For Windows 7 only; gets user's Desktop search MRU
#
# Change history
#   20120925 - updated to RS format
#	  20100330 - created
#
# References
#   http://www.winhelponline.com/blog/clear-file-search-mru-history-windows-7/
# 
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package wordwheelquery;
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
              osmask        => 0x10,
              version       => 20120925);

sub getConfig{return \%config}
sub getShortDescr {
	return "Gets contents of user's WordWheelQuery key";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $parent = ::getConfig();
	 
	::logMsg("wordwheelquery v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("wordwheelquery v.".$VERSION);
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

	my $key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		my @vals = $key->get_list_of_values();
		if (scalar(@vals) > 0) {
			my @list;
			my %wwq;
			foreach my $v (@vals) { 
				my $name = $v->get_name();
				if ($name eq "MRUListEx") {
					@list = unpack("V*",$v->get_data());
					pop(@list) if ($list[scalar(@list) - 1] == 0xffffffff);
				}
				else {
					my $data = $v->get_data();
					$data =~ s/\00//g;
					$wwq{$name} = $data;
				}
			}
# list searches in MRUListEx order
			::rptMsg("");
			::rptMsg("Searches listed in MRUListEx order");
			::rptMsg("");			
			foreach my $l (@list) {
				::rptMsg(sprintf "%-4d %-30s",$l,$wwq{$l});
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