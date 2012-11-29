#-----------------------------------------------------------
# appcertdlls.pl
#
# History:
#  20120925 - updated to RS format
#  20120912 - created
#
# References:
#  Blog post: https://blog.mandiant.com/archives/2459
#  Whitepaper: http://fred.mandiant.com/Whitepaper_ShimCacheParser.pdf
#  Tool: https://github.com/mandiant/ShimCacheParser
#
# This plugin is based solely on the work and examples provided by Mandiant;
# thanks to them for sharing this information, and making the plugin possible.
# 
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package appcertdlls;
use strict;

my %config = (hive          => "System",
							hivemask      => 4,
							class         => 0, #system = 0, user = 1
							type          => "Reg",
							output        => "report",
							category      => "Malware",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 31,  #XP - Win7
              version       => 20120925);

sub getConfig{return \%config}
sub getShortDescr {
	return "Get entries from AppCertDlls key";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();
my %files;
my @temps;

sub pluginmain {
	my $class = shift;
	my $parent = ::getConfig();
	::logMsg("appcertdlls v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("appcertdlls v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
	
	my $reg = Parse::Win32Registry->new($parent->{system});
	my $root_key = $reg->get_root_key;
# First thing to do is get the ControlSet00x marked current...this is
# going to be used over and over again in plugins that access the system
# file
	my ($current,$ccs);
	my $key_path = 'Select';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		$current = $key->get_value("Current")->get_data();
		$ccs = "ControlSet00".$current;
		my $appcert_path = $ccs."\\Control\\Session Manager\\AppCertDlls";
		my $appcert;
		if ($appcert = $root_key->get_subkey($appcert_path)) {
			my @vals = $appcert->get_list_of_values();
			if (scalar(@vals) > 0) {
				foreach my $v (@vals) {
					my $name = $v->get_name();
					my $data = $v->get_data();
					::rptMsg($name." - ".$data);
				}
			}
			else {
				::rptMsg($appcert_path."has no values.");
			}
		}
		else {
			::rptMsg($appcert_path." not found.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}

1;