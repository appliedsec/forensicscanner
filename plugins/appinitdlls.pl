#-----------------------------------------------------------
# appinitdlls - check for suspicious entries in AppInit_Dlls value
#
# Change History
#   20120925 - updated to RS format
#   20080324 - created
#
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package appinitdlls;
use strict;

my %config = (hive          => "Software",
              hivemask      => 0x08,
							type          => "Reg",
							category      => "Malware",
							output        => "report",
							class         => 0,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 1,
              osmask        => 31, #XP-Win7
              version       => 20120925);

sub getConfig{return \%config}
sub getShortDescr {
	return "Gets contents of AppInit_DLLs value";	
}
sub getDescr{}
sub getRefs {
	my %refs = ("Working with the AppInit_DLLs Reg Value" => 
	            "http://support.microsoft.com/kb/q197571");
	return %refs;
}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $parent = ::getConfig();
	
	::logMsg("appinitdlls v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("appinitdlls v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
		
	my $hive = $parent->{software};

	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Microsoft\\Windows NT\\CurrentVersion\\Windows';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		::rptMsg("");
		my @vals = $key->get_list_of_values();
		foreach my $v (@vals) {
			my $name = $v->get_name();
			if ($name eq "AppInit_DLLs") {
				my $data = $v->get_data();
				$data = "{blank}" if ($data eq "");
				::rptMsg($name." -> ".$data);
				::rptMsg("");
				::rptMsg("Verify any entries if the AppInit_DLLs value is not blank.");
			}
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}
1;