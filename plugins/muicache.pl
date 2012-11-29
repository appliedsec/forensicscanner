#! c:\perl\bin\perl.exe
#-----------------------------------------------------------
# muicache.pl
# Gets user's MUICache values that do not start with '@' 
#
# Change history
#  20120925 - updated to RS format
#  20120522 - updated to collect info from Win7 USRCLASS.DAT
#
# 
# copyright 2012 Quantum Research Analytics, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package muicache;
use strict;

my %config = (hive          => "NTUSER\.DAT,USRCLASS\.DAT",
              hivemask      => 48, #NTUSER.DAT or USRCLASS.DAT, depending upon the OS version
              type          => "Reg",
              class         => 1, # User
              output        => "report",
              category      => "Program Execution",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 23, #XP,2003,Vista,Win7/2008R2
              version       => 20120925);

sub getConfig{return \%config}
sub getShortDescr {
	return "Gets EXEs from user's MUICache key (entries that do not start with \"@\")";	
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
	
	::logMsg("muicache v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("muicache v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
	::rptMsg("Profile: ".$profile);
	$profile .= "\\" unless ($profile =~ m/\\$/);
	::rptMsg("");
	
	my $hive;
	my $key_path;
	
	if ($parent->{"CurrentVersion"} >= 6.0) {
		$hive = $profile."AppData\\Local\\Microsoft\\Windows\\USRCLASS\.DAT";
		$key_path = 'Local Settings\\Software\\Microsoft\\Windows\\Shell\\MUICache';
	}
	else {
		$hive = $profile."NTUSER\.DAT";
		$key_path = 'Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache';
	}
	
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
#	my $key_path = 'Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		my @vals = $key->get_list_of_values();
		if (scalar(@vals) > 0) {
			foreach my $v (@vals) {
				my $name = $v->get_name();
				next if ($name =~ m/^@/ || $name eq "LangID");
				my $data = $v->get_data();
				::rptMsg("\t".$name." (".$data.")");
			}
		}
		else {
			::rptMsg($key_path." has no values.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
		::rptMsg("");
	}

}
1;