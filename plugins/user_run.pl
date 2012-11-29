#-----------------------------------------------------------
# user_run
# Get contents of Run key from user's hive
#
# History
#  20120824 - updated to FS format
#  20080328 - created
#
# References:
#   http://msdn2.microsoft.com/en-us/library/aa376977.aspx
#   http://support.microsoft.com/kb/170086
#   
#
# copyright 2008 H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package user_run;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              osmask        => 63, #XP - Win8
              class         => 1,
              output        => "report",
              type          => "Reg",
              category      => "AutoStart",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 1,
              version       => 20120824);

sub getConfig{return \%config}

sub getShortDescr {
	return "Get HKU\\\.\.\\Run key contents from NTUSER\.DAT hive";	
}
sub getDescr{}
sub getRefs {
	my %refs = ("Definition of the Run keys in the WinXP Registry" =>
	            "http://support.microsoft.com/kb/314866");	
	return %refs;
}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $parent = ::getConfig();
	
	::logMsg("user_run v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("user_run v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
		
	my $profile = $parent->{userprofile};
	::rptMsg("Profile: ".$profile);
	
	my @u = split(/\\/,$profile);
	my $n = scalar(@u) - 1;
	my $user = $u[$n];
	
	$profile .= "\\" unless ($profile =~ m/\\$/);
	my $hive = $profile."NTUSER\.DAT";
	
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	my $key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		
		my %vals = getKeyValues($key);
		if (scalar(keys %vals) > 0) {
			foreach my $v (keys %vals) {
				::rptMsg("\t".$v." -> ".$vals{$v});
			}
		}
		else {
			::rptMsg($key_path." has no values.");
		}
		
		my @sk = $key->get_list_of_subkeys();
		if (scalar(@sk) > 0) {
			foreach my $s (@sk) {
				::rptMsg("");
				::rptMsg($key_path."\\".$s->get_name());
				::rptMsg("LastWrite Time ".gmtime($s->get_timestamp())." (UTC)");
				my %vals = getKeyValues($s);
				foreach my $v (keys %vals) {
					::rptMsg("\t".$v." -> ".$vals{$v});
				}
			}
		}
		else {
			::rptMsg("");
			::rptMsg($key_path." has no subkeys.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
		::logMsg($key_path." not found.");
	}
	
}

sub getKeyValues {
	my $key = shift;
	my %vals;
	
	my @vk = $key->get_list_of_values();
	if (scalar(@vk) > 0) {
		foreach my $v (@vk) {
			next if ($v->get_name() eq "" && $v->get_data() eq "");
			$vals{$v->get_name()} = $v->get_data();
		}
	}
	else {
	
	}
	return %vals;
}

1;