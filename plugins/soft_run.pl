#-----------------------------------------------------------
# soft_run
# Get contents of Run key from Software hive
#
#
# History:
#   20120824 - updated to FS format
#   20120524 - updated to support newer OS's, and 64-bit
#   20080328 - created
#
#
# copyright 2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package soft_run;
use strict;

my %config = (hive          => "Software",
	            hivemask      => 0x08,
	            type          => "Reg",
	            category      => "AutoStart",
							output        => "report",
							class         => 0,
              osmask        => 63, #XP - Win8 
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 1,
              version       => 20120824);

sub getConfig{return \%config}

sub getShortDescr {
	return "Get Run key contents from Software hive";	
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
	
	::logMsg("soft_run v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("soft_run v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
		
	my $hive = $parent->{software};
	
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	my @paths = ("Microsoft\\Windows\\CurrentVersion\\Run",
	             "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run");
	
	foreach my $key_path (@paths) {
	
		my $key;
		if ($key = $root_key->get_subkey($key_path)) {
			::rptMsg($key_path);
			::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		
			my %vals = getKeyValues($key);
			if (scalar(keys %vals) > 0) {
				foreach my $v (keys %vals) {
					::rptMsg("  ".$v." - ".$vals{$v});
				}
				::rptMsg("");
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
						::rptMsg("  ".$v." -> ".$vals{$v});
					}
					::rptMsg("");
				}
			}
			else {
				::rptMsg($key_path." has no subkeys.");
				::rptMsg("");
			}
		}
		else {
			::rptMsg($key_path." not found.");
			::rptMsg("");
		}
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