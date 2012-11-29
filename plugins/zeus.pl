package zeus;
#-----------------------------------------------------------
# zeus - simple plugin to check for potential Zeus/Zbot 
#        infection
#
# Change History
#   20111004 - Updated
#   20100923 - Created 
#
#
# copyright 2011 Quantum Analytics Research, LLC
#-----------------------------------------------------------
use strict;

my %config = (hasShortDescr => 1,
							shortDescr    => "Check for Zeus/Zbot sdra64\.exe",
              hasRefs       => 0,
              osmask        => 3, #XP, 2003
              class         => 0, 
              type          => "File,Reg",
              hive          => "Software",
              hivemask      => 8, #Software hive
              category      => "Malware",
              version       => 20111004);

sub getConfig{return \%config};
my $VERSION = $config{version};

sub pluginmain {
	my $class = shift;
	my %parent = ::getConfig();
	::logMsg("Zeus v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("Zeus v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
	::rptMsg("Simple checks for indicators of Zeus/ZBot");
	::rptMsg("");
	my $tag = "sdra64";
	my $check = 0;
	
	my $reg = Parse::Win32Registry->new($parent{softwarehive});
	my $root_key = $reg->get_root_key;
	my $key_path = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		my $ui;
		eval {
			$ui = $key->get_value("Userinit")->get_data();
			::rptMsg("  Userinit: ".$ui);
			::rptMsg("");
			if (grep(/$tag/,$ui)) {
				$check++;
			}
			else {
				::rptMsg("*Zeus apparently not found.");
			}
		};
	}
	::rptMsg("");
	$parent{systemroot} = $parent{systemroot}."\\" unless ($parent{systemroot} =~ m/\\$/);
	my $file = $parent{systemroot}."system32\\sdra64\.exe";
	if (-e $file && -f $file) {
		::rptMsg($file." found!");
		$check++;
	}
	else {
		::rptMsg($file." not found.");
	}
	
	if ($check == 0) {
		::rptMsg($parent{computername}." is apparently not infected with Zeus.");
	}
	else {
		::rptMsg($check." check(s) of two succeeded.");
	}
}

1;