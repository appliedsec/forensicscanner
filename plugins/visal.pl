package visal;
#-----------------------------------------------------------
# visal
# Check for indications of Visal.B infection
#
# Change History:
#   20120928 - updated to FS format
#   20100928 - created
#
# References:
#   http://www.microsoft.com/security/portal/Threat/Encyclopedia/
#          Entry.aspx?Name=Worm%3aWin32%2fVisal.B
#
# copyright 2010 Quantum Analytics Research, LLC
#-----------------------------------------------------------
use strict;

my %config = (hasShortDescr => 1,
							shortDescr    => "Check for Visal\.B infection",
							category      => "Malware",
							type          => "File+Reg",
							output        => "report",
							class         => 0,
              osmask        => 31,
              version       => 20120928);

sub getConfig{return \%config}
my $VERSION = $config{version};
sub getShortDescr { return $config{shortDescr};}
sub pluginmain {
	my $class = shift;
	my $win = WinFile->new();
	my $parent = ::getConfig();
	my $drv = $parent->{drive};
	my $checks = 0;
	
	::logMsg("visal\.b v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("visal\.b v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
	my $reg = Parse::Win32Registry->new($parent->{software});
	my $root_key = $reg->get_root_key;
	my $key_path = "Microsoft\\Windows NT\\CurrentVersion\\WinLogon";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		my $shell;
		eval {
			$shell = $key->get_value("Shell")->get_data();
			::rptMsg("Shell = ".$shell);
			if (grep(/csrss/,$shell)) {
				::rptMsg("**Possible Visal\.B detected.");
				$checks++;
			}
		};
		::rptMsg("Error getting Shell value: ".$@) if ($@);
	}
	else {
		::rptMsg($key_path." not found.");
	}
	::rptMsg("");
	my $file = $drv."Windows\\csrss\.exe";
#	::rptMsg("File: ".$file);
	if (-e $file && -f $file) {
		my $md5 = $win->getMD5($file);
		::rptMsg("  MD5        : ".$md5);
		$checks++;
	}
	else {
		::rptMsg($file." not found.");
	}
	if ($checks > 0) {
		::rptMsg("");
		::rptMsg("Possible Visal\.B infection detected.");
	}
}

1;