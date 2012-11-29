package usertemp;
#-----------------------------------------------------------
# usertemp - Plugin to parse through user profile Temp folder looking
#    for suspicious files.
#
# XP/2003: Local Settings\Temp
# Vista+ : AppData\Local\Temp
#
# History
#   20120823 - renamed; was "localsettings.pl", changed to current name
#   20120822 - updated to current format
#   20100927 - created
# 
# copyright 2012
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
use strict;

my %config = (hasShortDescr => 1,
							category      => "Malware",
							shortDescr    => "Parse users Local Settings\\Temp dirs for suspicious files",
							type          => "File",
							class         => 1,
							output        => "report",
              osmask        => 31,
              version       => 20120822);

sub getConfig{return \%config};
my $VERSION = $config{version};
sub getShortDescr {
	return $config{shortDescr};
}
sub pluginmain {
	my $class = shift;
	my $parent = ::getConfig();

	::logMsg("usertemp v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("usertemp v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
	my $profile = $parent->{userprofile};
	::rptMsg("Profile: ".$profile);
	$profile .= "\\" unless ($profile =~ m/\\$/);
	
	my $temp;
	if ($parent->{CurrentVersion} >= 6.0) {
		$temp = $profile."AppData\\Local\\Temp\\";
	}
	else {
		$temp = $profile."Local Settings\\Temp\\";
	} 
	
	checkTmp($temp);
	checkExe($temp);

}

sub checkTmp {
	my $path = shift;
	my $win = WinFile->new();
	my @files;
	
	opendir(DIR,$path);
	@files = map{$path.$_}(grep(/\.tmp$/,readdir(DIR)));
	closedir(DIR);
	
	if (scalar @files > 0) {
		foreach my $f (@files) {
			if ($win->isMZSig($f)) {
				::rptMsg("File with \.tmp extension and MZ signature:");
				::rptMsg("  ".$f);
				::rptMsg("  MD5: ".$win->getMD5($f));
				::rptMsg("");
			}
		}
	}
	else {
		::rptMsg("No files with \.tmp extension found.");
		::rptMsg("");
	}
}

sub checkExe {
	my $path = shift;
	my $win = WinFile->new();
	my @files;
	
	opendir(DIR,$path);
	@files = map{$path.$_}(grep(/\.exe$/,readdir(DIR)));
	closedir(DIR);
	 
	if (scalar @files > 0) {
		foreach my $f (@files) {
			if ($win->isMZSig($f)) {
				::rptMsg("File with \.exe extension found:");
				::rptMsg("  ".$f);
				::rptMsg("  MD5: ".$win->getMD5($f));
				::rptMsg("");
			}
		}
	}
	else {
		::rptMsg("No files with a \.exe extension found.");
		::rptMsg("");
	}
}

1;