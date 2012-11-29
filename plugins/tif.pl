package tif;
#-----------------------------------------------------------
# tif - Plugin to parse through user profile Temporary Internet Files
#   dir (based on ProfileList key) and look for "suspicious" files.
#
# Change History
#   20120823 - updated to FS format
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
							output        => "report",
              osmask        => 31,
              class         => 1,
              version       => 20120823);

sub getConfig{return \%config};
my $VERSION = $config{version};
sub getShortDescr { return $config{shortDescr};}
sub pluginmain {
	my $class = shift;
	my $parent = ::getConfig();
	
	::logMsg("tif v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("tif v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
		
	my $profile = $parent->{userprofile};
	::rptMsg("Profile: ".$profile);
	$profile .= "\\" unless ($profile =~ m/\\$/);	
	
	my $path;
	
	if ($parent->{CurrentVersion} >= 6.0) {
		$path = $profile."AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Low\\Content\.IE5\\";
	}
	else {
		$path = $profile."Local Settings\\Temporary Internet Files\\Content\.IE5\\";
	}
	
	if (-e $path && -d $path) {
		::rptMsg("Path: ".$path);
		my @dirs;
		opendir(DIR,$path);
		while(readdir(DIR)) {
			next if ($_ =~ m/^\./);
			push(@dirs,$_) if (-d $path.$_);
		}
		closedir(DIR);
		
		foreach my $d (@dirs) {
			my $tif = $path.$d."\\";
			::rptMsg("Checking ".$tif."...");
			checkTMP($tif);		
			checkPDF($tif);
			checkEXE($tif);
			::rptMsg("");
		}
	}
	else {
		::rptMsg($path." not found.");
	}
}

sub checkTMP {
	my $path = shift;
	my $win = WinFile->new();
	my @files;
	
	opendir(DIR,$path);
	@files = map{$path.$_}(grep(/\.tmp$/i,readdir(DIR)));
	closedir(DIR);
	
	if (scalar @files > 0) {
		foreach my $f (@files) {
			::rptMsg("  File with \.tmp extension:");
			::rptMsg("    ".$f);
			::rptMsg("    MD5: ".$win->getMD5($f));
			::rptMsg("**File has MZ signature!") if ($win->isMZSig($f));
		}
	}
	else {
		::rptMsg("  No files with \.tmp extension found.");
	}
}

sub checkPDF {
	my $path = shift;
	my $win = WinFile->new();
	my @files;
	
	opendir(DIR,$path);
	@files = map{$path.$_}(grep(/\.pdf$/i,readdir(DIR)));
	closedir(DIR);
	
	if (scalar @files > 0) {
		foreach my $f (@files) {
			::rptMsg("  File with \.pdf extension:");
			::rptMsg("    ".$f);
			::rptMsg("    MD5: ".$win->getMD5($f));
		}
	}
	else {
		::rptMsg("  No files with \.pdf extension found.");
	}
}


sub checkEXE {
	my $path = shift;
	my $win = WinFile->new();
	my @files;
	
	opendir(DIR,$path);
	@files = map{$path.$_}(grep(/\.exe$/,readdir(DIR)));
	closedir(DIR);
	 
	if (scalar @files > 0) {
		foreach my $f (@files) {
			if ($win->isMZSig($f)) {
				::rptMsg("  File with \.exe extension and signature found:");
				::rptMsg("    ".$f);
				::rptMsg("    MD5: ".$win->getMD5($f));
			}
		}
	}
	else {
		::rptMsg("  No files with a \.exe extension found.");
	}
}

1;