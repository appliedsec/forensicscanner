package prefetch;
#-----------------------------------------------------------
# prefetch - List .pf files in %SystemRoot%\Prefetch dir
#
# Change History:
#   20120822 - updated to current plugin format
#   20110323 - created
#
# To-Do:
#  Implement Prefetch file parsing
#
# copyright 2012
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
use strict;

my %config = (hasShortDescr => 1,
							shortDescr    => "List \.pf files in %SystemRoot%\\Prefetch dir",
							category      => "Malware",
							type          => "File",
							output        => "report",
							class         => 0, # 0 = system, 1 = user
              osmask        => 21, #XP,Vista, Win7
              version       => 20120822);

sub getConfig{return \%config}
my $VERSION = $config{version};
sub getShortDescr {
	return "Gets contents of Prefetch folder";	
}

sub pluginmain {
	my $class = shift;
	my $parent = ::getConfig();
	::logMsg("prefetch v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("prefetch v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
	
	my $dir = $parent->{systemroot}."Prefetch";
	::rptMsg("Directory : ".$dir);
	my @files;
	
	if (-e $dir && -d $dir) {
		opendir(DIR,$dir);
		my @files = grep(/\.pf$/,readdir(DIR));
		closedir(DIR);
		
		if (scalar @files > 0) {
			foreach my $f (@files) {
				::rptMsg(" ".$f);
			}
		}
		else {
			::rptMsg($dir." has no \.pf files.");
		}
		
	}
	else {
		::rptMsg($dir." not found.");
	}
}
1;