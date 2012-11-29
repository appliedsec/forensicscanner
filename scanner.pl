#! c:\perl\bin\perl.exe
#-----------------------------------------------------------
# Forensic Scanner
# 
# Change History:
#  20120815 - created
#  
# created for ASI
# Author: H. Carvey, keydet89@yahoo.com
# 
# This software is released under the Perl Artistic License:
# http://dev.perl.org/licenses/artistic.html
#-----------------------------------------------------------
#use strict;
use Win32::GUI();
use Time::Local;
use Parse::Win32Registry qw(:REG_);

use Engine;
use WinFile;
use ReadPE;
#use Win32::URLCache;

# File containing 'helper' functions, available to the plugins
require 'time.pl';

# Included to permit compiling via Perl2Exe
#perl2exe_include "Parse/Win32Registry.pm";
#perl2exe_include "Parse/Win32Registry/Key.pm";
#perl2exe_include "Parse/Win32Registry/Entry.pm";
#perl2exe_include "Parse/Win32Registry/Value.pm";
#perl2exe_include "Parse/Win32Registry/File.pm";
#perl2exe_include "Parse/Win32Registry/Win95/File.pm";
#perl2exe_include "Parse/Win32Registry/Win95/Key.pm";
#perl2exe_include "Encode.pm";
#perl2exe_include "Encode/Byte.pm";
#perl2exe_include "Encode/Unicode.pm";
#perl2exe_include "utf8.pm";
#perl2exe_include "unicore/Heavy.pl";
#perl2exe_include "unicore/To/Upper.pl";
#-----------------------------------------------------------
# Global variables
#-----------------------------------------------------------
my $VERSION = "20120926";
my %env; 
my $eng;
my $tag;
my %users;

my %os_table = ('5.1' => 1,
								'5.2' => 2,
								'6.0' => 4,
								'6.1' => 16);
								
#-----------------------------------------------------------
# GUI
#-----------------------------------------------------------
# create our menu
my $menu = Win32::GUI::MakeMenu(
		"&File"                => "File",
		" > O&pen..."          => { -name => "Open"},
		" > -"                 => 0,
    " > E&xit"             => { -name => "Exit", -onClick => sub {exit 1;}},
    "&Help"                => "Help",
    " > &About"            => { -name => "About", -onClick => \&FS_OnAbout},
);

# Create Main Window
my $main = new Win32::GUI::Window (
    -name     => "Main",
    -title    => "Forensic Scanner, v.".$VERSION,
    -pos      => [200, 200],
# Format: [width, height]
    -maxsize  => [490, 530],
    -size     => [490, 530],
    -menu     => $menu,
    -dialogui => 1,
) or die "Could not create a new Window: $!\n";

$main->AddLabel(
	-text => "",
	-name => "border1",
	-pos => [10,5],
	-size => [445,130],
	-frame => etched,
	-sunken => 1
);

$main->AddLabel(
    -text   => "System32 Path:",
    -left   => 20,
    -top    => 20);
    
my $path = $main->AddTextfield(
    -name     => "path",
    -tabstop  => 1,
    -left     => 100,
    -top      => 20,
    -width    => 250,
    -height   => 22,
    -tabstop  => 1,
    -foreground => "#000000",
    -background => "#FFFFFF");

my $browse1 = $main->AddButton(
		-name => 'browse1',
		-left => 375,
		-top  => 20,
		-width => 50,
		-height => 22,
		-tabstop  => 1,
		-text => "Browse");

$main->AddLabel(
    -text   => "Report Dir:",
    -left   => 20,
    -top    => 60);
    
my $rptdir = $main->AddTextfield(
    -name     => "rptdir",
    -tabstop  => 1,
    -left     => 100,
    -top      => 60,
    -width    => 250,
    -height   => 22,
    -tabstop  => 1,
    -foreground => "#000000",
    -background => "#FFFFFF");

my $browse2 = $main->AddButton(
		-name => 'browse2',
		-left => 375,
		-top  => 60,
		-width => 50,
		-height => 22,
		-tabstop  => 1,
		-text => "Browse");

my $init = $main->AddButton(
		-name => 'init',
		-left => 375,
		-top  => 100,
		-width => 50,
		-height => 22,
		-tabstop  => 1,
		-text => "Init");

my $user1 = $main->AddListbox(
    -name    => 'user1',
    -pos     => [40,145],
    -size    => [130,90],
    -vscroll => 1,
    -multisel => 2);

my $add = $main->AddButton(
		-name => 'add',
		-left => 205,
		-top  => 150,
		-width => 50,
		-height => 22,
		-tabstop  => 1,
		-text => ">>");

my $remove = $main->AddButton(
		-name => 'remove',
		-left => 205,
		-top  => 200,
		-width => 50,
		-height => 22,
		-tabstop  => 1,
		-text => "<<");

my $user2 = $main->AddListbox(
    -name    => 'user2',
    -pos     => [290,145],
    -size    => [130,90],
    -vscroll => 1,
    -multisel => 2);


$main->AddLabel(
	-text => "",
	-name => "border2",
	-pos => [10,240],
	-size => [445,160],
	-frame => etched,
	-sunken => 1
);

my $report = $main->AddTextfield(
    -name      => "Report",
    -pos       => [20,250],
    -size      => [425,140],
    -multiline => 1,
    -vscroll   => 1,
    -autohscroll => 1,
    -autovscroll => 1,
    -keepselection => 1 ,
    -tabstop => 1,
);

my $scan = $main->AddButton(
		-name => 'scan',
		-left => 320,
		-top  => 410,
		-width => 50,
		-height => 25,
		-tabstop => 1,
		-text => "Scan");
		
$main->AddButton(
		-name => 'close',
		-left => 390,
		-top  => 410,
		-width => 50,
		-height => 25,
		-tabstop => 1,
		-text => "Close");

my $status = new Win32::GUI::StatusBar($main,
		-text  => "Forensic Scanner v.".$VERSION." opened.",
);


#$status->Text("blah");

$main->Show();
Win32::GUI::Dialog();
#-----------------------------------------------------------
sub Open_Click {
	\&browse1_Click();	
}

sub browse1_Click {
  my $dir = Win32::GUI::BrowseForFolder(
                   -title => "System32 Dir",
                -root => 0x0011,
                -folderonly => 1,
                -includefiles => 0);
  
  $path->Text($dir);
  0;
}

sub browse2_Click {
  my $dir = Win32::GUI::BrowseForFolder(
                   -title => "Report Dir",
                -root => 0x0011,
                -folderonly => 1,
                -includefiles => 0);
  
  $rptdir->Text($dir);
  0;
}

sub init_Click {
	$user1->ResetContent();
	$user2->ResetContent();
	
	my $system32dir = $path->Text();
# Add check to access the mounted volume	
	if (opendir(DIR,$system32dir)) {
		
	}
	else {
		Win32::GUI::MessageBox($main,"You cannot access ".$system32dir.".\r\n",
		                       "Access Error!",16);
		return;
	}	

# Generate a unique tag for the scan
	$tag = genTag();
	
	my $reportdir   = $rptdir->Text();
	$reportdir .= "\\" unless ($reportdir =~ m/\\$/);
	
# Get System information 	
	$eng = Engine->new();
	$eng->systemDir($system32dir);
#	$eng->reportDir($reportdir);

# Populate the global %env hash; data needs to be available
# to the plugins
	%env = $eng->getSystemInfo();
	
	$env{reportfile} = $reportdir.$env{computername}."-".$tag."\.txt";
	$env{logfile}    = $reportdir.$env{computername}."-".$tag."\.log";
	
	$report->Append("Environment variables populated, available to the plugins\r\n");	
	$report->Append("Report File: ".$env{reportfile}."\r\n");
	$report->Append("Log File   : ".$env{logfile}."\r\n");
# user profiles	
	%users = $eng->getUserInfo();
	foreach my $u (keys %users) {
		$user1->InsertString($u);
	}
	$report->Append("List of user profiles populated.\r\n");
	Win32::GUI::DoEvents();
}

# Copy a user profile name from the left panel to the right
sub add_Click {
	my @list = $user1->SelectedItems();
	foreach my $i (sort {$a <=> $b} @list) {
		my $str = $user1->GetString($i);
		$user2->InsertString($str);
	}
}

# Remove a user profile name from the right panel
sub remove_Click {
	my @list = $user2->SelectedItems();
	foreach my $i (reverse @list) {
		$user2->DeleteString($i);
	}
}

sub scan_Click {
# Get users to scan from right-side Listbox; if 
# no users selected, none to scan	
	my %usertemp = ();
	my $count = $user2->GetCount();
	foreach my $u (0..($count - 1)) {
		my $str = $user2->GetString($u);
		if (exists $users{$str}) {
			$usertemp{$str} = $users{$str};
		}
	}
	%users = %usertemp;

# Add configuration information to the log file
	logMsg("Scan Configuration Info");
	logMsg("-" x 60);
	logMsg($env{ProductName}." (".$env{CurrentVersion}.") ".$env{CSDVersion});
	logMsg("HostName: ".$env{hostname}."   InstallDate: ".$env{InstallDate}); 
	logMsg("");
	logMsg("User Profiles");
	foreach (keys %users) {
		logMsg(sprintf "%-20s  %-50s",$_,$users{$_});
	}
	logMsg("");
# Tell Engine.pm to sort the plugins, and build it's lists
	$eng->sortPlugins();
# Hash to maintain a list of executed plugins
  my %executed = ();
# get the system plugins	
	my %plugins = $eng->getSystemPlugins();
	foreach my $pl (keys %plugins) {
#		print "Running ".$pl." plugins...\n";
		foreach my $s (@{$plugins{$pl}}) {
			my @path = split(/\\/,$s);
			my $num = scalar(@path);
			my $plugin = $path[$num - 1];
			my $pkg = (split(/\./,$plugin,2))[0];
			$report->Append("Running plugin ".$pkg."...\r\n");
# Check to see if plugin has already been executed; if so, 
# don't do anything (write a log entry); otherwise, run it and
# add it to the list.
			if (exists $executed{$pkg}) {
				::logMsg("Plugin ".$pkg." has already been executed.");
			}
			else {
				eval{
					require $s;
					$pkg->pluginmain();
				};
				::logMsg($s." Error: ".$@) if ($@);
				$executed{$pkg} = 1;
			}
			Win32::GUI::DoEvents();
		}
	}

# Run user plugins	
	my %plugins = $eng->getUserPlugins();
	
	foreach my $u (keys %users) {
# Each plugin that access a user profile needs to call ::getConfig() and
# get $sys{userprofile}
		$env{userprofile} = $users{$u};
		my $reportdir   = $rptdir->Text();
		$reportdir .= "\\" unless ($reportdir =~ m/\\$/);
		$env{reportfile} = $reportdir.$u."-".$tag."\.txt";
		my %executed = ();
		
		foreach my $pl (keys %plugins) {
#			print "Running ".$pl." plugins against ".$u." profile...\n";
			foreach my $up (@{$plugins{$pl}}) {
				my @path = split(/\\/,$up);
				my $num = scalar(@path);
				my $plugin = $path[$num - 1];
				my $pkg = (split(/\./,$plugin,2))[0];
				$report->Append("Running plugin ".$pkg." against ".$u." profile...\r\n");
				# Check to see if plugin has already been executed; if so, 
# don't do anything (write a log entry); otherwise, run it and
# add it to the list.
				if (exists $executed{$pkg}) {
					::logMsg("Plugin ".$pkg." has already been executed.");
				}
				else {
					eval{
						require $up;
						$pkg->pluginmain();
					};
					::logMsg($s." Error: ".$@) if ($@);
					$executed{$pkg} = 1;
				}
				Win32::GUI::DoEvents();
			}
		}
	}
	$status->Text("Scan complete\.");
	$report->Append("Scan complete\.\r\n");
}

sub close_Click {
	exit 1;
}

# About box
sub FS_OnAbout {
  my $self = shift;

  $self->MessageBox(
     "Forensic Scanner, v.".$VERSION."\r\n".
     "\r\n".
     "\r\n".
     "Copyright 2012    \r\n".
     "Author: H\. Carvey, keydet89\@yahoo\.com",
     "About...",
     MB_ICONINFORMATION | MB_OK,
  );
  0;
}
#-----------------------------------------------------------

#-----------------------------------------------------------
sub logMsg {
	open(FH,">>",$env{logfile});
	print FH localtime(time).": ".$_[0]."\n";
	close(FH);
}

sub rptMsg {
	open(FH,">>",$env{reportfile});
	binmode FH,":utf8";
	print FH $_[0]."\n";
	close(FH);
}

sub getConfig {
	return \%env;
}

sub genTag {
# Generate a unique tag for the scan
	my @t = gmtime();	
	my $yy = sprintf("%02d", $t[5] % 100);
	my $mm = sprintf("%02d", $t[4] + 1);
	my $dd = sprintf("%02d", $t[3]);
	my $hr = sprintf("%02d", $t[2]);
	my $min = sprintf("%02d", $t[1]);
	my $sec = sprintf("%02d", $t[0]);
	return $yy.$mm.$dd.$hr.$min.$sec;
}
