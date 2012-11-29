package imm32;
#-----------------------------------------------------------
# imm32 - check imm32.dll for signs of tampering; during an
#    exam, imm32.dll had been modified to add another section, as well
#    as add a reference to a malicious DLL to the import table (IAT).
#
# Change History:
#   20120816 - updated
#   20111004 - Updated
#   20110323 - Updated reading of sections to use ReadPE.pm
#   20100928 - updated to include parsing of PE Sections (Win32::Exe)
#   20100927 - Created
#
# References:
#   http://vil.nai.com/vil/content/v_142626.htm
#
#
# copyright 2012
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
use strict;

my %config = (hasShortDescr => 1,
	            shortDescr    => "Check imm32\.dll for indications of tampering",
							category      => "Malware",
							class         => 0, # system = 0, user = 1
							output        => "report",
							type          => "File",
              osmask        => 3, #as of 20120816, focus on XP, 2003 primarily
              version       => 20120816);

sub getConfig{return \%config}
my $VERSION = $config{version};
sub getShortDescr { return $config{shortDescr};}
sub pluginmain {
	my $class = shift;
	my $parent = ::getConfig();
	::logMsg("imm32 v.".$VERSION);
	::rptMsg("-" x 60);
	::rptMsg("imm32 v.".$VERSION);
	::rptMsg(getShortDescr());
	::rptMsg("Category: ".$config{category});
	::rptMsg("");
	my $win = WinFile->new();
	my $file = $parent->{drive}."Windows\\system32\\imm32\.dll";
	::rptMsg("File: ".$file);
	if (-e $file && -f $file) {
		my $md5 = $win->getMD5($file);
		::rptMsg("  MD5        : ".$md5);
		
		my %sect = getPESections($file);
		foreach my $s (keys %sect) {
			::rptMsg("Section: ".$s."  Virt Size: ".$sect{$s}{virt_sz});
			::rptMsg("");
		}
	}
	else {
		::rptMsg($file." not found.");
	}
}

sub getPESections {
	my $file = shift;
	my %sect;
	my $pe = ReadPE::new($file);
	my %dos = $pe->getDOSHeader();
  my %fh = $pe->getFileHeader($dos{e_lfanew});
  my %opt32 = $pe->getOptionalHeader32($dos{e_lfanew},$fh{size_opt_header});
  my $sections_offset = $dos{e_lfanew} + 24 + 96 + (8*$opt32{rva_num});
	my %sections = $pe->getImageSectionHeaders($sections_offset,$fh{number_sections});
	
	$pe->close();
	return %sections;
}
1;