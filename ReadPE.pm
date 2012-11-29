package ReadPE;
$VERSION = 0.1;
#------------------------------------------------------
# ReadPE.pm
# Perl module to make accessing PE file headers easier
#
# Usage: within a Perl script; use ReadPE;
# Installation: Copy this file to the site/lib/File directory
#               within your Perl installation
#
# copyright 2006-2012 H. Carvey keydet89@yahoo.com
#
# This software is released under the Perl Artistic License:
# http://dev.perl.org/licenses/artistic.html
#------------------------------------------------------
use strict;
use vars qw($VERSION @ISA @EXPORT_OK);
use Carp;

require Exporter;

@ISA         = qw(Exporter);
@EXPORT_OK   = qw(new);

my $self;				# self reference

#---------------------------------------------------------------------
# new()
# Opens file in binary mode; blesses self, including file handle
# Input : Name of file to be opened
# Output: Blessed object reference; includes file handle
# Sets  : file handle 
#---------------------------------------------------------------------      	    
sub new {
	$self = {};
	my $file = shift;
#	$self->{filesize} = (stat($self->{file}))[7];
	if (open($self->{hFile},"<",$file)) {
		binmode($self->{hFile});
		return bless($self);
	}
	else {
		carp "Could not open ".$file." : $! \n";
	}
}

#-------------------------------------------------------
# getDOSHeader()
# Reads first 64 bytes of file
# Input : 
# Output: DOS header hash (magic number and e_lfanew elements)
#-------------------------------------------------------
sub getDOSHeader {
	$self = $_[0];
	my %dos = ();
	my $record;
	seek($self->{hFile},0,0);
	my $bytes = read($self->{hFile},$record,64);
	if (64 == $bytes) {
		($dos{magic},$dos{e_ss},$dos{e_sp},$dos{e_csum},$dos{e_ip},
		 $dos{e_cs},$dos{e_oemid},$dos{e_oeminfo},$dos{e_lfanew})
		 = unpack("vx12v5x12v2x20V",$record);
		return %dos;		
	}
	else {
		$self->{error} = "$bytes of 64 bytes read in getDOSHeader()";
		return %dos;
	}
}

#-------------------------------------------------------
# getNTHeader()
# Input : 'e_lfanew' value
# Output: DWORD located at 'e_lfanew'
#-------------------------------------------------------
sub getNTHeader {
	$self = $_[0];
	my $ofs = $_[1];
	my $record;
	seek($self->{hFile},$ofs,0);
	my $bytes = read($self->{hFile},$record,4);
	if (4 == $bytes) {
		return unpack("V",$record);
	}
	else {
		$self->{error} = "$bytes of 4 bytes read in getNTHeader()";
		return 0;
	}
}

#-------------------------------------------------------
# getFileHeader()
# Input : 'e_lfanew' value
# Output: Hash containing elements of IMAGE_FILE_HEADER
# Ref   : http://msdn.microsoft.com/library/default.asp?url=
#         /library/en-us/debug/base/image_file_header_str.asp
#-------------------------------------------------------
sub getFileHeader {
	$self   = $_[0];
	my $ofs = $_[1];
	my %ifh = ();
	my $record;
	seek($self->{hFile},$ofs + 4,0);
	my $bytes = read($self->{hFile},$record,20);
	if ($bytes == 20) {
		($ifh{machine},$ifh{number_sections},$ifh{datetimestamp},$ifh{ptr_symbol_table},
		$ifh{number_symbols},$ifh{size_opt_header},$ifh{characteristics}) 
			= unpack("vvVVVvv",$record);
		$self->{size_opt_header} = $ifh{size_opt_header};
		return %ifh;
	}
	else {
		$self->{error} = "$bytes of 20 bytes read in getFileHeader()";
		return %ifh;
	}
}

#-------------------------------------------------------
# getFileHeaderCharacteristics()
# Input : WORD (2 byte) 'characteristics' value from
#         IMAGE_FILE_HEADER structure 
# Output: List containing characteristics
#-------------------------------------------------------
sub getFileHeaderCharacteristics {
	$self    = $_[0];
	my $char = $_[1];
	my @list = ();
	my %chars = (0x0001 => "IMAGE_FILE_RELOCS_STRIPPED",
							 0x0002 => "IMAGE_FILE_EXECUTABLE_IMAGE",
							 0x0004 => "IMAGE_FILE_LINE_NUMS_STRIPPED",
							 0x0008 => "IMAGE_FILE_LOCAL_SYMS_STRIPPED",
							 0x0010 => "IMAGE_FILE_AGGRESIVE_WS_TRIM",
							 0x0020 => "IMAGE_FILE_LARGE_ADDRESS_AWARE",
							 0x0080 => "IMAGE_FILE_BYTES_REVERSED_LO",
							 0x0100 => "IMAGE_FILE_32BIT_MACHINE",
							 0x0200 => "IMAGE_FILE_DEBUG_STRIPPED",
							 0x0400 => "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", 
							 0x0800 => "IMAGE_FILE_NET_RUN_FROM_SWAP",
							 0x1000 => "IMAGE_FILE_SYSTEM",
							 0x2000 => "IMAGE_FILE_DLL",
							 0x4000 => "IMAGE_FILE_UP_SYSTEM_ONLY",	
							 0x8000 => "IMAGE_FILE_BYTES_REVERSED_HI");

	foreach my $c (keys %chars) {
		push(@list,$chars{$c}) if ($char & $c);
	}
	return @list;
}

#-------------------------------------------------------
# getFileHeaderMachine()
# Input : WORD (2 byte) 'machine' value from
#         IMAGE_FILE_HEADER structure 
# Output: Architecture type of the image
#-------------------------------------------------------
sub getFileHeaderMachine {
	$self    = $_[0];
	my $word = $_[1];
	my %mach = (0x014c => "IMAGE_FILE_MACHINE_I386",
							0x014d => "IMAGE_FILE_MACHINE_I860",
							0x0184 => "IMAGE_FILE_MACHINE_ALPHA",
							0x01c0 => "IMAGE_FILE_MACHINE_ARM",
							0x01c2 => "IMAGE_FILE_MACHINE_THUMB",
							0x01f0 => "IMAGE_FILE_MACHINE_POWERPC",
							0x0284 => "IMAGE_FILE_MACHINE_ALPHA64",
	            0x0200 => "IMAGE_FILE_MACHINE_IA64",
	            0x8664 => "IMAGE_FILE_MACHINE_AMD64");
							 
	foreach my $m (keys %mach) {
		return $mach{$m} if ($word & $m);
	}
}

#-------------------------------------------------------
# getOptionalHeaderMagic()
# Determine which optional header needs to be read
# Input : 'e_lfanew' value
# Output: Value of the magic number of the IMAGE_OPTIONAL_HEADER
#         structure
#-------------------------------------------------------
sub getOptionalHeaderMagic {
	$self   = $_[0];
	my $ofs = $_[1];
	my $record;
# size of the IMAGE_NT_HEADER is 4 bytes, and the size of the 
# IMAGE_FILE_HEADER is 20 bytes; the IMAGE_OPTIONAL_HEADER structure
# immediately follows the IMAGE_FILE_HEADER structure
	seek($self->{hFile},$ofs + 24,0);
	read($self->{hFile},$record,2);
	my $magic = unpack("v",$record);
	$self->{optHdr32} = 1 if (0x10b == $magic);
	return $magic;
}

#-------------------------------------------------------
# getOptionalHeader32()
# Input : 'e_lfanew' value and the size of the optional header 
#         (derived from the IMAGE_FILE_HEADER structure)
# Output: Hash containing elements of IMAGE_OPTIONAL_HEADER
#         (32-bit version)
#-------------------------------------------------------
sub getOptionalHeader32 {
	$self    = $_[0];
	my $ofs  = $_[1];
	my $size = $_[2];
	my %opt32  = ();
	my $record;
# size of the IMAGE_NT_HEADER is 4 bytes, and the size of the 
# IMAGE_FILE_HEADER is 20 bytes; the IMAGE_OPTIONAL_HEADER structure
# immediately follows the IMAGE_FILE_HEADER structure
	seek($self->{hFile},$ofs + 24,0);
	my $bytes = read($self->{hFile},$record,$size);
	if ($bytes == $size) {
		($opt32{magic},$opt32{majlinkver},$opt32{minlinkver},$opt32{codesize},
		 $opt32{initdatasz},$opt32{uninitdatasz},$opt32{addr_entrypt},$opt32{codbase},
		 $opt32{database},$opt32{imagebase},$opt32{sectalign},$opt32{filealign},
		 $opt32{os_maj},$opt32{os_min},$opt32{image_maj},$opt32{image_min},
		 $opt32{image_sz},$opt32{head_sz},$opt32{checksum},$opt32{subsystem},
		 $opt32{dll_char},$opt32{rva_num}) = unpack("vCCV9v4x8V3vvx20Vx4",$record);		
		 return %opt32;
	}
	else {
		$self->{error} = "$bytes of $size bytes read in getOptionalHeader32()";
		return %opt32;
	}
}

#---------------------------------------------------------------------
# getOptionalHeaderSubsystem()
# Determine the subsystem required to run this image
# Input : WORD (2-byte) 'subsystem' value from the IMAGE_OPTIONAL_HEADER
#         structure
# Output: String containing name of subsystem
#---------------------------------------------------------------------
sub getOptionalHeaderSubsystem {
	$self = shift;
	my $word = shift;
	my %subs = (0 => "IMAGE_SUBSYSTEM_UNKNOWN",
	            1 => "IMAGE_SUBSYSTEM_NATIVE",
	            3 => "IMAGE_SUBSYSTEM_WINDOWS_CUI",
	            2 => "IMAGE_SUBSYSTEM_WINDOWS_GUI",
	            5 => "IMAGE_SUBSYSTEM_OS2_CUI",
	            7 => "IMAGE_SUBSYSTEM_POSIX_CUI",
	            8 => "IMAGE_SUBSYSTEM_NATIVE_WINDOWS",
	            9 => "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
	            14 => "IMAGE_SUBSYSTEM_XBOX");

	foreach my $s (keys %subs) {
		return $subs{$s} if ($word == $s);
	}
}

#-------------------------------------------------------
# getImageDataDirectories()
# Input : 'e_lfanew' value, and 'rva_num' value from the 
#         IMAGE_OPTIONAL_HEADER structure
# Output: Hash of hashes containing listing of IMAGE_DATA_DIRECTORY
#         structures
#-------------------------------------------------------
sub getImageDataDirectories {
	$self    = shift;
	my $ofs  = shift;
	my $rvas = shift;
	my %dd     = ();
	my $record;
	
	my @dd_names = qw/ExportTable ImportTable ResourceTable ExceptionTable 
						 CertificateTable BaseRelocTable DebugTable ArchSpecific  
						 GlobalPtrReg TLSTable LoadConfigTable BoundImportTable 
						 IAT DelayImportDesc CLIHeader unused/;
# The IMAGE_FILE_HEADER is 24 bytes in size;						 
# The header of the IMAGE_OPTIONAL_HEADER structure is 96 bytes	in size;
# The IMAGE_DATA_DIRECTORY structures immediately follow the header of the 
# IMAGE_OPTIONAL_HEADER structure
	my $opt_hdr_size = 96 if (1 == $self->{optHdr32}); 
	seek($self->{hFile},$ofs + 24 + $opt_hdr_size,0);
	my $bytes = read($self->{hFile},$record,8*$rvas);
	if ($bytes == (8*$rvas)) {
		my @rva_list = unpack("VV" x $rvas,$record);
		foreach my $i (0..($rvas - 1)) {
			$dd{$dd_names[$i]}{rva} = $rva_list[($i*2)];
			$dd{$dd_names[$i]}{size} = $rva_list[($i*2)+1];
		}
		return %dd;
	}
	else {
		$self->{error} = "$bytes of ".(8*$rvas)." bytes read in getDataDirectories()";
		return %dd;
	}
}

#-------------------------------------------------------
# getImageSectionHeaders()
# Input :
# Output:
# http://msdn.microsoft.com/library/default.asp?url=/library/en-us/debug/
#        base/image_section_header_str.asp
#-------------------------------------------------------
sub getImageSectionHeaders {
	$self   = shift;
	my $ofs = shift;
	my $num = shift;
# Each section is 40 bytes in size, and all sections are contiguous
	my $sec_sz = 40;
	my $record;
	my %sec    = ();
	foreach my $i (0..($num - 1)) {
		seek($self->{hFile},$ofs + ($sec_sz * $i),0);
		read($self->{hFile},$record,$sec_sz);
		my ($name,$virt_sz,$virt_addr,$rdata_sz,$rdata_ptr,$char) 
			= unpack("a8V4x12V",$record);
		$name =~ s/\00+$//;
		$sec{$name}{virt_sz}         = $virt_sz;
		$sec{$name}{virt_addr}       = $virt_addr;
		$sec{$name}{rdata_sz}        = $rdata_sz;
		$sec{$name}{rdata_ptr}       = $rdata_ptr;
		$sec{$name}{characteristics} = $char;
	} 
	return %sec;
}
#----------------------------------------------------------------
# getImageSectionCharacteristics() subroutines
# Input : 'characteristics' value from the section header structure
# Output: list containing characteristics
#----------------------------------------------------------------
sub getImageSectionCharacteristics {
	$self = shift;
	my $char = shift;
	my @characteristics = ();
	my %char_hash = (0x00000000 => "IMAGE_SCN_TYPE_REG",
		0x00000001 => "IMAGE_SCN_TYPE_DSECT",
		0x00000002 => "IMAGE_SCN_TYPE_NOLOAD",
		0x00000004 => "IMAGE_SCN_TYPE_GROUP",
		0x00000008 => "IMAGE_SCN_TYPE_NO_PAD",
		0x00000010 => "IMAGE_SCN_TYPE_COPY",
		0x00000020 => "IMAGE_SCN_CNT_CODE",
		0x00000040 => "IMAGE_SCN_CNT_INITIALIZED_DATA",
		0x00000080 => "IMAGE_SCN_CNT_UNINITIALIZED_DATA",
		0x00000100 => "IMAGE_SCN_LNK_OTHER",
		0x00000200 => "IMAGE_SCN_LNK_INFO",
		0x00000400 => "IMAGE_SCN_TYPE_OVER",
		0x00001000 => "IMAGE_SCN_LNK_COMDAT",
		0x00008000 => "IMAGE_SCN_MEM_FARDATA",
		0x00020000 => "IMAGE_SCN_MEM_PURGEABLE",
		0x00020000 => "IMAGE_SCN_MEM_16BIT",
		0x00040000 => "IMAGE_SCN_MEM_LOCKED",
		0x00080000 => "IMAGE_SCN_MEM_PRELOAD",
		0x00100000 => "IMAGE_SCN_ALIGN_1BYTES",
		0x00200000 => "IMAGE_SCN_ALIGN_2BYTES",
		0x00300000 => "IMAGE_SCN_ALIGN_4BYTES",
		0x00400000 => "IMAGE_SCN_ALIGN_8BYTES",
		0x00500000 => "IMAGE_SCN_ALIGN_16BYTES",
		0x00600000 => "IMAGE_SCN_ALIGN_32BYTES",
		0x00700000 => "IMAGE_SCN_ALIGN_64BYTES",
		0x00800000 => "IMAGE_SCN_ALIGN_128BYTES",
		0x00900000 => "IMAGE_SCN_ALIGN_256BYTES",
		0x00A00000 => "IMAGE_SCN_ALIGN_512BYTES",
		0x00B00000 => "IMAGE_SCN_ALIGN_1024BYTES",
		0x00C00000 => "IMAGE_SCN_ALIGN_2048BYTES",
		0x00D00000 => "IMAGE_SCN_ALIGN_4096BYTES",
		0x00E00000 => "IMAGE_SCN_ALIGN_8192BYTES",
		0x01000000 => "IMAGE_SCN_LNK_NRELOC_OVFL",
		0x02000000 => "IMAGE_SCN_MEM_DISCARDABLE",
		0x04000000 => "IMAGE_SCN_MEM_NOT_CACHED",
		0x08000000 => "IMAGE_SCN_MEM_NOT_PAGED",
		0x10000000 => "IMAGE_SCN_MEM_SHARED",
		0x20000000 => "IMAGE_SCN_MEM_EXECUTE",
		0x40000000 => "IMAGE_SCN_MEM_READ",
		0x80000000 => "IMAGE_SCN_MEM_WRITE");
	
	foreach my $ch (keys %char_hash) {
		push(@characteristics, $char_hash{$ch}) if ($char & $ch);
	}
	return @characteristics; 
}

#----------------------------------------------------------------
# getXXXX() subroutines
# Gets the contents of various elements of $self
#----------------------------------------------------------------
sub getError {return $self->{error};}
sub getFileHandle {return $self->{hFile};}
#---------------------------------------------------------------------
# close()
# close the filehandle
#---------------------------------------------------------------------
sub close {close($self->{hFile});}

1;
__END__

=head1 NAME

File::ReadPE

=head1 VERSION

Version 0.1

=head1 DESCRIPTION

File::ReadPE - Perl module to read/parse Windows PE file structures without using the Win32 API.  This allows
for Win32 image (ie, malware) analysis on any platform that supports Perl.  This module retrieves relative
portions of the following structures:

IMAGE_DOS_HEADER
IMAGE_FILE_HEADER
IMAGE_NT_HEADER
IMAGE_OPTIONAL_HEADER(32)
IMAGE_DATA_DIRECTORY
IMAGE_SECTION_HEADER

The module also contains several functions to perform translation of 'characteristics' values from the
various structures.

=head1 SYNOPSIS

  use ReadPE;
	my $pefile = shift || die "You must enter a filename.\n";
	die "File not found.\n" unless (-e $pefile);

	my $pe = ReadPE::new($pefile);
	my %dos;
	if (%dos = $pe->getDOSHeader()) {
		printf "magic      : 0x%x\n",$dos{magic};
		printf "e_lfanew   : 0x%x\n",$dos{e_lfanew};
	}
	else {
		print "Error : ".$pe->getError()."\n";
	}

	printf "PE header = 0x%x\n",$pe->getNTHeader($dos{e_lfanew});
	
	my %fh = $pe->getFileHeader($dos{e_lfanew});
	map{printf "%-30s 0x%x\n",$_,$fh{$_};}(keys %fh);
	
	print "\n";
	my @list = $pe->getFileHeaderCharacteristics($fh{characteristics});
	map{print "\t$_\n";}@list;
	print "\n";
	
	my $hdr = $pe->getOptionalHeaderMagic($dos{e_lfanew});
	printf "Optional header magic = 0x%x\n",$hdr;
	print "\n";
	
	my %opt32 = $pe->getOptionalHeader32($dos{e_lfanew},$fh{size_opt_header});
	print "Subsystem = ".$pe->getOptionalHeaderSubsystem($opt32{subsystem})."\n";
	print "\n";

	my %dd = $pe->getImageDataDirectories($dos{e_lfanew},$opt32{rva_num});
	foreach my $d (keys %dd) {
		printf "%-20s 0x%08x 0x%08x\n",$d,$dd{$d}{rva},$dd{$d}{size};
	}
	print "\n";

# The PE header structures are contiguous from the $dos{e_lfanew} value; 
# To compute the location of the IMAGE_SECTION_HEADER structures, add the 
# size of the IMAGE_FILE_HEADER (24 bytes), the IMAGE_OPTIONAL_HEADER headers 
# (96 bytes for a 32-bit image), and the total size of the IMAGE_DATA_DIRECTORY
# structures (8 bytes x the number of data directories)	
	my $sections_offset = $dos{e_lfanew} + 24 + 96 + (8*$opt32{rva_num});
	my %sections = $pe->getImageSectionHeaders($sections_offset,$fh{number_sections});
	foreach my $sect (keys %sections) {
		print "$sect\n";
	}

	$pe->close();  

=head1 METHODS

=head2 $pe = File::ReadPE::new($filename)

Creates a new ReadPE object.  Opens a file handle and blesses the object. It is up to the script 
using this module to determine whether the file exists or not.

=head2 %dos = $pe->getDOSHeader()

Reads the first 64 bytes of the file and returns a hash containing the DOS header elements. The 
DOS header 'magic' ('MZ', or 0x5a4d) number is used to determine whether the image is a valid 
executable.  The 'e_lfanew' value is is the offset of the new, PE header, and is used as an 
input argument for some of the other methods.

=head2 $signature = $pe->getNTHeader($offset)

Reads the IMAGE_NT_HEADER signature located at the offset pointed to by 'e_lfanew'.  The method returns 
the DWORD value located at the 'e_lfanew' location, which should be 'PE\00\00' for a PE file.

=head2 %ifh = $pe->getFileHeader($offset)

Reads the IMAGE_FILE_HEADER structure, which follows the DWORD (4 byte) IMAGE_NT_HEADER structure.  On
success, returns a Perl hash containing the elements of the IMAGE_FILE_HEADER structure.

=head2 @list = $pe->getFileHeaderCharacteristics($characteristics)

Takes the 'characteristic' WORD value from the IMAGE_FILE_HEADER structure as an input, and returns a 
(Perl) list of characteristics of the image.

=head2 $machine = $pe->getFileHeaderMachine($machine)

Takes the 'machine' WORD value from the IMAGE_FILE_HEADER structure as an input, and returns the
architecture type of the system.

=head2 $magic = $pe->getOptionalHeaderMagic($offset)

Reads the 'magic' WORD value from the IMAGE_OPTIONAL_HEADER structure.  This value determines the type of 
the image (ie, 32-bit, 64-bit, or ROM).  This value is used in conjuction with the 'SizeofOptionalHeader' 
WORD value from the IMAGE_FILE_HEADER structure to determine the type and size of the IMAGE_OPTIONAL_HEADER 
structure.

=head2 %opt32 = $pe->getOptionalHeader32($offset,$size)

Reads in the IMAGE_OPTIONAL_HEADER structure as a 32-bit image header.  On success, returns a Perl hash
containing the elements of the 32-bit IMAGE_OPTIONAL_HEADER structure.

=head2 $sys = $pe->getOptionalHeaderSubsystem($subsystem)

Takes the 'subsystem' value from the IMAGE_OPTIONAL_HEADER structure and returns the subsystem required for
the image.

=head2 %dd = $pe->getImageDataDirectories($offset,$opt32{num_rvas})

Reads in the IMAGE_DATA_DIRECTORY structures as a hash-of-hashes Perl data structure.  Needs an offset, 
as well as the number of RVAs from the IMAGE_OPTIONAL_HEADER structure.

=head2 %sect = $pe->getImageSectionHeaders($offset,$ifh{number_sections})

Reads in the IMAGE_SECTION_HEADER structures as a hash-of-hashes Perl data structure.  Needs an offset,
and the number of sections to be read (WORD value from the IMAGE_FILE_HEADER structure)

=head2 @char = $pe->getImageSectionCharacteristics($characteristics)

Takes in the 'characteristics' value from the IMAGE_SECTION_HEADER structure, and returns a list
containing the various characteristics.

=head2 $pe->getError()

Returns the message stored in $self->{error}

=head2 $pe->getFileHandle()

Returns the file handle used by the object ($self->{hFile}); useful if you want to access bytes within 
the file from the script.

=head2 $pe->close()

Closes the file handle

=head1 REFERENCES

Structure definitions are located in winnt.h

pe_image.h - PE image structure definitions
http://research.microsoft.com/invisible/include/loaders/pe_image.h.htm

PE File Structure
http://www.madchat.org/vxdevl/papers/winsys/pefile/pefile.htm

Iczelion's PE Tutorial 2: Detecting a Valid PE File
http://win32assembly.online.fr/pe-tut2.html

ImageHlp API Structures
http://msdn.microsoft.com/library/default.asp?url=/library/en-us/debug/base/imagehlp_structures.asp

HOWTO: How To Determine Whether an Application is Console or GUI
http://support.microsoft.com/default.aspx?scid=kb;en-us;90493

=head1 AUTHOR

Harlan Carvey, E<lt>keydet89 at yahoo dot comE<gt>

=head1 DOCUMENTATION

You can find documentation for this module using the perldoc command.

=head1 BUGS

Please report any bugs and feature requests to keydet89 at yahoo dot com.

=head1 TODO

Need to create modules for parsing import/export tables, resource tables, etc.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Harlan Carvey (keydet89 at yahoo dot com)

This library is free software; you can redistribute it and/or modify
it as you like.  However, please be sure to provide proper credit where
it is due.

=cut
