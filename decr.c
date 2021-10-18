#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TYPE_MCU 0
#define TYPE_PPM 1

typedef unsigned char byte;
typedef unsigned short half;
typedef unsigned int word;

typedef struct _
{
	word addr_bits;
	half xor_value;
}
ADDR_ADJ;


//#define ZERO_MASK 0x1956
#define ZERO_MASK 0x0000

half mbit[] = {
	0x1221, 0xA91A, 0x52A5, 0x0908, // 0001 0002 0004 0008
	0xa918, 0x1020, 0xFFFF, 0x52A1, // 0010 0020 0040 0080
	0x0100, 0x1220, 0xAD1A, 0x0900, // 0100 0200 0400 0800
	0x1000, 0x2908, 0x5221, 0xa908, // 1000 2000 4000 8000
};

half maddr[] = {
	0x0FAE, 0x3E7F, 0xC99F, 0xD6F7, // 00.0002 00.0004 00.0008 000.0010
	0xA71B, 0x14C4, 0x52A5, 0xCBB1, // 00.0020 00.0040 00.0080 000.0100
	0x4285, 0xEFDF, 0xDFF7, 0x5080, // 00.0200 00.0400 00.0800 000.1000
	0xEE9F, 0x0000, 0x8432, 0x5221, // 00.2000 00.4000 00.8000 001.0000
	0x4084, 0xA91A, 0x56E7, 0xB93A, // 02.0000 04.0000 08.0000 010.0000
	0x5B21, 0xA818, 0x0000, 0xEFDF, // 20.0000 40.0000 80.0000 100.0000
};
ADDR_ADJ maddr_adj[] = {
	{0x00140,	0x1000},
	{0x00220,	0x52a1},
	{0x00480,	0x1221},
	{0x00600,	0xB928},
	{0x00810,	0x5221},
	{0x00840,	0x1220},
	{0x00900,	0x2008},
	{0x01020,	0x1221},
	{0x01080,	0x0908},
	{0x01100,	0x52A1},
	{0x02020,	0x0100},
	{0x02080,	0xFBBD},
	{0x04010,	0xA91A},
	{0x04040,	0xA908},
	{0x08008,	0x2908},
	{0x09000,	0x1000},
	{0x0A000,	0xBD3A},
	{0x10010,	0xAD1A},
	{0x10040,	0x5221},
	{0x10400,	0x0908},
	{0x20200,	0x53A5},
	{0x40040,	0xA91A},
	{0x44000,	0x1B20},
	{0x80100,	0xA918},
	{0x800000,	0xB908},

	{0, 0}
};

half en_codes[65535];
half de_codes[65535];
half de_addr[0xFFFF];

half mcu_crypt_start = 0;
half mcu_flash_hdlen = 0;
word mcu_flash_start = 0;
half mcu_auto_offset = 0;
half ppm_auto_offset = 0;
half fls_fixchecksum = 1;
half mcu_auto_values = 0;
half ppm_auto_values = 0;
half fls_endianess = 0;


word
get_word ( FILE * fin )
{
	byte b[4];
	fread ( b, 1, 4, fin );
	return ( b[0] << 24 ) | ( b[1] << 16 ) | ( b[2] << 8 ) | ( b[3] );
}


word
get_chunk ( FILE * fin, byte * buf, word * addr )
{
	int len;
	byte b[10];

	if ( feof ( fin ) )
		return 0;

	do
	{
		if ( fread ( b, 1, 1, fin ) != 1 )
			return 0;

		if ( b[0] == 0x21 )
		{
			fread ( &b[1], 1, 5, fin );
		}
		else if ( b[0] == 0x20 )
		{
			fread ( &b[1], 1, 5, fin );
			len = ( b[3] << 8 ) | b[4];
			fread ( buf, 1, len, fin );
		}
	}
	while ( b[0] != 0x14 );

	*addr = get_word ( fin );
	fread ( b, 1, 5, fin );
	len = ( b[1] << 16 ) | ( b[2] << 8 ) | b[3];
	fread ( buf, 1, len, fin );
	return len / 2;
}

unsigned short
get_pt_from_ct ( unsigned short val )
{
	unsigned short nc = 0, i;

	for ( i = 0; i < 16; i++ )
		if ( val & ( 1 << i ) )
			nc ^= mbit[i];

	return nc;
}

half get_half ( byte *buf, word ofs )
{
	return ( buf[ofs] << 8 ) | buf[ofs ^ 1];
}

void set_half ( byte *buf, word ofs, half code )
{
	buf[ofs] = code >> 8;
	buf[ofs ^ 1] = ( byte ) code;
}


half address_bits ( half code, word addr )
{
	int i = 0;
	ADDR_ADJ *adj = maddr_adj;

	while ( adj->addr_bits )
	{
		if ( ( addr & adj->addr_bits ) == adj->addr_bits )
			code ^= adj->xor_value;
		adj++;
	}

	for ( i = 0; i < 24; i++ )
	{
		if ( addr & ( 1 << ( i + 1 ) ) )
			code ^= maddr[i];
	}
	return code;
}

half address_fix ( half code, word fad, half basecode )
{
	return code ^ basecode;

}

void
decode ( byte * buf, word addr, word len, half basecode, int type )
{
	word ofs, fad;
	int pos = 0;
	half code;

	for ( ofs = 0; ofs < len * 2; ofs += 2 )
	{
		fad = addr + ofs - mcu_flash_start;
		if ( fad >= mcu_crypt_start || type == TYPE_PPM )
		{
			code = get_half ( buf, ofs ^ fls_endianess );

			// Clean the special address bits
			code = address_bits ( code, addr + ofs );

			// Get the PT
			code = de_codes[code];

			// hack
			code = address_fix ( code, fad , basecode );

			set_half ( buf, ofs ^ fls_endianess, code );
		}
	}
}


void
encode ( byte * buf, word addr, word len, half basecode, int type )
{
	word ofs, fad;
	half code;

	for ( ofs = 0; ofs < len * 2; ofs += 2 )
	{
		fad = addr + ofs - mcu_flash_start;

		if ( fad >= mcu_crypt_start || type == TYPE_PPM )
		{
			code = get_half ( buf, ofs ^ fls_endianess );

			// hack
			code = address_fix ( code, fad, basecode );

			// Get the CT
			code = en_codes[code];

			// Clean the special address bits
			code = address_bits ( code, addr + ofs );

			set_half ( buf, ofs, code );
		}

	}
}

void
generate_codes (  )
{
	unsigned int c, nc, i;
	printf ( " - Generating codes      [" );
	for ( c = 0; c <= 65535; c++ )
	{
		if ( ( c & 0xF000 ) == c )
			printf ( "." );
		fflush ( stdout );
		nc = ZERO_MASK;
		for ( i = 0; i < 16; i++ )
			if ( c & ( 1 << i ) )
				nc ^= mbit[i];
		de_codes[nc]  = c;
		en_codes[c] = nc;
	}
//	printf ( "\n" );
	for ( c = 0; c <= 0xFFFF; c+=1 )
	{
		nc = 0;
		if ( ( c & 0xFFFF0000 ) == c )
			printf ( "." );
//		if ( !( c % 0x10 ) )
//			printf ( "" );
		fflush ( stdout );
		for ( i = 0; i < 24; i++ )
			if ( c & ( 1 << i ) )
				nc ^= maddr[i];

		de_addr[c] = nc;
//		printf ( "%04X ", nc );
	}
//	exit ( 0 );
	printf ( "]\n" );
}

int
do_decode ( unsigned char *fname, unsigned char *fname_out, word address, half *code, int type )
{
	int i = 0;
	int skip = 0;
	int count = 0;
	int startaddr_set = 0;
	void *pos = NULL;
	byte buf[0x4000];
	half idx = 0;
	word len = 0;
	word startaddr = 0;
	FILE *fin = NULL;
	FILE *fout = NULL;

	fin = fopen ( fname, "rb" );
	if ( !fin )
	{
		printf ( "Can't open %s\n", fname );
		return 0;
	}

	fout = fopen ( fname_out, "wb" );
	if ( !fout )
	{
		printf ( "Can't open %s\n", fname_out );
		return 0;
	}

	printf ( " - Decrypting File       [" );
	fflush ( stdout );

	while ( (len = fread ( buf, 2, 0x2000, fin )) > 0 )
	{
		if ( !startaddr_set )
		{
			startaddr_set = 1;
			startaddr = address;
			printf ( "0x%08X            ", startaddr );
		}

		if ( skip > 30 )
		{
			printf ( "\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8. 0x%08X", address );
			fflush ( stdout );
			if ( ++count > 100 )
			{
				count = 0;
				printf ( "\n                       [" );
				printf ( "0x%08X            ", address );
				fflush ( stdout );
			}
			skip = 0;
		}

		decode ( buf, address, len, *code, type );
		

		if ( !(*code) && address == startaddr )
		{
			switch ( type )
			{

				case TYPE_MCU:
					*code = buf[mcu_auto_offset] << 8 | buf[mcu_auto_offset+1];      //  at this position is "0x20 0x20"
					*code ^= mcu_auto_values;  
					break;
				case TYPE_PPM:
					*code = buf[ppm_auto_offset] << 8 | buf[ppm_auto_offset+1];      //  at this position is "PPM"
					*code ^= ppm_auto_values;
					break;
				default:
					break;
			}

			//  show some output
			printf ( "\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8" ); 
			printf ( "\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8" );
			printf ( "\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8" );
			printf ( " * Found CryptKey        [0x%04X]                 \n", *code );
			fflush ( stdout );
			if ( type == TYPE_MCU )
				idx = mcu_crypt_start;
			else
				idx = 0;
			for ( ; idx < ( len * 2 ); idx += 2 )
			{
				buf[idx] ^= *code >> 8;
				buf[idx + 1] ^= ( byte ) *code;
			}
			printf ( " - Decrypting File       [" );
			printf ( "0x%08X            ", address );
			fflush ( stdout );
			count = 0;
		}

		fseek ( fout, address - startaddr, SEEK_SET );
		fwrite ( buf, 2, len, fout );

		address += (len*2);
		skip++;
	}
	printf ( "\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8. 0x%08X", address );
	printf ( "]\n" );
	fclose ( fin );
	fclose ( fout );

	return 1;
}

int
do_encode ( unsigned char *fname, unsigned char *fname_out, word address, half code, int type )
{
	int i = 0;
	int skip = 0;
	int count = 0;
	int startaddr_set = 0;
	byte buf[0x4000];
	word len = 0;
	word startaddr = 0;
	void *pos = NULL;
	FILE *fin = NULL;
	FILE *fout = NULL;

	fin = fopen ( fname, "rb" );
	if ( !fin )
	{
		printf ( "Can't open %s\n", fname );
		return 0;
	}

	fout = fopen ( fname_out, "wb" );
	if ( !fout )
	{
		printf ( "Can't open %s\n", fname_out );
		return 0;
	}

	printf ( " - Encrypting File       [" );
	fflush ( stdout );

	while ( (len = fread ( buf, 2, 0x2000, fin )) > 0 )
	{
		if ( !startaddr_set )
		{
			startaddr_set = 1;
			startaddr = address;
			printf ( "0x%08X            ", startaddr );
		}
		if ( skip > 30 )
		{
			printf ( "\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8. 0x%08X", address );
			fflush ( stdout );
			if ( ++count > 100 )
			{
				count = 0;
				printf ( "\n                       [" );
				printf ( "0x%08X            ", address );
				fflush ( stdout );
			}
			skip = 0;
		}
		encode ( buf, address, len, code, type );

		fseek ( fout, address - startaddr, SEEK_SET );
		fwrite ( buf, 2, len, fout );

		address += (len*2);
		skip++;
	}
	printf ( "\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8. 0x%08X", address );
	printf ( "]\n" );
	fclose ( fin );
	fclose ( fout );

	return 1;
}

int create_flash ( char *hdr, char *in, char *out, word address )
{
	int count = 0;
	int skip = 0;
	int startaddr_set = 0;
	unsigned int i = 0;
	unsigned long size = 0x4000;
	unsigned long len = 0;
	unsigned long startaddr = 0;
	byte buf[0x4000];
	byte tmp[0x0A];
	byte data = 0x00;
	FILE *fin = NULL;
	FILE *fout = NULL;

	printf ( " - Writing DCT4 File     [" );
	fflush ( stdout );

	// open the source file for the header
	fin = fopen ( hdr, "rb" );
	if ( !fin )
	{
		printf ( "Can't open %s\n", hdr );
		return 0;
	}
	// get the length
	fseek ( fin, 1, SEEK_SET );
	len = get_word ( fin ) + 5;
	fseek ( fin, 0, SEEK_SET );

	// read the header
	if ( fread ( buf, 1, len, fin ) != len )
	{
		printf ( "error while reading header from %s\n", hdr );
		return 0;
	}

	// open output file
	fout = fopen ( out, "wb" );
	if ( !fout )
	{
		printf ( "Can't open %s\n", out );
		return 0;
	}
	// write the header
	fwrite ( buf, 1, len, fout );

	// now open the flash file
	fin = fopen ( in, "rb" );
	if ( !fin )
	{
		printf ( "Can't open %s\n", in );
		return 0;
	}

	// in case of MCU, the first block is 0x2C bytes (6610)
	if ( address == mcu_flash_start )
		size = mcu_flash_hdlen;

	// and write the blocks
	while ( (len = fread ( buf, 1, size, fin )) > 0 )
	{
		if ( !startaddr_set )
		{
			startaddr_set = 1;
			startaddr = address;
			printf ( "0x%08X            ", startaddr );
		}
		if ( skip > 30 )
		{
			printf ( "\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8. 0x%08X", address );
			fflush ( stdout );
			if ( ++count > 25 )
			{
				count = 0;
				printf ( "\n                       [" );
				printf ( "0x%08X            ", address );
				fflush ( stdout );
			}
			skip = 0;
		}

		// write the flash data
		//
		// hex: 14 AA AA AA AA CD 00 LL LL CH
		//
		// AA = Address
		// CD = Checksum of Data
		// LL = Length of Data
		// CH = Checksum of Header
		//

		memset ( tmp, 0x00, 0x0A );
		tmp[0] = (byte)0x14;                    // flash block header
		tmp[1] = (byte)(address >> 24) & 0xff;  // address of the chunk
		tmp[2] = (byte)(address >> 16) & 0xff;
		tmp[3] = (byte)(address >> 8) & 0xff;
		tmp[4] = (byte) address & 0xFF;
		for (i=0; i<len; i++ )                  // checksum of the chunk
			tmp[5] += buf[i];
		tmp[5] ^= 0xFF;
		if ( fls_fixchecksum )
			tmp[5]++;
		tmp[6] = 0x00;                          // not used
		tmp[7] = (byte)(len >> 8) & 0xff;       // length of the chunk
		tmp[8] = (byte) len & 0xFF;
		for (i=1; i<9; i++ )                    // checksum of the header
			tmp[9] += tmp[i];
		tmp[9] ^= 0xFF;

		fwrite ( tmp, 1, 0x0A, fout );          // write header
		fwrite ( buf, 1, len, fout );           // followed by the data itself


		
		// if we wrote the "PeaK" block, go over to 0x01000064
		if ( address == 0x1000000 )
		{
			size = 0x4000 - 0x64;
			address = 0x1000064;
			fseek ( fin, 0x64, SEEK_SET );
		}
		else
		{	
			size = 0x4000;
			address += len;
		}
		skip++;
	}
	printf ( "\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8. 0x%08X", address );
	printf ( "]\n" );
	fclose ( fin );
	fclose ( fout );

	return 1;
}

int
read_flash ( unsigned char *fname, unsigned char *fname_out, word *start_address )
{
	int i = 0;
	int skip = 0;
	int count = 0;
	int startaddr_set = 0;
	byte buf[0x10000];
	word len = 0;
	word ofs = 0;
	word address = 0;
	word startaddr = 0;
	word lastaddr = 0;
	half code = 0;
	void *pos = NULL;
	FILE *fin = NULL;
	FILE *fout = NULL;

	if ( !fin )
	{
		fin = fopen ( fname, "rb" );
		if ( !fin )
		{
			printf ( "Can't open %s\n", fname );
			return 0;
		}
	}

	fout = fopen ( fname_out, "wb" );
	if ( !fout )
	{
		printf ( "Can't open %s\n", fname_out );
		return 0;
	}

	fseek ( fin, 1, SEEK_SET );
	ofs = get_word ( fin );
	fseek ( fin, ofs, SEEK_CUR );

	printf ( " - Reading DCT4 File     [" );
	fflush ( stdout );

	while ( len = get_chunk ( fin, buf, &address ) )
	{
		if ( !startaddr_set )
		{
			startaddr_set = 1;
			startaddr = address;
			printf ( "0x%08X            ", startaddr );
		}
		if ( skip > 30 )
		{
			printf ( "\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8. 0x%08X", address );
			fflush ( stdout );
			if ( ++count > 25 )
			{
				count = 0;
				printf ( "\n                       [" );
				printf ( "0x%08X            ", address );
				fflush ( stdout );
			}
			skip = 0;
		}
		fseek ( fout, address - startaddr, SEEK_SET );
		fwrite ( buf, 2, len, fout );
		skip++;
		lastaddr = address + (len*2);
	}
	printf ( "\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8\x8. 0x%08X", lastaddr );
	printf ( "]\n" );
	fclose ( fin );
	fclose ( fout );

	*start_address = startaddr;

	return 1;
}

int 
analyse_codes ( void )
{
	int i = 0;
	int j = 0;
	int addr = 0;
	word val = 0;
	unsigned char p1 = 0;
	unsigned char p2 = 0;
	unsigned char p3 = 0;
	unsigned char p4 = 0;
/*
	for ( i=0; i<0x10; i++ )
	{
			printf ( "0x%04X ",1<<i );
//		if ( !(i & 0x07) )
//			printf ( "\n" );
		val   = de_codes[1<<i];
		for ( j=0; j<0x10; j++ )
			if ( (val^(1<<i)) & (1<<(0x0F-j)) )
				printf ( "1" );
			else
				printf ( "0" );
		printf ( " 0x%04X\n", val ^ (1<<i) );
	}
*/

//
// digit 0xF000
//
/*
	for ( i=0; i<=0x32; i++ )
	{
		addr = (1<<i);

		if ( !(i & 0x07) )
			printf ( " " );
		if ( !(i & 0x3F) )
			printf ( "\n" );
//		val   = de_addr[addr];
		val = 0;
		for ( j = 0; j < 24; j++ )
			if ( addr & ( 1 << j ) )
				val ^= maddr[j];
		val  &= 0xF000;
		val >>= 12;
*/
/*		p1 = (addr & 0x7000) >> 12;

		if ( addr & 0x8000 )
			p1 ^= 0xA;
		if ( addr & 0x0010 )
			p1 ^= 0x8;	
		if ( addr & 0x0020 )
			p1 ^= 0x1;
		if ( addr & 0x0080 )
			p1 ^= 0x4;

		if ( val != p1 )
			printf ( "%1X%1X ", val, p1 );
		else
			printf ( "%1X%", val );
	}
*/
/*
//
// digit 0xF000
//

	for ( i=0; i<=0xFFFF; i++ )
	{
		addr = i*0x1;

		if ( !(i & 0x07) )
			printf ( " " );
		if ( !(i & 0x3F) )
			printf ( "\n" );
		val   = de_codes[addr];
		val  &= 0xF000;
		val >>= 12;

		p1 = (addr & 0x7000) >> 12;

		if ( addr & 0x8000 )
			p1 ^= 0xA;
		if ( addr & 0x0010 )
			p1 ^= 0x8;	
		if ( addr & 0x0020 )
			p1 ^= 0x1;
		if ( addr & 0x0080 )
			p1 ^= 0x4;

		if ( val != p1 )
			printf ( "%1X%1X ", val, p1 );
		else
			printf ( "%1X%", val );
	}
*/
/*
//
// digit 0x0F00
//

	for ( i=0; i<=0xFFFF; i++ )
	{
		addr = i*0x1;

		if ( !(i & 0x07) )
			printf ( " " );
		if ( !(i & 0x3F) )
			printf ( "\n" );
		val   = de_codes[addr];
		val  &= 0xF00;
		val >>= 8;

		p2 = (addr & 0x0700) >> 8;

		if ( addr & 0x0001 )
			p2 ^= 0x2;
		if ( addr & 0x0008 )
			p2 ^= 0x8;
		if ( addr & 0x0040 )
			p2 ^= 0x4;
		if ( addr & 0x0800 )
			p2 ^= 0x9;

		if ( val != p2 )
			printf ( "%1X%1X ", val, p2 );
		else
			printf ( "%1X%", val );
	}
*/
/*
//
// digit 0x00F0
//

	for ( i=0; i<=0xFFFF; i++ )
	{
		addr = i*0x1;

		if ( !(i & 0x07) )
			printf ( " " );
		if ( !(i & 0x3F) )
			printf ( "\n" );
		val   = de_codes[addr];
		val  &= 0x00F0;
		val >>= 4;

		p3 = (addr & 0x0010) >> 4;

		if ( addr & 0x0002 )
			p3 ^= 0x1;
		if ( addr & 0x0004 )
			p3 ^= 0x8;
		if ( addr & 0x0020 )
			p3 ^= 0x2;
		if ( addr & 0x0040 )
			p3 ^= 0x4;
		if ( addr & 0x0080 )
			p3 ^= 0x8;
		if ( addr & 0x0200 )
			p3 ^= 0x2;

		if ( val != p3 )
			printf ( "%1X%1X ", val, p3 );
		else
			printf ( "%1X%", val );
	}
*/
//
// digit 0x000F
//
/*
	for ( i=0; i<=0xFFFF; i++ )
	{
		addr = i*0x1;

		if ( !(i & 0x07) )
			printf ( " " );
		if ( !(i & 0x3F) )
			printf ( "\n" );
		val   = de_codes[addr];
		val  &= 0x000F;


		p4 = (addr & 0x0007);

		if ( addr & 0x0008 )
			p4 ^= 0x8;
		if ( addr & 0x0040 )
			p4 ^= 0x4;
		if ( addr & 0x0400 )
			p4 ^= 0x2;
		if ( addr & 0x2000 )
			p4 ^= 0x8;
		if ( addr & 0x4000 )
			p4 ^= 0x1;

		if ( val != p4 )
			printf ( "%1X%1X ", val, p4 );
		else
			printf ( "%1X%", val );
	}
*/
	return 0;
}


#ifdef CRYPT_LIB
unsigned long decrypter_main ( char* name_in, char* name_out, char* name_org, int action, unsigned short *basecode)
{
#else
int
main ( int argc, char *argv[] )
{
#endif

	int type = TYPE_MCU;
	int decrypt = 1;
	half code = 0;
	static word addr = 0;

#ifndef CRYPT_LIB
	printf ( "\n     DCT4 CrypterX v4.0\n" );
	printf ( " --------------------------\n\n" );
#endif

	generate_codes (  );

//	analyse_codes ();
//	return 0;


//#define TEST_TIKU

#ifndef TEST_TIKU
	mcu_flash_start = 0x1000000;        // 6610 NHL4   MCU area start
	mcu_flash_hdlen = 0x2C;             //             length of first header block
	mcu_crypt_start = 0x84;             //             start offset of encrypted MCU data

	mcu_auto_offset = 0x0084;
	ppm_auto_offset = 0x0000;
	mcu_auto_values = 0xFFFF; // for RH-17/2280: 0x5E80
	ppm_auto_values = 0x5050;

	fls_fixchecksum = 1;


#else

//
//	_____TEST_____
//

	mcu_flash_start = 0x0000000;        // 6230 RH12   MCU area start      
	mcu_flash_hdlen = 0x012C;            //             length of first header block
	mcu_crypt_start = 0x01F4;            //             start offset of encrypted MCU data

	mcu_auto_offset = 0x01F4;
	ppm_auto_offset = 0x0000;
	mcu_auto_values = 0xFFFF;
	ppm_auto_values = 0x5050;

//	fls_endianess  |= 0x01;             // swap bytes
//	fls_endianess  |= 0x02;             // swap halfs
#endif

//	type = TYPE_MCU;
	//	type = TYPE_PPM;



	//
	//  <g3gg0>
	//
	//  f_orig.fls    =   Original Nokia DCT4 FlashFile
	//      ||
	//      \/
	//  f_data.fls    =   Original ENcrypted flash data
	//      ||
	//      \/
	//  f_decr.fls    =   Original DEcrypted flash data
	//      ||
	//      || __  Modify the file and save it.
	//      ||/    Either pause there or restart using the right files.
	//      ||     I prefer changing the filenames.
	//      \/
	//  f_encr.fls    =   Modified ENcrypted flash data
	//      ||
	//      \/
	//  f_done.fls    =   Modified Nokia DCT4 FlashFile
	//

	//
	//  After the file was created, simply 0xFF all the 0x40 bytes of the D340 signed hash.
	//  It seems nokia left a backdoor to disable the algo by simple 0xFF-ing it :)
	//  I also noticed that 6610 has NO ContactService when the MCU checksum is wrong.
	//  Modifying is easier than i thought :)
	//
	//  </g3gg0>
	//

	if ( addr > 0x01000000 )
		type = TYPE_PPM;

#ifdef CRYPT_LIB
	if ( action == 0 )
		read_flash   ( name_in,   name_out, &addr );                 // open a nokia flash and serialize it

	if ( action == 1 )
		do_decode    ( name_in,   name_out,  addr, &code, type );    // use the serialized file to decode

	if ( action == 2 )
		do_encode    ( name_in,   name_out,  addr,  code, type );          // open a decoded serialized flash and encode it again

	if ( action == 3 )
		create_flash ( name_org,  name_in,  name_out, addr );   // convert the serialized file to flashfile using headers from original file

	*basecode = code;
	//printf ( "\n\n" );
	return addr;
#else
//	type = TYPE_MCU;
	read_flash   ( "flash.fls",   "flash.ser", &addr );                 // open a nokia flash and serialize it
	do_decode    ( "flash.ser",   "flash.dec",  addr, &code, type );    // use the serialized file to decode
	do_encode    ( "flash.mod",   "flash.enc",  addr,  code, type );          // open a decoded serialized flash and encode it again
	create_flash ( "flash.fls",   "flash.enc",  "flash.out", addr );   // convert the serialized file to flashfile using headers from original file

#endif

	return 0;

}
