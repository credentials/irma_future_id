/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999
 *  David Corcoran <corcoran@linuxnet.com>
 * Copyright (C) 2004-2010
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * $Id: testpcsc.c 5885 2011-08-09 07:49:14Z rousseau $
 */

/**
 * @file
 * @brief This is a test program for pcsc-lite.
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcsclite.h"
#include "winscard.h"
#include "reader.h"

#define PANIC 0
#define DONT_PANIC 1

#define USE_AUTOALLOCATE

#define BLUE "\33[34m"
#define RED "\33[31m"
#define BRIGHT_RED "\33[01;31m"
#define GREEN "\33[32m"
#define NORMAL "\33[0m"
#define MAGENTA "\33[35m"

static void test_rv(LONG rv, SCARDCONTEXT hContext, int dont_panic)
{
	if (rv != SCARD_S_SUCCESS)
	{
		if (dont_panic)
			printf(BLUE "%s (don't panic)\n" NORMAL, pcsc_stringify_error(rv));
		else
		{
			printf(RED "%s\n" NORMAL, pcsc_stringify_error(rv));
			(void)SCardReleaseContext(hContext);
			exit(-1);
		}
	}
	else
		(void)puts(pcsc_stringify_error(rv));
}

int main(/*@unused@*/ int argc, /*@unused@*/ char **argv)
{
	SCARDHANDLE hCard;
	SCARDCONTEXT hContext;
	SCARD_READERSTATE rgReaderStates[1];
	DWORD dwReaderLen, dwState, dwProt, dwAtrLen;
	DWORD dwPref, dwReaders = 0;
	char *pcReaders = NULL, *mszReaders;
#ifdef USE_AUTOALLOCATE
	unsigned char *pbAtr = NULL;
#else
	unsigned char pbAtr[MAX_ATR_SIZE];
#endif
	union {
		unsigned char as_char[100];
		DWORD as_DWORD;
		uint32_t as_uint32_t;
	} buf;
	DWORD dwBufLen;
	unsigned char *pbAttr = NULL;
	DWORD pcbAttrLen;
	char *mszGroups;
	DWORD dwGroups = 0;
	long rv;
	DWORD i;
	int p, iReader;
	int iList[16];
	SCARD_IO_REQUEST ioRecvPci = *SCARD_PCI_T0;	/* use a default value */
	const SCARD_IO_REQUEST *pioSendPci;
	unsigned char bSendBuffer[MAX_BUFFER_SIZE];
	unsigned char bRecvBuffer[MAX_BUFFER_SIZE];
	DWORD send_length, length;

	(void)argc;
	(void)argv;

	printf("\nMUSCLE PC/SC Lite unitary test Program\n\n");

	printf(MAGENTA "THIS PROGRAM IS NOT DESIGNED AS A TESTING TOOL FOR END USERS!\n");
	printf("Do NOT use it unless you really know what you do.\n\n" NORMAL);

	printf("Testing SCardEstablishContext\t: ");
	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
	test_rv(rv, hContext, PANIC);

	printf("Testing SCardIsValidContext\t: ");
	rv = SCardIsValidContext(hContext);
	test_rv(rv, hContext, PANIC);

	printf("Testing SCardIsValidContext\t: ");
	rv = SCardIsValidContext(hContext+1);
	test_rv(rv, hContext, DONT_PANIC);

	printf("Testing SCardListReaderGroups\t: ");
#ifdef USE_AUTOALLOCATE
	dwGroups = SCARD_AUTOALLOCATE;
	rv = SCardListReaderGroups(hContext, (LPSTR)&mszGroups, &dwGroups);
#else
	rv = SCardListReaderGroups(hContext, NULL, &dwGroups);
	test_rv(rv, hContext, PANIC);

	printf("Testing SCardListReaderGroups\t: ");
	mszGroups = calloc(dwGroups, sizeof(char));
	rv = SCardListReaderGroups(hContext, mszGroups, &dwGroups);
#endif
	test_rv(rv, hContext, PANIC);

	/*
	 * Have to understand the multi-string here
	 */
	p = 0;
	for (i = 0; i+1 < dwGroups; i++)
	{
		++p;
		printf(GREEN "Group %02d: %s\n" NORMAL, p, &mszGroups[i]);
		while (mszGroups[++i] != 0) ;
	}

#ifdef USE_AUTOALLOCATE
	printf("Testing SCardFreeMemory\t\t: ");
	rv = SCardFreeMemory(hContext, mszGroups);
	test_rv(rv, hContext, PANIC);
#else
	free(mszGroups);
#endif

wait_for_card_again:
	mszGroups = NULL;
	printf("Testing SCardListReaders\t: ");
	rv = SCardListReaders(hContext, mszGroups, NULL, &dwReaders);
	test_rv(rv, hContext, DONT_PANIC);
	if (SCARD_E_NO_READERS_AVAILABLE == rv)
	{
		printf("Testing SCardGetStatusChange \n");
		printf("Please insert a working reader\t: ");
		(void)fflush(stdout);
		rgReaderStates[0].szReader = "\\\\?PnP?\\Notification";
		rgReaderStates[0].dwCurrentState = SCARD_STATE_EMPTY;

		rv = SCardGetStatusChange(hContext, INFINITE, rgReaderStates, 1);
		test_rv(rv, hContext, PANIC);
	}

	printf("Testing SCardListReaders\t: ");
#ifdef USE_AUTOALLOCATE
	dwReaders = SCARD_AUTOALLOCATE;
	rv = SCardListReaders(hContext, mszGroups, (LPSTR)&mszReaders, &dwReaders);
#else
	rv = SCardListReaders(hContext, mszGroups, NULL, &dwReaders);
	test_rv(rv, hContext, PANIC);

	printf("Testing SCardListReaders\t: ");
	mszReaders = calloc(dwReaders, sizeof(char));
	rv = SCardListReaders(hContext, mszGroups, mszReaders, &dwReaders);
#endif
	test_rv(rv, hContext, DONT_PANIC);

	/*
	 * Have to understand the multi-string here
	 */
	p = 0;
	for (i = 0; i+1 < dwReaders; i++)
	{
		++p;
		printf(GREEN "Reader %02d: %s\n" NORMAL, p, &mszReaders[i]);
		iList[p] = i;
		while (mszReaders[++i] != 0) ;
	}

	if (p > 1)
		do
		{
			char input[80];

			printf("Enter the reader number\t\t: ");
			(void)fgets(input, sizeof(input), stdin);
			iReader = atoi(input);

			if (iReader > p || iReader <= 0)
				printf("Invalid Value - try again\n");
		}
		while (iReader > p || iReader <= 0);
	else
		iReader = 1;

	rgReaderStates[0].szReader = &mszReaders[iList[iReader]];
	rgReaderStates[0].dwCurrentState = SCARD_STATE_EMPTY;

	printf("Waiting for card insertion\t: ");
	(void)fflush(stdout);
	rv = SCardGetStatusChange(hContext, INFINITE, rgReaderStates, 1);
	test_rv(rv, hContext, PANIC);
	if (rgReaderStates[0].dwEventState & SCARD_STATE_UNKNOWN)
	{
		printf("\nA reader has been connected/disconnected\n");
		goto wait_for_card_again;
	}

	printf("Testing SCardConnect\t\t: ");
	rv = SCardConnect(hContext, &mszReaders[iList[iReader]],
		SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
		&hCard, &dwPref);
	test_rv(rv, hContext, PANIC);

	switch(dwPref)
	{
		case SCARD_PROTOCOL_T0:
			pioSendPci = SCARD_PCI_T0;
			break;
		case SCARD_PROTOCOL_T1:
			pioSendPci = SCARD_PCI_T1;
			break;
		case SCARD_PROTOCOL_RAW:
			pioSendPci = SCARD_PCI_RAW;
			break;
		default:
			printf("Unknown protocol\n");
			return -1;
	}

	/* APDU select file */
	printf("Select file:");
	send_length = 7;
	memcpy(bSendBuffer, "\x00\xA4\x00\x00\x02\x3F\x00", send_length);
	for (i=0; i<send_length; i++)
		printf(" %02X", bSendBuffer[i]);
	printf("\n");
	length = sizeof(bRecvBuffer);

	printf("Testing SCardTransmit\t\t: ");
	rv = SCardTransmit(hCard, pioSendPci, bSendBuffer, send_length,
		&ioRecvPci, bRecvBuffer, &length);
	test_rv(rv, hContext, PANIC);
	printf(" card response:" GREEN);
	for (i=0; i<length; i++)
		printf(" %02X", bRecvBuffer[i]);
	printf("\n" NORMAL);

	printf("Testing SCardControl\t\t: ");
#ifdef PCSC_PRE_120
	{
		char buffer[1024] = "Foobar";
		DWORD cbRecvLength = sizeof(buffer);

		rv = SCardControl(hCard, buffer, 7, buffer, &cbRecvLength);
	}
#else
	{
		char buffer[1024] = { 0x02 };
		DWORD cbRecvLength = sizeof(buffer);

		rv = SCardControl(hCard, SCARD_CTL_CODE(1), buffer, 1, buffer,
			sizeof(buffer), &cbRecvLength);
		if (cbRecvLength && (SCARD_S_SUCCESS == rv))
		{
			for (i=0; i<cbRecvLength; i++)
				printf("%c", buffer[i]);
			printf(" ");
		}
	}
#endif
	test_rv(rv, hContext, DONT_PANIC);

	printf("Testing SCardGetAttrib\t\t: ");
#ifdef USE_AUTOALLOCATE
	pcbAttrLen = SCARD_AUTOALLOCATE;
	rv = SCardGetAttrib(hCard, SCARD_ATTR_DEVICE_FRIENDLY_NAME, (unsigned char *)&pbAttr,
		&pcbAttrLen);
#else
	rv = SCardGetAttrib(hCard, SCARD_ATTR_DEVICE_FRIENDLY_NAME, NULL, &pcbAttrLen);
	test_rv(rv, hContext, DONT_PANIC);
	if (rv == SCARD_S_SUCCESS)
	{
		printf("SCARD_ATTR_DEVICE_FRIENDLY_NAME length: " GREEN "%ld\n" NORMAL, pcbAttrLen);
		pbAttr = malloc(pcbAttrLen);
	}

	printf("Testing SCardGetAttrib\t\t: ");
	rv = SCardGetAttrib(hCard, SCARD_ATTR_DEVICE_FRIENDLY_NAME, pbAttr, &pcbAttrLen);
#endif
	test_rv(rv, hContext, DONT_PANIC);
	if (rv == SCARD_S_SUCCESS)
		printf("SCARD_ATTR_DEVICE_FRIENDLY_NAME: " GREEN "%s\n" NORMAL, pbAttr);

#ifdef USE_AUTOALLOCATE
	printf("Testing SCardFreeMemory\t\t: ");
	rv = SCardFreeMemory(hContext, pbAttr);
	test_rv(rv, hContext, PANIC);
#else
	if (pbAttr)
		free(pbAttr);
#endif

	printf("Testing SCardGetAttrib\t\t: ");
#ifdef USE_AUTOALLOCATE
	pcbAttrLen = SCARD_AUTOALLOCATE;
	rv = SCardGetAttrib(hCard, SCARD_ATTR_ATR_STRING, (unsigned char *)&pbAttr,
		&pcbAttrLen);
#else
	rv = SCardGetAttrib(hCard, SCARD_ATTR_ATR_STRING, NULL, &pcbAttrLen);
	test_rv(rv, hContext, DONT_PANIC);
	if (rv == SCARD_S_SUCCESS)
	{
		printf("SCARD_ATTR_ATR_STRING length: " GREEN "%ld\n" NORMAL, pcbAttrLen);
		pbAttr = malloc(pcbAttrLen);
	}

	printf("Testing SCardGetAttrib\t\t: ");
	rv = SCardGetAttrib(hCard, SCARD_ATTR_ATR_STRING, pbAttr, &pcbAttrLen);
#endif
	test_rv(rv, hContext, DONT_PANIC);
	if (rv == SCARD_S_SUCCESS)
	{
		printf("SCARD_ATTR_ATR_STRING length: " GREEN "%ld\n" NORMAL, pcbAttrLen);
		printf("SCARD_ATTR_ATR_STRING: " GREEN);
		for (i = 0; i < pcbAttrLen; i++)
			printf("%02X ", pbAttr[i]);
		printf("\n" NORMAL);
	}

#ifdef USE_AUTOALLOCATE
	printf("Testing SCardFreeMemory\t\t: ");
	rv = SCardFreeMemory(hContext, pbAttr);
	test_rv(rv, hContext, PANIC);
#else
	if (pbAttr)
		free(pbAttr);
#endif

	printf("Testing SCardGetAttrib\t\t: ");
	dwBufLen = sizeof(buf);
	rv = SCardGetAttrib(hCard, SCARD_ATTR_VENDOR_IFD_VERSION, buf.as_char, &dwBufLen);
	test_rv(rv, hContext, DONT_PANIC);
	if (rv == SCARD_S_SUCCESS)
		printf("Vendor IFD version\t\t: " GREEN "0x%08lX\n" NORMAL,
			buf.as_DWORD);

	printf("Testing SCardGetAttrib\t\t: ");
	dwBufLen = sizeof(buf);
	rv = SCardGetAttrib(hCard, SCARD_ATTR_MAXINPUT, buf.as_char, &dwBufLen);
	test_rv(rv, hContext, DONT_PANIC);
	if (rv == SCARD_S_SUCCESS)
	{
		if (dwBufLen == sizeof(uint32_t))
			printf("Max message length\t\t: " GREEN "%d\n" NORMAL,
				buf.as_uint32_t);
		else
			printf(RED "Wrong size" NORMAL);
	}

	printf("Testing SCardGetAttrib\t\t: ");
	dwBufLen = sizeof(buf);
	rv = SCardGetAttrib(hCard, SCARD_ATTR_VENDOR_NAME, buf.as_char, &dwBufLen);
	test_rv(rv, hContext, DONT_PANIC);
	if (rv == SCARD_S_SUCCESS)
		printf("Vendor name\t\t\t: " GREEN "%s\n" NORMAL, buf.as_char);

	printf("Testing SCardSetAttrib\t\t: ");
	rv = SCardSetAttrib(hCard, SCARD_ATTR_ATR_STRING, (LPCBYTE)"", 1);
	test_rv(rv, hContext, DONT_PANIC);

	printf("Testing SCardStatus\t\t: ");

#ifdef USE_AUTOALLOCATE
	dwReaderLen = SCARD_AUTOALLOCATE;
	dwAtrLen = SCARD_AUTOALLOCATE;
	rv = SCardStatus(hCard, (LPSTR)&pcReaders, &dwReaderLen, &dwState, &dwProt,
		(LPBYTE)&pbAtr, &dwAtrLen);
#else
	dwReaderLen = 100;
	pcReaders   = malloc(sizeof(char) * 100);
	dwAtrLen    = MAX_ATR_SIZE;

	rv = SCardStatus(hCard, pcReaders, &dwReaderLen, &dwState, &dwProt,
		pbAtr, &dwAtrLen);
#endif
	test_rv(rv, hContext, PANIC);

	printf("Current Reader Name\t\t: " GREEN "%s\n" NORMAL, pcReaders);
	printf("Current Reader State\t\t: " GREEN "0x%.4lx\n" NORMAL, dwState);
	printf("Current Reader Protocol\t\t: T=" GREEN "%ld\n" NORMAL, dwProt - 1);
	printf("Current Reader ATR Size\t\t: " GREEN "%ld" NORMAL " bytes\n",
		dwAtrLen);
	printf("Current Reader ATR Value\t: " GREEN);

	for (i = 0; i < dwAtrLen; i++)
	{
		printf("%02X ", pbAtr[i]);
	}
	printf(NORMAL "\n");

#ifdef USE_AUTOALLOCATE
	printf("Testing SCardFreeMemory\t\t: ");
	rv = SCardFreeMemory(hContext, pcReaders);
	test_rv(rv, hContext, PANIC);
	printf("Testing SCardFreeMemory\t\t: ");
	rv = SCardFreeMemory(hContext, pbAtr);
	test_rv(rv, hContext, PANIC);
#else
	if (pcReaders)
		free(pcReaders);
#endif

	if (rv != SCARD_S_SUCCESS)
	{
		(void)SCardDisconnect(hCard, SCARD_RESET_CARD);
		(void)SCardReleaseContext(hContext);
	}

	printf("Press enter: ");
	(void)getchar();
	printf("Testing SCardReconnect\t\t: ");
	rv = SCardReconnect(hCard, SCARD_SHARE_SHARED,
		SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, SCARD_UNPOWER_CARD, &dwPref);
	test_rv(rv, hContext, PANIC);

	printf("Testing SCardDisconnect\t\t: ");
	rv = SCardDisconnect(hCard, SCARD_UNPOWER_CARD);
	test_rv(rv, hContext, PANIC);

#ifdef USE_AUTOALLOCATE
	printf("Testing SCardFreeMemory\t\t: ");
	rv = SCardFreeMemory(hContext, mszReaders);
	test_rv(rv, hContext, PANIC);
#else
	free(mszReaders);
#endif

	printf("Testing SCardReleaseContext\t: ");
	rv = SCardReleaseContext(hContext);
	test_rv(rv, hContext, PANIC);

	printf("\n");
	printf("PC/SC Test Completed Successfully !\n");

	return 0;
}
