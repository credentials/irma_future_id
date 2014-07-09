/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999-2002
 *  David Corcoran <corcoran@linuxnet.com>
 * Copyright (C) 2002-2009
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * $Id: atrhandler.h 5962 2011-09-24 08:24:34Z rousseau $
 */

/**
 * @file
 * @brief This keeps track of smart card protocols, timing issues
 * and Answer to Reset ATR handling.
 */

#ifndef __atrhandler_h__
#define __atrhandler_h__

	/*
	 * Decodes the ATR
	 */
	short ATRDecodeAtr(/*@out@*/ int *availableProtocols, int *currentProtocol,
		PUCHAR pucAtr, DWORD dwLength);

#endif							/* __atrhandler_h__ */
