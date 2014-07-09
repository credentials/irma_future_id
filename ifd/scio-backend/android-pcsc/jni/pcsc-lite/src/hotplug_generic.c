/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2000-2003
 *  David Corcoran <corcoran@linuxnet.com>
 * Copyright (C) 2002-2011
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * $Id: hotplug_generic.c 5711 2011-05-05 09:02:08Z rousseau $
 */

/**
 * @file
 * @brief This provides a search API for hot pluggble devices.
 *
 * Check for platforms that have their own specific support.
 * It's easier and flexible to do it here, rather than
 * with automake conditionals in src/Makefile.am.
 * No, it's still not a perfect solution design wise.
 */

#include "config.h"
#include "pcsclite.h"

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#if !defined(__APPLE__) && !defined(HAVE_LIBUSB) && !defined(__linux__) && !defined(HAVE_LIBUDEV)

LONG HPSearchHotPluggables(void)
{
	return 0;
}

ULONG HPRegisterForHotplugEvents(void)
{
	return 0;
}

LONG HPStopHotPluggables(void)
{
	return 0;
}

void HPReCheckSerialReaders(void)
{
}

#endif
