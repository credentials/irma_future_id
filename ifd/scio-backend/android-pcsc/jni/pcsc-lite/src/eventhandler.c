/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2000-2002
 *  David Corcoran <corcoran@linuxnet.com>
 * Copyright (C) 2002-2011
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * $Id: eventhandler.c 6391 2012-07-26 18:44:54Z rousseau $
 */

/**
 * @file
 * @brief This keeps track of card insertion/removal events
 * and updates ATR, protocol, and status information.
 */

#include "config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include "misc.h"
#include "pcscd.h"
#include "debuglog.h"
#include "readerfactory.h"
#include "eventhandler.h"
#include "dyn_generic.h"
#include "sys_generic.h"
#include "ifdwrapper.h"
#include "prothandler.h"
#include "strlcpycat.h"
#include "utils.h"
#include "winscard_svc.h"
#include "simclist.h"

static list_t ClientsWaitingForEvent;	/**< list of client file descriptors */
pthread_mutex_t ClientsWaitingForEvent_lock;	/**< lock for the above list */

static void EHStatusHandlerThread(READER_CONTEXT *);

LONG EHRegisterClientForEvent(int32_t filedes)
{
	(void)pthread_mutex_lock(&ClientsWaitingForEvent_lock);

	(void)list_append(&ClientsWaitingForEvent, &filedes);

	(void)pthread_mutex_unlock(&ClientsWaitingForEvent_lock);

	return SCARD_S_SUCCESS;
} /* EHRegisterClientForEvent */

/**
 * Try to unregisted a client
 * If no client is found then do not log an error
 */
LONG EHTryToUnregisterClientForEvent(int32_t filedes)
{
	LONG rv = SCARD_S_SUCCESS;
	int ret;

	(void)pthread_mutex_lock(&ClientsWaitingForEvent_lock);

	ret = list_delete(&ClientsWaitingForEvent, &filedes);

	(void)pthread_mutex_unlock(&ClientsWaitingForEvent_lock);

	if (ret < 0)
		rv = SCARD_F_INTERNAL_ERROR;

	return rv;
} /* EHTryToUnregisterClientForEvent */

/**
 * Unregister a client and log an error if the client is not found
 */
LONG EHUnregisterClientForEvent(int32_t filedes)
{
	LONG rv = EHTryToUnregisterClientForEvent(filedes);

	if (rv < 0)
		Log2(PCSC_LOG_ERROR, "Can't remove client: %d", filedes);

	return rv;
} /* EHUnregisterClientForEvent */

/**
 * Sends an asynchronous event to any waiting client
 */
LONG EHSignalEventToClients(void)
{
	LONG rv = SCARD_S_SUCCESS;
	int32_t filedes;

	(void)pthread_mutex_lock(&ClientsWaitingForEvent_lock);

	(void)list_iterator_start(&ClientsWaitingForEvent);
	while (list_iterator_hasnext(&ClientsWaitingForEvent))
	{
        filedes = *(int32_t *)list_iterator_next(&ClientsWaitingForEvent);
		rv = MSGSignalClient(filedes, SCARD_S_SUCCESS);
	}
	(void)list_iterator_stop(&ClientsWaitingForEvent);

	(void)list_clear(&ClientsWaitingForEvent);

	(void)pthread_mutex_unlock(&ClientsWaitingForEvent_lock);

	return rv;
} /* EHSignalEventToClients */

LONG EHInitializeEventStructures(void)
{
	(void)list_init(&ClientsWaitingForEvent);

	/* request to store copies, and provide the metric function */
    (void)list_attributes_copy(&ClientsWaitingForEvent, list_meter_int32_t, 1);

	/* setting the comparator, so the list can sort, find the min, max etc */
    (void)list_attributes_comparator(&ClientsWaitingForEvent, list_comparator_int32_t);

	(void)pthread_mutex_init(&ClientsWaitingForEvent_lock, NULL);

	return SCARD_S_SUCCESS;
}

LONG EHDestroyEventHandler(READER_CONTEXT * rContext)
{
	int rv;
	DWORD dwGetSize;
	UCHAR ucGetData[1];

	if ('\0' == rContext->readerState->readerName[0])
	{
		Log1(PCSC_LOG_INFO, "Thread already stomped.");
		return SCARD_S_SUCCESS;
	}

	/*
	 * Set the thread to 0 to exit thread
	 */
	rContext->hLockId = 0xFFFF;

	Log1(PCSC_LOG_INFO, "Stomping thread.");

	/* kill the "polling" thread */
	dwGetSize = sizeof(ucGetData);
	rv = IFDGetCapabilities(rContext, TAG_IFD_POLLING_THREAD_KILLABLE,
		&dwGetSize, ucGetData);

#ifdef HAVE_PTHREAD_CANCEL
	if ((IFD_SUCCESS == rv) && (1 == dwGetSize) && ucGetData[0])
	{
		Log1(PCSC_LOG_INFO, "Killing polling thread");
		(void)pthread_cancel(rContext->pthThread);
	}
	else
#endif
	{
		/* ask to stop the "polling" thread */
		RESPONSECODE (*fct)(DWORD) = NULL;

		dwGetSize = sizeof(fct);
		rv = IFDGetCapabilities(rContext, TAG_IFD_STOP_POLLING_THREAD,
			&dwGetSize, (PUCHAR)&fct);

		if ((IFD_SUCCESS == rv) && (dwGetSize == sizeof(fct)))
		{
			Log1(PCSC_LOG_INFO, "Request stopping of polling thread");
			fct(rContext->slot);
		}
		else
			Log1(PCSC_LOG_INFO, "Waiting polling thread");
	}

	/* wait for the thread to finish */
	rv = pthread_join(rContext->pthThread, NULL);
	if (rv)
		Log2(PCSC_LOG_ERROR, "pthread_join failed: %s", strerror(rv));

	/* Zero the thread */
	rContext->pthThread = 0;

	Log1(PCSC_LOG_INFO, "Thread stomped.");

	return SCARD_S_SUCCESS;
}

LONG EHSpawnEventHandler(READER_CONTEXT * rContext)
{
	LONG rv;
	DWORD dwStatus = 0;

	rv = IFDStatusICC(rContext, &dwStatus);
	if (rv != SCARD_S_SUCCESS)
	{
		Log2(PCSC_LOG_ERROR, "Initial Check Failed on %s",
			rContext->readerState->readerName);
		return SCARD_F_UNKNOWN_ERROR;
	}

	rv = ThreadCreate(&rContext->pthThread, 0,
		(PCSCLITE_THREAD_FUNCTION( ))EHStatusHandlerThread, (LPVOID) rContext);
	if (rv)
	{
		Log2(PCSC_LOG_ERROR, "ThreadCreate failed: %s", strerror(rv));
		return SCARD_E_NO_MEMORY;
	}
	else
		return SCARD_S_SUCCESS;
}

static void EHStatusHandlerThread(READER_CONTEXT * rContext)
{
	LONG rv;
	const char *readerName;
	DWORD dwStatus;
	uint32_t readerState;
	int32_t readerSharing;
	DWORD dwCurrentState;
	DWORD dwAtrLen;

	/*
	 * Zero out everything
	 */
	dwStatus = 0;

	readerName = rContext->readerState->readerName;

	rv = IFDStatusICC(rContext, &dwStatus);

	if ((SCARD_S_SUCCESS == rv) && (dwStatus & SCARD_PRESENT))
	{
#ifdef DISABLE_AUTO_POWER_ON
		rContext->readerState->cardAtrLength = 0;
		rContext->readerState->cardProtocol = SCARD_PROTOCOL_UNDEFINED;
		readerState = SCARD_PRESENT;
		Log1(PCSC_LOG_INFO, "Skip card power on");
#else
		dwAtrLen = sizeof(rContext->readerState->cardAtr);
		rv = IFDPowerICC(rContext, IFD_POWER_UP,
			rContext->readerState->cardAtr, &dwAtrLen);
		rContext->readerState->cardAtrLength = dwAtrLen;

		/* the protocol is unset after a power on */
		rContext->readerState->cardProtocol = SCARD_PROTOCOL_UNDEFINED;

		if (rv == IFD_SUCCESS)
		{
			readerState = SCARD_PRESENT | SCARD_POWERED | SCARD_NEGOTIABLE;
			rContext->powerState = POWER_STATE_POWERED;
			Log1(PCSC_LOG_DEBUG, "powerState: POWER_STATE_POWERED");

			if (rContext->readerState->cardAtrLength > 0)
			{
				LogXxd(PCSC_LOG_INFO, "Card ATR: ",
					rContext->readerState->cardAtr,
					rContext->readerState->cardAtrLength);
			}
			else
				Log1(PCSC_LOG_INFO, "Card ATR: (NULL)");
		}
		else
		{
			readerState = SCARD_PRESENT | SCARD_SWALLOWED;
			rContext->powerState = POWER_STATE_UNPOWERED;
			Log1(PCSC_LOG_DEBUG, "powerState: POWER_STATE_UNPOWERED");
			Log3(PCSC_LOG_ERROR, "Error powering up card: %ld 0x%04lX", rv, rv);
		}
#endif

		dwCurrentState = SCARD_PRESENT;
	}
	else
	{
		readerState = SCARD_ABSENT;
		rContext->readerState->cardAtrLength = 0;
		rContext->readerState->cardProtocol = SCARD_PROTOCOL_UNDEFINED;

		dwCurrentState = SCARD_ABSENT;
	}

	/*
	 * Set all the public attributes to this reader
	 */
	rContext->readerState->readerState = readerState;
	rContext->readerState->readerSharing = readerSharing = rContext->contexts;

	(void)EHSignalEventToClients();

	while (1)
	{
		dwStatus = 0;

		rv = IFDStatusICC(rContext, &dwStatus);

		if (rv != SCARD_S_SUCCESS)
		{
			Log2(PCSC_LOG_ERROR, "Error communicating to: %s", readerName);

			/*
			 * Set error status on this reader while errors occur
			 */
			rContext->readerState->readerState = SCARD_UNKNOWN;
			rContext->readerState->cardAtrLength = 0;
			rContext->readerState->cardProtocol = SCARD_PROTOCOL_UNDEFINED;

			dwCurrentState = SCARD_UNKNOWN;

			(void)EHSignalEventToClients();
		}

		if (dwStatus & SCARD_ABSENT)
		{
			if (dwCurrentState == SCARD_PRESENT ||
				dwCurrentState == SCARD_UNKNOWN)
			{
				/*
				 * Change the status structure
				 */
				Log2(PCSC_LOG_INFO, "Card Removed From %s", readerName);
				/*
				 * Notify the card has been removed
				 */
				(void)RFSetReaderEventState(rContext, SCARD_REMOVED);

				rContext->readerState->cardAtrLength = 0;
				rContext->readerState->cardProtocol = SCARD_PROTOCOL_UNDEFINED;
				rContext->readerState->readerState = SCARD_ABSENT;
				dwCurrentState = SCARD_ABSENT;

				rContext->readerState->eventCounter++;

				(void)EHSignalEventToClients();
			}

		}
		else if (dwStatus & SCARD_PRESENT)
		{
			if (dwCurrentState == SCARD_ABSENT ||
				dwCurrentState == SCARD_UNKNOWN)
			{
#ifdef DISABLE_AUTO_POWER_ON
				rContext->readerState->cardAtrLength = 0;
				rContext->readerState->cardProtocol = SCARD_PROTOCOL_UNDEFINED;
				rContext->readerState->readerState = SCARD_PRESENT;
				rContext->powerState = POWER_STATE_UNPOWERED;
				Log1(PCSC_LOG_DEBUG, "powerState: POWER_STATE_UNPOWERED");
				readerState = SCARD_PRESENT;
				rv = IFD_SUCCESS;
				Log1(PCSC_LOG_INFO, "Skip card power on");
#else
				/*
				 * Power and reset the card
				 */
				dwAtrLen = sizeof(rContext->readerState->cardAtr);
				rv = IFDPowerICC(rContext, IFD_POWER_UP,
					rContext->readerState->cardAtr, &dwAtrLen);
				rContext->readerState->cardAtrLength = dwAtrLen;

				/* the protocol is unset after a power on */
				rContext->readerState->cardProtocol = SCARD_PROTOCOL_UNDEFINED;

				if (rv == IFD_SUCCESS)
				{
					rContext->readerState->readerState = SCARD_PRESENT | SCARD_POWERED | SCARD_NEGOTIABLE;
					rContext->powerState = POWER_STATE_POWERED;
					Log1(PCSC_LOG_DEBUG, "powerState: POWER_STATE_POWERED");
				}
				else
				{
					rContext->readerState->readerState = SCARD_PRESENT | SCARD_SWALLOWED;
					rContext->powerState = POWER_STATE_UNPOWERED;
					Log1(PCSC_LOG_DEBUG, "powerState: POWER_STATE_UNPOWERED");
					rContext->readerState->cardAtrLength = 0;
				}
#endif

				dwCurrentState = SCARD_PRESENT;

				rContext->readerState->eventCounter++;

				Log2(PCSC_LOG_INFO, "Card inserted into %s", readerName);

				(void)EHSignalEventToClients();

				if (rv == IFD_SUCCESS)
				{
					if (rContext->readerState->cardAtrLength > 0)
					{
						LogXxd(PCSC_LOG_INFO, "Card ATR: ",
							rContext->readerState->cardAtr,
							rContext->readerState->cardAtrLength);
					}
					else
						Log1(PCSC_LOG_INFO, "Card ATR: (NULL)");
				}
				else
					Log1(PCSC_LOG_ERROR,"Error powering up card.");
			}
		}

		/*
		 * Sharing may change w/o an event pass it on
		 */
		if (readerSharing != rContext->contexts)
		{
			readerSharing = rContext->contexts;
			rContext->readerState->readerSharing = readerSharing;
			(void)EHSignalEventToClients();
		}

		if (rContext->pthCardEvent)
		{
			int ret;
			int timeout;

#ifndef DISABLE_ON_DEMAND_POWER_ON
			if (POWER_STATE_POWERED == rContext->powerState)
				/* The card is powered but not yet used */
				timeout = PCSCLITE_POWER_OFF_GRACE_PERIOD;
			else
				/* The card is already in use or not used at all */
#endif
				timeout = PCSCLITE_STATUS_EVENT_TIMEOUT;

			ret = rContext->pthCardEvent(rContext->slot, timeout);
			if (IFD_SUCCESS != ret)
				(void)SYS_USleep(PCSCLITE_STATUS_POLL_RATE);
		}
		else
			(void)SYS_USleep(PCSCLITE_STATUS_POLL_RATE);

#ifndef DISABLE_ON_DEMAND_POWER_ON
		/* the card is powered but not used */
		(void)pthread_mutex_lock(&rContext->powerState_lock);
		if (POWER_STATE_POWERED == rContext->powerState)
		{
			/* power down */
			IFDPowerICC(rContext, IFD_POWER_DOWN, NULL, NULL);
			rContext->powerState = POWER_STATE_UNPOWERED;
			Log1(PCSC_LOG_DEBUG, "powerState: POWER_STATE_UNPOWERED");

			/* the protocol is unset after a power down */
			rContext->readerState->cardProtocol = SCARD_PROTOCOL_UNDEFINED;
		}

		/* the card was in use */
		if (POWER_STATE_GRACE_PERIOD == rContext->powerState)
		{
			/* the next state should be UNPOWERED unless the
			 * card is used again */
			rContext->powerState = POWER_STATE_POWERED;
			Log1(PCSC_LOG_DEBUG, "powerState: POWER_STATE_POWERED");
		}
		(void)pthread_mutex_unlock(&rContext->powerState_lock);
#endif

		if (rContext->hLockId == 0xFFFF)
		{
			/*
			 * Exit and notify the caller
			 */
			(void)EHSignalEventToClients();
			Log1(PCSC_LOG_INFO, "Die");
			rContext->hLockId = 0;
			(void)pthread_exit(NULL);
		}
	}
}

