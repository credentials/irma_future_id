/****************************************************************************
 * Copyright (C) 2012 ecsec GmbH.
 * All rights reserved.
 * Contact: ecsec GmbH (info@ecsec.de)
 *
 * This file is part of the Open eCard App.
 *
 * GNU General Public License Usage
 * This file may be used under the terms of the GNU General Public
 * License version 3.0 as published by the Free Software Foundation
 * and appearing in the file LICENSE.GPL included in the packaging of
 * this file. Please review the following information to ensure the
 * GNU General Public License version 3.0 requirements will be met:
 * http://www.gnu.org/copyleft/gpl.html.
 *
 * Other Usage
 * Alternatively, this file may be used in accordance with the terms
 * and conditions contained in a signed written agreement between
 * you and ecsec GmbH.
 *
 ***************************************************************************/

package org.openecard.event;

import iso.std.iso_iec._24727.tech.schema.EstablishContext;
import iso.std.iso_iec._24727.tech.schema.EstablishContextResponse;
import org.openecard.common.ClientEnv;
import org.openecard.common.interfaces.Environment;
import org.openecard.ifd.scio.IFD;
import org.testng.annotations.Test;


/**
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 */
public class ManagerTest {

    @Test(enabled=false)
    public void runManager() throws InterruptedException {
	IFD ifd = new IFD();
	EstablishContext ctx = new EstablishContext();
	EstablishContextResponse ctxR = ifd.establishContext(ctx);
	Environment env = new ClientEnv();
	env.setIFD(ifd);
	EventManager evt = new EventManager(null, env, ctxR.getContextHandle());
	evt.initialize();
	Thread.sleep(1000);
	//evt.terminate();
	Thread.sleep(1000000);
    }

}
