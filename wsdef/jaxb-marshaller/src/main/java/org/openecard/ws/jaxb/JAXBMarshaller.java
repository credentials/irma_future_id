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

package org.openecard.ws.jaxb;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import javax.xml.bind.JAXBException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.openecard.ws.marshal.MarshallingTypeException;
import org.openecard.ws.marshal.WSMarshaller;
import org.openecard.ws.marshal.WSMarshallerException;
import org.openecard.ws.marshal.WhitespaceFilter;
import org.openecard.ws.soap.MessageFactory;
import org.openecard.ws.soap.SOAPBody;
import org.openecard.ws.soap.SOAPException;
import org.openecard.ws.soap.SOAPMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;


/**
 * Implementation of a WSMarshaller utilizing JAXB and Javas default XML facilities.
 *
 * @author Tobias Wich <tobias.wich@ecsec.de>
 */
public final class JAXBMarshaller implements WSMarshaller {

    private static final Logger logger = LoggerFactory.getLogger(JAXBMarshaller.class);

    // Marshaller and Unmarshaller
    private final MarshallerImpl marshaller;
    // w3 factory
    private final DocumentBuilderFactory w3Factory;
    private final DocumentBuilder w3Builder;
    private final Transformer serializer;
    // soap
    private final MessageFactory soapFactory;

    /**
     * Creates a JAXBMarshaller capable of marshalling und unmarshalling all JAXB element types found in the classpath
     * resource classes.lst.
     */
    public JAXBMarshaller() {
	MarshallerImpl tmpMarshaller = null;
	DocumentBuilderFactory tmpW3Factory = null;
	DocumentBuilder tmpW3Builder = null;
	Transformer tmpSerializer = null;
	MessageFactory tmpSoapFactory = null;

	try {
	    tmpMarshaller = new MarshallerImpl();

	    // instantiate w3 stuff
	    tmpW3Factory = DocumentBuilderFactory.newInstance();
	    tmpW3Factory.setNamespaceAware(true);
	    tmpW3Factory.setIgnoringComments(true);
	    tmpW3Builder = tmpW3Factory.newDocumentBuilder();

	    TransformerFactory tfactory = TransformerFactory.newInstance();
	    tmpSerializer = tfactory.newTransformer();
	    tmpSerializer.setOutputProperty(OutputKeys.INDENT, "yes");
	    tmpSerializer.setOutputProperty(OutputKeys.STANDALONE, "yes");
	    tmpSerializer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
	    tmpSerializer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");

	    // instantiate soap stuff
	    tmpSoapFactory = MessageFactory.newInstance();
	} catch (Exception ex) {
	    logger.error("Failed to initialize XML components.", ex);
	    System.exit(1); // non recoverable
	}

	marshaller = tmpMarshaller;
	w3Factory = tmpW3Factory;
	w3Builder = tmpW3Builder;
	serializer = tmpSerializer;
	soapFactory = tmpSoapFactory;
    }



    ////////////////////////////////////////////////////////////////////////////
    // public functions to marshal and convert stuff
    ////////////////////////////////////////////////////////////////////////////

    @Override
    public void addXmlTypeClass(Class xmlTypeClass) throws MarshallingTypeException {
	marshaller.addXmlClass(xmlTypeClass);
    }

    @Override
    public void removeAllTypeClasses() {
	marshaller.removeAllClasses();
    }


    @Override
    public synchronized Document str2doc(String docStr) throws SAXException {
	try {
	    // read dom as w3
	    StringReader strReader = new StringReader(docStr);
	    InputSource inSrc = new InputSource(strReader);
	    Document doc = w3Builder.parse(inSrc);

	    WhitespaceFilter.filter(doc);

	    return doc;
	} catch (IOException ex) {
	    throw new SAXException(ex);
	}
    }

    @Override
    public synchronized Document str2doc(InputStream docStr) throws SAXException, IOException {
	// read dom as w3
	Document doc = w3Builder.parse(docStr);

	WhitespaceFilter.filter(doc);

	return doc;
    }

    @Override
    public synchronized String doc2str(Node doc) throws TransformerException {
	ByteArrayOutputStream out = new ByteArrayOutputStream();
	serializer.transform(new DOMSource(doc), new StreamResult(out));
	String result;
	try {
	    result = out.toString("UTF-8");
	} catch (UnsupportedEncodingException ex) {
	    throw new TransformerException(ex);
	}
	return result;
    }

    @Override
    public synchronized Object unmarshal(Node n) throws MarshallingTypeException, WSMarshallerException {
	Document newDoc = null;
	if (n instanceof Document) {
	    newDoc = (Document) n;
	} else if(n instanceof Element) {
	    newDoc = w3Builder.newDocument();
	    Node root = newDoc.importNode(n, true);
	    newDoc.appendChild(root);
	} else {
	    throw new WSMarshallerException("Only w3c Document and Element are accepted.");
	}

	Object result;
	try {
	    result = marshaller.getUnmarshaller().unmarshal(newDoc); //NOI18N
	} catch (JAXBException ex) {
	    throw new MarshallingTypeException(ex);
	}
	return result;
    }

    @Override
    public synchronized Document marshal(Object o) throws MarshallingTypeException {
	try {
	    StringWriter sw = new StringWriter();
	    XMLStreamWriter xmlStreamWriter = XMLOutputFactory.newInstance().createXMLStreamWriter(sw);
	    // wrap writer so specific ns prefixes are written out correctly
	    XMLStreamWriterWrapper xmlwrap = new XMLStreamWriterWrapper(xmlStreamWriter);
	    marshaller.getMarshaller().marshal(o, xmlwrap);
	    return str2doc(sw.toString());
	} catch (Exception ex) {
	    throw new MarshallingTypeException(ex);
	}
    }

    @Override
    public synchronized SOAPMessage doc2soap(Document envDoc) throws SOAPException {
	SOAPMessage msg = soapFactory.createMessage(envDoc);
	return msg;
    }

    @Override
    public synchronized SOAPMessage add2soap(Document content) throws SOAPException {
	SOAPMessage msg = soapFactory.createMessage();
	SOAPBody body = msg.getSOAPBody();
	body.addDocument(content);

	return msg;
    }

}
